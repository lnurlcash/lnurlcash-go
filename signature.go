package lnurlcash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// LUD-25 offline verification.
//
// A service certifies each note it issues with its Lightning node identity key
// (the same key it signs BOLT-11 invoices with), so a holder can confirm a
// note's issuer and amount without contacting anyone. Signed via the node's own
// signmessage RPC (lnd's /v1/signmessage, cln's signmessage), which wraps the
// message with this prefix and double-SHA256s it before signing. That is
// deliberate reuse: any tool that already verifies a Lightning node's signed
// messages can verify a note.
//
//	message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(Q)
//	digest  = sha256(sha256("Lightning Signed Message:" || message))
//
// Q is the note's output key, public for every note, a bearer note included:
// the certificate names the note without disclosing anything that spends it.
// A mint from before every note was keyed by Q certified a bearer note over
// its h instead, and that message is still read, reported as such.

const lightningSignedMessagePrefix = "Lightning Signed Message:"

// AddressProofMessage returns the message that proves control of a registered
// address's index-0 branch key, bound to action, mint and username:
// LNURLcash:<action>:<domain>:<username>. domain is the mint's own, in any
// form SpendDomainOf reads, and is written as its bare lowercase hostname.
// username must be the normalised value sent to the service.
func AddressProofMessage(action, domain, username string) (string, error) {
	if action != "register" && action != "unregister" {
		return "", &ProtocolError{Detail: "an address proof action is register or unregister"}
	}
	host, err := SpendDomainOf(domain)
	if err != nil {
		return "", err
	}
	return "LNURLcash:" + action + ":" + host + ":" + username, nil
}

// AddressProofDigest is AddressProofMessage hashed to the 32-byte digest that
// is actually signed: the message is variable-length, and most Schnorr signers
// only take 32 bytes.
func AddressProofDigest(action, domain, username string) ([]byte, error) {
	message, err := AddressProofMessage(action, domain, username)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(message))
	return digest[:], nil
}

// SignAddressProof signs a register/update or unregister proof with the
// branch's index-0 private key: a raw 64-byte BIP-340 signature over
// AddressProofDigest, with all-zero auxiliary input. Binding the domain stops
// a proof one mint has seen from being replayed at another. This is a fresh
// action a wallet initiates itself, never a stored bearer secret read back
// later, so there is no older scheme to fall back to reading.
func SignAddressProof(indexZeroSecretKey [32]byte, action, domain, username string) ([64]byte, error) {
	var out [64]byte
	var key btcec.ModNScalar
	if key.SetBytes(&indexZeroSecretKey) != 0 || key.IsZero() {
		return out, &ProtocolError{Detail: "an index-zero secret key is a 32-byte scalar in [1, n)"}
	}
	digest, err := AddressProofDigest(action, domain, username)
	if err != nil {
		return out, err
	}
	signature, err := schnorr.Sign(btcec.PrivKeyFromScalar(&key), digest, schnorr.CustomNonce([32]byte{}))
	if err != nil {
		return out, &ProtocolError{Detail: "could not sign the address proof message"}
	}
	copy(out[:], signature.Serialize())
	return out, nil
}

// NoteSignatureMessage returns the message a note's certificate commits to,
// over hex(Q) of the note k1 opens (see NoteIDOf).
func NoteSignatureMessage(k1 string, amountMsat int64) (string, error) {
	id, err := NoteIDOf(k1)
	if err != nil {
		return "", err
	}
	return NoteSignatureMessageForHash(id, amountMsat), nil
}

// NoteSignatureMessageForHash is the same message for a caller holding a
// note's id as 32 bytes of hex rather than a spend of it: hex(Q), which is all
// a watcher holding only a cx1 has. Given a bearer note's h instead, it builds
// the message a mint from before taproot certified.
func NoteSignatureMessageForHash(h string, amountMsat int64) string {
	return fmt.Sprintf("LNURLcash:%d:%s", amountMsat, strings.ToLower(strings.TrimSpace(h)))
}

// NoteSignatureDigest returns the digest a signer actually put its pen to.
func NoteSignatureDigest(k1 string, amountMsat int64) ([]byte, error) {
	id, err := NoteIDOf(k1)
	if err != nil {
		return nil, err
	}
	return NoteSignatureDigestForHash(id, amountMsat), nil
}

// NoteSignatureDigestForHash is NoteSignatureDigest for a note's hex id.
func NoteSignatureDigestForHash(h string, amountMsat int64) []byte {
	inner := sha256.Sum256([]byte(lightningSignedMessagePrefix + NoteSignatureMessageForHash(h, amountMsat)))
	outer := sha256.Sum256(inner[:])
	return outer[:]
}

// Certification is whether a certificate verified, and over which message.
type Certification int

const (
	// NotCertified: the certificate does not verify for this note and amount.
	NotCertified Certification = iota
	// CertifiedOverQ: signed over hex(Q), as LUD-25 specifies.
	CertifiedOverQ
	// CertifiedOverHash: a bearer note certified over its h, the message a
	// mint used before every note was keyed by Q. Genuine, but from a mint
	// that has not caught up.
	CertifiedOverHash
)

// Verified reports whether the certificate verified over either message.
func (c Certification) Verified() bool { return c != NotCertified }

func (c Certification) String() string {
	switch c {
	case CertifiedOverQ:
		return "certified over hex(Q)"
	case CertifiedOverHash:
		return "certified over the bearer note's h (pre-taproot)"
	default:
		return "not certified"
	}
}

// VerifyNoteSignature is LUD-25's offline check of a note, as a recipient
// makes it: that k1 opens its note Q at domain (see VerifySpend), and that
// signature certifies Q for amountMsat under mintPubkeyHex. A bearer note
// is tried over hex(Q) first, then over its h for a mint from before taproot.
//
// domain is the note URL's, in any form SpendDomainOf reads; a bearer note's
// spend opens it at any domain, but a ck1 only at the one it signed for. A
// cw1 whose leaf this package cannot run is NotCertified here: only the mint
// can say whether it opens its note, so check the certificate alone with
// VerifyNoteSignatureForKey and leave the spend to the mint.
//
// signature is 65 bytes of hex, an amount-bearing cs1, or a legacy
// fixed-prefix cs1. The signature is 65 bytes, but which end carries the
// recovery id varies by implementation: LUD-25 calls for r || s ||
// recovery_id, the layout raw BOLT-11 signatures use, while lnurl-mint once
// forwarded its node's signmessage output unreordered as recovery_id || r ||
// s. Trying both costs nothing security-wise - recovering against the wrong
// one yields an unrelated key that cannot match - and means a note verifies
// regardless of which convention issued it.
//
// Never panics. Anything unverifiable is NotCertified.
func VerifyNoteSignature(k1, domain string, amountMsat int64, signature, mintPubkeyHex string) Certification {
	verified, err := VerifySpend(k1, domain)
	if err != nil || verified.Unevaluated {
		return NotCertified
	}
	q := hex.EncodeToString(verified.OutputKey[:])
	if verifyCertificate(q, amountMsat, signature, mintPubkeyHex) {
		return CertifiedOverQ
	}
	spend, err := DecodeSpend(k1)
	if err != nil || spend.Kind != ScriptPathSpend {
		return NotCertified
	}
	if h, isBearer := bearerHashOfLeaf(spend.ScriptPath.Script); isBearer &&
		verifyCertificate(hex.EncodeToString(h[:]), amountMsat, signature, mintPubkeyHex) {
		return CertifiedOverHash
	}
	return NotCertified
}

// VerifyNoteSignatureHash checks the certificate on a bearer note named by
// its hex h rather than a spend of it: a device that keeps the preimage to
// itself and discloses only h, say. Over hex(Q) first, then over h itself for
// a mint from before taproot.
func VerifyNoteSignatureHash(h string, amountMsat int64, signature, mintPubkeyHex string) Certification {
	q, err := BearerNoteID(h)
	if err != nil {
		return NotCertified
	}
	if verifyCertificate(q, amountMsat, signature, mintPubkeyHex) {
		return CertifiedOverQ
	}
	if verifyCertificate(h, amountMsat, signature, mintPubkeyHex) {
		return CertifiedOverHash
	}
	return NotCertified
}

// VerifyNoteSignatureForKey checks a certificate over a note's output key,
// given as hex(Q): a watcher checking a note minted to a key it derived from
// a cx1, or any note whose spend is not to hand.
func VerifyNoteSignatureForKey(outputKeyHex string, amountMsat int64, signature, mintPubkeyHex string) Certification {
	if verifyCertificate(outputKeyHex, amountMsat, signature, mintPubkeyHex) {
		return CertifiedOverQ
	}
	return NotCertified
}

// VerifyNoteURL makes LUD-25's offline check on a note URL as a recipient
// holds it, lnurlw://mint.example/w?k1=<spend>&sig=<cs1>: the spend from k1,
// the domain from the URL's own host, and the amount from the cs1, or from the
// URL's amount when the certificate is an older one that carries none. It
// returns that amount with the verdict. A certificate proves issuance, never
// that the note is still outstanding: rotate a received note once online.
func VerifyNoteURL(noteURL, mintPubkeyHex string) (int64, Certification) {
	k1, signature := NoteK1(noteURL), NoteSignature(noteURL)
	domain, err := SpendDomainOf(noteURL)
	if k1 == "" || signature == "" || err != nil {
		return 0, NotCertified
	}
	amount, ok := int64(0), false
	if certificate, err := DecodeCs1WithAmount(signature); err == nil {
		amount, ok = certificate.AmountMsat, true
	} else {
		amount, ok = NoteDeclaredAmountMsat(noteURL)
	}
	if !ok {
		return 0, NotCertified
	}
	return amount, VerifyNoteSignature(k1, domain, amount, signature, mintPubkeyHex)
}

// verifyCertificate recovers the signer of a certificate over the note id and
// checks it against mintPubkeyHex.
func verifyCertificate(id string, amountMsat int64, signature, mintPubkeyHex string) bool {
	raw, ok := signatureBytes(signature)
	// an id is 32 bytes of hex whichever message it names
	if !ok || !IsPreimage(id) {
		return false
	}
	digest := NoteSignatureDigestForHash(id, amountMsat)
	target := strings.ToLower(strings.TrimSpace(mintPubkeyHex))

	// btcec wants the recovery id FIRST, offset by 27 (the compact-signature
	// convention). Neither wire layout is that, so both need rebuilding.
	trailing := make([]byte, 65)
	trailing[0] = raw[64] + 27
	copy(trailing[1:], raw[:64])

	leading := make([]byte, 65)
	leading[0] = raw[0] + 27
	copy(leading[1:], raw[1:])

	for _, candidate := range [][]byte{trailing, leading} {
		if candidate[0] < 27 || candidate[0] > 34 {
			continue
		}
		pubkey, _, err := ecdsa.RecoverCompact(candidate, digest)
		if err != nil {
			// not a valid recovery under this ordering - try the other
			continue
		}
		if hex.EncodeToString(pubkey.SerializeCompressed()) == target {
			return true
		}
	}
	return false
}

// signatureBytes reads a note signature in any supported spelling.
func signatureBytes(value string) ([]byte, bool) {
	if certificate, err := DecodeAnyCs1(value); err == nil {
		return certificate[:], true
	}
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != 65 {
		return nil, false
	}
	return raw, true
}
