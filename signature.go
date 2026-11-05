package lnurlcash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// LUD-25 offline verification, and the address-registration proof.
//
// A service certifies each note it issues with its Lightning node identity key
// (the same key it signs BOLT-11 invoices with), so a holder can confirm a
// note's issuer and amount without contacting anyone. Signed via the node's own
// signmessage RPC (lnd's /v1/signmessage, cln's signmessage), which wraps the
// message with this prefix and double-SHA256s it before signing. That is
// deliberate reuse: any tool that already verifies a Lightning node's signed
// messages can verify a note.
//
//	message = "LNURLcash:" || domain || ":" || amount_msat (decimal ASCII) || ":" || hex(Q)
//	digest  = sha256(sha256("Lightning Signed Message:" || message))
//
// domain is the mint's lowercase hostname, the string the canonical spend
// transaction commits to, so a certificate names the one mint on that domain
// and never vouches for a note at another. Q is the note's output key, public
// for every note, a bearer note included: the certificate names the note
// without disclosing anything that spends it.
//
// Two older messages are still read, never written, since notes people hold
// carry them: hex(Q) without the domain (before luds 92abbb3), reported as
// CertifiedOverLegacyQ, and a bearer note's hash h from before notes were keyed
// by Q, reported as CertifiedOverHash.

const lightningSignedMessagePrefix = "Lightning Signed Message:"

const domainTag = "LNURLcash"

// AddressProofMessage returns the message a share's own key signs to register,
// update or unregister a Lightning Address (LUD-26):
//
//	register    LNURLcash:register:<domain>:<username>:<cx1>
//	update      LNURLcash:update:<domain>:<username>:<new cx1>
//	unregister  LNURLcash:unregister:<domain>:<username>
//
// domain is the SERVICE's own, in any form SpendDomainOf reads, and is written
// as its bare lowercase hostname. username is lowercased, as LUD-26 has it
// signed and stored. cx1 is the share being registered, or for update the new
// one, and must be empty for unregister; it is signed in its canonical
// lowercase spelling.
func AddressProofMessage(action, domain, username, cx1 string) (string, error) {
	host, err := SpendDomainOf(domain)
	if err != nil {
		return "", &ProtocolError{Detail: "an address proof names the SERVICE's domain"}
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", &ProtocolError{Detail: "an address proof names a username"}
	}
	canonical := ""
	if cx1 != "" {
		decoded, err := DecodeCx1(cx1)
		if err != nil {
			return "", &ProtocolError{Detail: "that is not a cx1"}
		}
		canonical = EncodeCx1(decoded)
	}
	switch {
	case (action == "register" || action == "update") && canonical != "":
		return domainTag + ":" + action + ":" + host + ":" + username + ":" + canonical, nil
	case action == "unregister" && cx1 == "":
		return domainTag + ":unregister:" + host + ":" + username, nil
	case action == "register" || action == "update":
		return "", &ProtocolError{Detail: "a " + action + " proof binds the cx1 it puts on file"}
	case action == "unregister":
		return "", &ProtocolError{Detail: "an unregister proof binds no cx1"}
	default:
		return "", &ProtocolError{Detail: "an address proof action is register, update or unregister"}
	}
}

// AddressProofDigest is AddressProofMessage hashed to the 32-byte digest that
// is actually signed: the message is variable-length, and most Schnorr signers
// only take 32 bytes.
func AddressProofDigest(action, domain, username, cx1 string) ([]byte, error) {
	message, err := AddressProofMessage(action, domain, username, cx1)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(message))
	return digest[:], nil
}

// SignAddressProof signs an address proof as a raw 64-byte BIP-340 signature
// over AddressProofDigest, with all-zero auxiliary input so a retried request
// resends the same proof. The key is the signing share's own private key
// (DeriveShareNode): the share being registered, or for update and unregister
// the one on file.
func SignAddressProof(shareSecretKey [32]byte, action, domain, username, cx1 string) ([64]byte, error) {
	var out [64]byte
	var key btcec.ModNScalar
	if key.SetBytes(&shareSecretKey) != 0 || key.IsZero() {
		return out, &ProtocolError{Detail: "a share secret key is a 32-byte scalar in [1, n)"}
	}
	digest, err := AddressProofDigest(action, domain, username, cx1)
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

// VerifyAddressProof is what a SERVICE checks: does signature (64 bytes) verify
// against x(P) of signer, the cx1 being registered or the one on file, over
// this action's message? False for anything malformed.
func VerifyAddressProof(signer string, signature []byte, action, domain, username, cx1 string) bool {
	share, err := DecodeCx1(signer)
	if err != nil {
		return false
	}
	digest, err := AddressProofDigest(action, domain, username, cx1)
	if err != nil {
		return false
	}
	parsed, err := schnorr.ParseSignature(signature)
	if err != nil {
		return false
	}
	x := share.PubkeyXOnly()
	key, err := schnorr.ParsePubKey(x[:])
	if err != nil {
		return false
	}
	return parsed.Verify(digest, key)
}

// NoteSignatureMessage returns the message a SERVICE certifies for the note k1
// opens at domain (a note URL, a mint URL or a bare host), over hex(Q) of the
// note (see NoteIDOf). An error for a k1 that is no spend or a domain that
// names none.
func NoteSignatureMessage(k1, domain string, amountMsat int64) (string, error) {
	id, err := NoteIDOf(k1)
	if err != nil {
		return "", err
	}
	return NoteSignatureMessageForHash(id, domain, amountMsat)
}

// NoteSignatureMessageForHash is the same message for a caller holding a note's
// id as 32 bytes of hex rather than a spend of it: hex(Q), used as given,
// lowercased, which is all a watcher holding only a cx1 has.
func NoteSignatureMessageForHash(id, domain string, amountMsat int64) (string, error) {
	host, err := SpendDomainOf(domain)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s:%d:%s", domainTag, host, amountMsat, strings.ToLower(strings.TrimSpace(id))), nil
}

// NoteSignatureDigest returns the digest a signer actually put its pen to.
func NoteSignatureDigest(k1, domain string, amountMsat int64) ([]byte, error) {
	id, err := NoteIDOf(k1)
	if err != nil {
		return nil, err
	}
	return NoteSignatureDigestForHash(id, domain, amountMsat)
}

// NoteSignatureDigestForHash is NoteSignatureDigest for a note's hex id.
func NoteSignatureDigestForHash(id, domain string, amountMsat int64) ([]byte, error) {
	message, err := NoteSignatureMessageForHash(id, domain, amountMsat)
	if err != nil {
		return nil, err
	}
	return lightningSignedDigest(message), nil
}

func lightningSignedDigest(message string) []byte {
	inner := sha256.Sum256([]byte(lightningSignedMessagePrefix + message))
	outer := sha256.Sum256(inner[:])
	return outer[:]
}

// LegacyNoteSignatureMessageForHash is the superseded message without a domain,
// LNURLcash:<amount>:<id>, over hex(Q) or a bearer note's h. Read, never
// written: a SERVICE MUST NOT issue it any more.
func LegacyNoteSignatureMessageForHash(id string, amountMsat int64) string {
	return fmt.Sprintf("%s:%d:%s", domainTag, amountMsat, strings.ToLower(strings.TrimSpace(id)))
}

// LegacyNoteSignatureDigestForHash is the digest signed over
// LegacyNoteSignatureMessageForHash.
func LegacyNoteSignatureDigestForHash(id string, amountMsat int64) []byte {
	return lightningSignedDigest(LegacyNoteSignatureMessageForHash(id, amountMsat))
}

// Certification is whether a certificate verified, and over which message.
type Certification int

const (
	// NotCertified: the certificate does not verify for this note and amount.
	NotCertified Certification = iota
	// CertifiedOverQ: signed over hex(Q) at the note's domain, as LUD-25
	// specifies.
	CertifiedOverQ
	// CertifiedOverHash: a bearer note certified over its h, the message a
	// mint used before every note was keyed by Q. Genuine, but from a mint
	// that has not caught up.
	CertifiedOverHash
	// CertifiedOverLegacyQ: signed over hex(Q) with no domain, as a SERVICE
	// signed before luds 92abbb3. It still proves issuance of that note for
	// that amount by that key, but not at which of the key's mints.
	CertifiedOverLegacyQ
)

// Verified reports whether the certificate verified over any message.
func (c Certification) Verified() bool { return c != NotCertified }

func (c Certification) String() string {
	switch c {
	case CertifiedOverQ:
		return "certified over hex(Q)"
	case CertifiedOverHash:
		return "certified over the bearer note's h (pre-taproot)"
	case CertifiedOverLegacyQ:
		return "certified over hex(Q) without a domain (pre-LUD-26)"
	default:
		return "not certified"
	}
}

// VerifyNoteSignature is LUD-25's offline check of a note, as a recipient
// makes it: that k1 opens its note Q at domain (see VerifySpend), and that
// signature certifies Q for amountMsat at that domain under mintPubkeyHex. The
// current message is tried first, then the legacy ones: hex(Q) without a
// domain and, for a bearer note, its h for a mint from before taproot.
//
// domain is the note URL's, in any form SpendDomainOf reads; a bearer note's
// spend opens it at any domain, but a ck1 only at the one it signed for. A cw1
// whose leaf this package cannot run is NotCertified here: only the mint can
// say whether it opens its note, so check the certificate alone with
// VerifyNoteSignatureForKey and leave the spend to the mint.
//
// signature is an amount-bearing cs1, which must state amountMsat in its
// human-readable part as well as sign it, with its recovery id last. For the
// legacy messages it may also be 65 bytes of hex or a fixed-prefix cs1, in
// either recovery-id layout: LUD-25 called for r || s || recovery_id, the layout
// raw BOLT-11 signatures use, while lnurl-mint once forwarded its node's
// signmessage output unreordered as recovery_id || r || s. Trying both costs
// nothing security-wise - recovering against the wrong one yields an unrelated
// key that cannot match.
//
// Never panics. Anything unverifiable is NotCertified.
func VerifyNoteSignature(k1, domain string, amountMsat int64, signature, mintPubkeyHex string) Certification {
	verified, err := VerifySpend(k1, domain)
	if err != nil || verified.Unevaluated {
		return NotCertified
	}
	q := hex.EncodeToString(verified.OutputKey[:])
	var bearerHash string
	if spend, err := DecodeSpend(k1); err == nil && spend.Kind == ScriptPathSpend {
		if h, isBearer := bearerHashOfLeaf(spend.ScriptPath.Script); isBearer {
			bearerHash = hex.EncodeToString(h[:])
		}
	}
	return certifiedOver(q, bearerHash, domain, amountMsat, signature, mintPubkeyHex)
}

// VerifyNoteSignatureHash checks the certificate on a bearer note named by its
// hex h rather than a spend of it: a device that keeps the preimage to itself
// and discloses only h, say. Over hex(Q) at domain first, then the legacy
// messages: hex(Q) without one, and h itself for a mint from before taproot.
func VerifyNoteSignatureHash(h, domain string, amountMsat int64, signature, mintPubkeyHex string) Certification {
	q, err := BearerNoteID(h)
	if err != nil {
		return NotCertified
	}
	return certifiedOver(q, strings.ToLower(strings.TrimSpace(h)), domain, amountMsat, signature, mintPubkeyHex)
}

// VerifyNoteSignatureForKey checks a certificate over a note's output key,
// given as hex(Q), at domain: a watcher checking a note minted to a key it
// derived from a cx1, or any note whose spend is not to hand. Tries the current
// message, then hex(Q) without a domain.
func VerifyNoteSignatureForKey(outputKeyHex, domain string, amountMsat int64, signature, mintPubkeyHex string) Certification {
	return certifiedOver(outputKeyHex, "", domain, amountMsat, signature, mintPubkeyHex)
}

// VerifyNoteURL makes LUD-25's offline check on a note URL as a recipient holds
// it, lnurlw://mint.example/w?k1=<spend>&c=<cs1>: the spend from k1, the domain
// from the URL's own host, and the amount from the cs1, or from the URL's
// amount when the certificate is an older one that carries none. It returns
// that amount with the verdict. A certificate proves issuance, never that the
// note is still outstanding: rotate a received note once online.
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

// certifiedOver tries the current message over hex(Q) at domain, then the legacy
// one without a domain, then, for a bearer note, the pre-taproot message over h.
func certifiedOver(q, bearerHash, domain string, amountMsat int64, signature, mintPubkeyHex string) Certification {
	if VerifyNoteCertificate(q, domain, amountMsat, signature, mintPubkeyHex) {
		return CertifiedOverQ
	}
	if VerifyLegacyNoteSignatureHash(q, amountMsat, signature, mintPubkeyHex) {
		return CertifiedOverLegacyQ
	}
	if bearerHash != "" && VerifyLegacyNoteSignatureHash(bearerHash, amountMsat, signature, mintPubkeyHex) {
		return CertifiedOverHash
	}
	return NotCertified
}

// VerifyNoteCertificate checks a current certificate over exactly the 64-hex id
// given, hex(Q), at domain (a note URL, a mint URL or a bare host). The
// primitive the other checks here are built on; prefer VerifyNoteSignature or
// VerifyNoteSignatureForKey, which fall back to the legacy messages.
//
// signature is an amount-bearing cs1, which must state amountMsat in its
// human-readable part as well as sign it, with its recovery id last.
func VerifyNoteCertificate(id, domain string, amountMsat int64, signature, mintPubkeyHex string) bool {
	id = strings.TrimSpace(id)
	if !IsPreimage(id) {
		return false
	}
	digest, err := NoteSignatureDigestForHash(id, domain, amountMsat)
	if err != nil {
		return false
	}
	raw, ok := certificateBytes(signature, amountMsat, false)
	return ok && recoversTo(digest, raw, false, mintPubkeyHex)
}

// VerifyLegacyNoteSignatureHash is VerifyNoteCertificate for the superseded
// message without a domain, over hex(Q) or a bearer note's h. signature may
// also be raw hex or a fixed-prefix cs1, in either recovery-id layout, as
// certificates were issued then.
func VerifyLegacyNoteSignatureHash(id string, amountMsat int64, signature, mintPubkeyHex string) bool {
	id = strings.TrimSpace(id)
	if !IsPreimage(id) {
		return false
	}
	raw, ok := certificateBytes(signature, amountMsat, true)
	return ok && recoversTo(LegacyNoteSignatureDigestForHash(id, amountMsat), raw, true, mintPubkeyHex)
}

// certificateBytes reads the signature out of a cs1 that states amountMsat, or
// for a legacy message also out of a fixed-prefix cs1 or raw hex. lenient
// admits a recovery id outside 0 to 3, which only a certificate in the leading
// layout has.
func certificateBytes(value string, amountMsat int64, lenient bool) ([]byte, bool) {
	trimmed := strings.TrimSpace(value)
	if certificate, err := DecodeCs1WithAmount(trimmed); err == nil {
		// An amount-bearing cs1 must state the amount it signs: a payload moved
		// under another amount's prefix would otherwise verify while
		// displaying an amount nobody certified.
		if certificate.AmountMsat != amountMsat {
			return nil, false
		}
		return certificate.Signature[:], true
	}
	if !lenient {
		return nil, false
	}
	if raw, ok := anyCs1Bytes(trimmed); ok {
		return raw, true
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil || len(raw) != 65 {
		return nil, false
	}
	return raw, true
}

// anyCs1Bytes reads a cs1 of any amount or none, recovery id unchecked, for the
// legacy layouts.
func anyCs1Bytes(value string) ([]byte, bool) {
	prefix, words, version, err := bech32.DecodeNoLimitWithVersion(value)
	if err != nil || version != bech32.VersionM || !strings.HasPrefix(prefix, "cs") {
		return nil, false
	}
	payload, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil || len(payload) != 65 {
		return nil, false
	}
	return payload, true
}

// recoversTo recovers the signer of raw (65 bytes) over digest and checks it
// against mintPubkeyHex.
//
// Which end of the raw bytes carries the recovery id varies by implementation,
// and btcec wants it FIRST, offset by 27 (the compact-signature convention), so
// each layout is rebuilt. A current certificate is only ever the trailing one;
// the legacy messages try both.
func recoversTo(digest, raw []byte, bothLayouts bool, mintPubkeyHex string) bool {
	target := strings.ToLower(strings.TrimSpace(mintPubkeyHex))

	trailing := make([]byte, 65)
	trailing[0] = raw[64] + 27
	copy(trailing[1:], raw[:64])
	candidates := [][]byte{trailing}

	if bothLayouts {
		leading := make([]byte, 65)
		leading[0] = raw[0] + 27
		copy(leading[1:], raw[1:])
		candidates = append(candidates, leading)
	}

	for _, candidate := range candidates {
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
