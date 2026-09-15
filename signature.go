package lnurlcash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// LUD-25 offline verification.
//
// A service may sign each note it issues with its Lightning node identity key
// (the same key it signs BOLT-11 invoices with), so a holder can confirm a
// note's issuer and amount without contacting anyone. Signed via the node's own
// signmessage RPC (lnd's /v1/signmessage, cln's signmessage), which wraps the
// message with this prefix and double-SHA256s it before signing. That is
// deliberate reuse: any tool that already verifies a Lightning node's signed
// messages can verify a note.
//
//	message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(sha256(k1))
//	digest  = sha256(sha256("Lightning Signed Message:" || message))
//
// The signature commits to the note's HASH, not its secret, so a holder can
// prove issuance - to expose a mint that will not honour its own note - without
// revealing what would let anyone spend it.
//
// A Part 2 note has no hash. Its certificate, the cs1, is the same signature
// over hex(pk) in the hash's place, and the pk comes from the ck1 by recovery,
// so checking a Part 2 note needs no network either. Everything below takes
// either kind of k1 and names the note by NoteIDOf.

const lightningSignedMessagePrefix = "Lightning Signed Message:"

// AddressProofDigest returns the action- and username-bound digest used to
// prove control of a registered address's index-0 branch key. The caller must
// use the same normalised username it sends to the service.
func AddressProofDigest(action, username string) ([]byte, error) {
	if action != "register" && action != "unregister" {
		return nil, &ProtocolError{Detail: "an address proof action is register or unregister"}
	}
	inner := sha256.Sum256([]byte(lightningSignedMessagePrefix + "LNURLcash:" + action + ":" + username))
	outer := sha256.Sum256(inner[:])
	return outer[:], nil
}

// SignAddressProof signs a register/update or unregister proof with the
// branch's index-0 private key. The returned bytes use the reference wire
// layout r || s || recovery-id.
func SignAddressProof(indexZeroSecretKey [32]byte, action, username string) ([65]byte, error) {
	var out [65]byte
	var key btcec.ModNScalar
	if key.SetBytes(&indexZeroSecretKey) != 0 || key.IsZero() {
		return out, &ProtocolError{Detail: "an index-zero secret key is a 32-byte scalar in [1, n)"}
	}
	digest, err := AddressProofDigest(action, username)
	if err != nil {
		return out, err
	}
	compact := ecdsa.SignCompact(btcec.PrivKeyFromScalar(&key), digest, true)
	copy(out[:64], compact[1:])
	out[64] = compact[0] - compactHeaderCompressed
	return out, nil
}

// NoteSignatureMessage returns the message a note's signature commits to. k1
// is a Part 1 secret or a Part 2 ck1.
func NoteSignatureMessage(k1 string, amountMsat int64) (string, error) {
	id, err := NoteIDOf(k1)
	if err != nil {
		return "", err
	}
	return NoteSignatureMessageForHash(id, amountMsat), nil
}

// NoteSignatureMessageForHash is the same message for a caller holding the
// note's id rather than its k1: sha256(k1), or a Part 2 note's x-only key, as
// hex. That is all a watcher holding only a cx1 has, and all a certificate
// needs.
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

// NoteSignatureDigestForHash is NoteSignatureDigest for a note's id.
func NoteSignatureDigestForHash(h string, amountMsat int64) []byte {
	inner := sha256.Sum256([]byte(lightningSignedMessagePrefix + NoteSignatureMessageForHash(h, amountMsat)))
	outer := sha256.Sum256(inner[:])
	return outer[:]
}

// VerifyNoteSignature recovers the signer's pubkey and checks it against
// mintPubkeyHex.
//
// k1 is a Part 1 secret or a Part 2 ck1. signature is 65 bytes of hex, a
// current amount-bearing cs1, or a legacy fixed-prefix cs1. Callers can decode
// the carried amount separately when they need it.
//
// The signature is 65 bytes, but which end carries the recovery id varies by
// implementation: LUD-25 calls for r || s || recovery_id, the layout raw
// BOLT-11 signatures use, while lnurl-mint once forwarded its node's
// signmessage output unreordered as recovery_id || r || s. That is fixed
// upstream, but other implementations may still get it wrong.
//
// Trying both orderings costs nothing security-wise - recovering against the
// wrong one yields an unrelated pubkey that cannot match - and means a note
// verifies regardless of which convention issued it.
//
// Never panics. An unverifiable signature is a false.
func VerifyNoteSignature(k1 string, amountMsat int64, signature, mintPubkeyHex string) bool {
	id, err := NoteIDOf(k1)
	if err != nil {
		// a malformed k1 names no note - not a panic, a "no"
		return false
	}
	return VerifyNoteSignatureHash(id, amountMsat, signature, mintPubkeyHex)
}

// VerifyNoteSignatureHash is VerifyNoteSignature for a caller holding the
// note's id (see NoteSignatureMessageForHash) rather than its k1: a watcher
// checking the certificate on a note minted to a key it derived from a cx1,
// say.
func VerifyNoteSignatureHash(h string, amountMsat int64, signature, mintPubkeyHex string) bool {
	raw, ok := signatureBytes(signature)
	// an id is 32 bytes of hex whichever kind of note it names
	if !ok || !IsPreimage(h) {
		return false
	}
	digest := NoteSignatureDigestForHash(h, amountMsat)
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
