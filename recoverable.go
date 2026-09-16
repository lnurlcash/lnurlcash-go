package lnurlcash

// LUD-25 Part 2: notes keyed by a public key.
//
// A Part 2 note is keyed by a public key rather than a hash. The holder keeps
// sk, discloses pk as cp1<pk>, and spends the note with ck1: pk followed by a
// BIP-340 signature by sk over one fixed digest. The service verifies the pair
// and looks the note up by pk. The service certifies each note with cs1, the
// same signature it has always made, over hex(pk) instead of a hash, so a
// recipient can check issuance offline with nothing but the ck1 and the cs1.
//
// A watch-only cx1 - a branch's x-only key and its chain code - lets whoever
// holds it derive every note key on the branch, which is how a service mints
// straight to a holder's next key, but spend none of them.
//
// The names follow lnurlcash-kit's recoverable.ts, which follows lnurl-wallet.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ---- bech32m ----
//
// Each type has a fixed payload length, so there is no length limit to pick:
// ck1, cs1 and cx1 all run past BIP-173's 90 characters, which the spec
// deliberately does not adopt. That rules out bech32.Decode, which enforces
// it. DecodeNoLimitWithVersion does not, and says which checksum it found, so
// a bech32 checksum can be refused rather than read as bech32m.
//
// All-uppercase is the same string and is accepted. Mixed case is refused, as
// BIP-350 requires and lnurl-mint does.

func encodeFixed(hrp string, payload []byte) string {
	// Neither step can fail: eight-to-five with padding takes any bytes, and
	// every word it produces is below 32, which is all EncodeM checks.
	words, _ := bech32.ConvertBits(payload, 8, 5, true)
	encoded, _ := bech32.EncodeM(hrp, words)
	return encoded
}

func decodeFixed(hrp, value string, length int) ([]byte, error) {
	// Never the value itself in the error: a ck1 is a bearer secret, and error
	// text ends up in logs.
	invalid := func(why string) error {
		return &ProtocolError{Detail: fmt.Sprintf("not a %s1: %s", hrp, why)}
	}
	prefix, words, version, err := bech32.DecodeNoLimitWithVersion(strings.TrimSpace(value))
	switch {
	case err != nil:
		return nil, invalid("not a well-formed bech32m string")
	case version != bech32.VersionM:
		return nil, invalid("the checksum is bech32, not bech32m")
	case prefix != hrp:
		return nil, invalid(fmt.Sprintf("the prefix is not %s1", hrp))
	}
	// Refuses non-zero padding, and five or more bits of it, which is what
	// leaves each payload with exactly one encoding.
	payload, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil {
		return nil, invalid("the padding is not zero")
	}
	if len(payload) != length {
		return nil, invalid(fmt.Sprintf("the payload is %d bytes, not %d", len(payload), length))
	}
	return payload, nil
}

// EncodeCp1 encodes a note's public key: 32 bytes, x-only, as BIP-340.
func EncodeCp1(pubkeyXOnly [32]byte) string { return encodeFixed("cp", pubkeyXOnly[:]) }

// DecodeCp1 reads a cp1 back to its x-only key.
func DecodeCp1(value string) ([32]byte, error) {
	var out [32]byte
	payload, err := decodeFixed("cp", value, len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], payload)
	return out, nil
}

// IsCp1 reports whether value is a well-formed cp1.
func IsCp1(value string) bool {
	_, err := DecodeCp1(value)
	return err == nil
}

// EncodeCk1 encodes a note's bearer secret: its 32-byte x-only public key
// followed by its 64-byte BIP-340 signature, from SignNoteOwnership. Whoever
// has it can spend the note.
func EncodeCk1(payload [96]byte) string { return encodeFixed("ck", payload[:]) }

// DecodedCk1 is what a ck1 carries. A current ck1 fills Current. A legacy one,
// the pre-Schnorr 65-byte recoverable-ECDSA bearer, fills Legacy and sets
// IsLegacy instead: it is still read only so existing notes stay spendable
// long enough to rotate into the current format.
type DecodedCk1 struct {
	Current  [96]byte
	Legacy   [65]byte
	IsLegacy bool
}

// Bytes returns whichever payload the ck1 carried.
func (d DecodedCk1) Bytes() []byte {
	if d.IsLegacy {
		return d.Legacy[:]
	}
	return d.Current[:]
}

// DecodeCk1 reads a ck1 back to its payload, the current 96-byte form or the
// legacy 65-byte one.
func DecodeCk1(value string) (DecodedCk1, error) {
	var out DecodedCk1
	payload, err := decodeFixed("ck", value, len(out.Current))
	if err == nil {
		copy(out.Current[:], payload)
		return out, nil
	}
	legacy, legacyErr := decodeFixed("ck", value, len(out.Legacy))
	if legacyErr != nil {
		return DecodedCk1{}, err
	}
	copy(out.Legacy[:], legacy)
	out.IsLegacy = true
	return out, nil
}

// IsCk1 reports whether value is a well-formed ck1, either form. Well-formed
// only: whether its proof verifies is NoteIDOf's question.
func IsCk1(value string) bool {
	_, err := DecodeCk1(value)
	return err == nil
}

// EncodeCs1 encodes a legacy fixed-prefix certificate. New code should use
// EncodeCs1WithAmount. This function remains unchanged so old notes and
// callers remain usable.
func EncodeCs1(signature [65]byte) string { return encodeFixed("cs", signature[:]) }

// DecodeCs1 reads only a legacy fixed-prefix cs1 back to its signature.
func DecodeCs1(value string) ([65]byte, error) {
	var out [65]byte
	payload, err := decodeFixed("cs", value, len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], payload)
	return out, nil
}

// IsCs1 reports whether value is a well-formed legacy fixed-prefix cs1.
func IsCs1(value string) bool {
	_, err := DecodeCs1(value)
	return err == nil
}

// Cs1 is a current amount-bearing mint certificate.
type Cs1 struct {
	AmountMsat int64
	Signature  [65]byte
}

func encodeCs1AmountSuffix(amountMsat int64) string {
	for _, unit := range []struct {
		suffix string
		msat   int64
	}{
		{"", 100_000_000_000},
		{"m", 100_000_000},
		{"u", 100_000},
		{"n", 100},
	} {
		if amountMsat%unit.msat == 0 {
			return strconv.FormatInt(amountMsat/unit.msat, 10) + unit.suffix
		}
	}
	// One pico-BTC is 0.1 msat. Appending a zero avoids overflowing int64
	// while rendering every amount that the package can represent.
	return strconv.FormatInt(amountMsat, 10) + "0p"
}

func decodeCs1AmountSuffix(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	digits, multiplier := value, byte(0)
	last := value[len(value)-1]
	if strings.ContainsRune("munp", rune(last)) {
		digits, multiplier = value[:len(value)-1], last
	}
	if digits == "" {
		return 0, false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return 0, false
	}
	switch multiplier {
	case 0:
		n.Mul(n, big.NewInt(100_000_000_000))
	case 'm':
		n.Mul(n, big.NewInt(100_000_000))
	case 'u':
		n.Mul(n, big.NewInt(100_000))
	case 'n':
		n.Mul(n, big.NewInt(100))
	case 'p':
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(n, big.NewInt(10), remainder)
		if remainder.Sign() != 0 {
			return 0, false
		}
		n = quotient
	}
	if !n.IsInt64() {
		return 0, false
	}
	return n.Int64(), true
}

// EncodeCs1WithAmount encodes a current certificate. Its human-readable
// prefix is cs followed by the amount using BOLT 11 amount suffix rules; its
// payload is the mint's 65-byte recoverable signature over that same amount
// and the note key.
func EncodeCs1WithAmount(amountMsat int64, signature [65]byte) (string, error) {
	if amountMsat < 0 {
		return "", fmt.Errorf("amountMsat must be non-negative")
	}
	return encodeFixed("cs"+encodeCs1AmountSuffix(amountMsat), signature[:]), nil
}

// DecodeCs1WithAmount reads a current certificate and the amount carried by
// its prefix. It deliberately rejects the legacy fixed cs prefix, which has no
// amount to return.
func DecodeCs1WithAmount(value string) (Cs1, error) {
	var out Cs1
	invalid := func(why string) error {
		return &ProtocolError{Detail: "not an amount-bearing cs1: " + why}
	}
	trimmed := strings.TrimSpace(value)
	prefix, words, version, err := bech32.DecodeNoLimitWithVersion(trimmed)
	switch {
	case err != nil:
		return out, invalid("not a well-formed bech32m string")
	case version != bech32.VersionM:
		return out, invalid("the checksum is bech32, not bech32m")
	case !strings.HasPrefix(prefix, "cs"):
		return out, invalid("the prefix does not start with cs")
	}
	amount, ok := decodeCs1AmountSuffix(strings.TrimPrefix(prefix, "cs"))
	if !ok {
		return out, invalid("the prefix carries no whole int64 msat amount")
	}
	payload, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil {
		return out, invalid("the padding is not zero")
	}
	if len(payload) != len(out.Signature) {
		return out, invalid(fmt.Sprintf("the payload is %d bytes, not %d", len(payload), len(out.Signature)))
	}
	out.AmountMsat = amount
	copy(out.Signature[:], payload)
	return out, nil
}

// IsCs1WithAmount reports whether value is a current amount-bearing cs1.
func IsCs1WithAmount(value string) bool {
	_, err := DecodeCs1WithAmount(value)
	return err == nil
}

// DecodeAnyCs1 reads the signature from either current or legacy form.
func DecodeAnyCs1(value string) ([65]byte, error) {
	if current, err := DecodeCs1WithAmount(value); err == nil {
		return current.Signature, nil
	}
	return DecodeCs1(value)
}

// IsAnyCs1 reports whether value is either a current or legacy cs1.
func IsAnyCs1(value string) bool {
	_, err := DecodeAnyCs1(value)
	return err == nil
}

// Cx1 is a watch-only branch export: the branch's x-only public key and its
// chain code. Anyone holding one can enumerate every note key on the branch,
// and link them, but cannot spend any.
type Cx1 struct {
	PubkeyXOnly [32]byte
	ChainCode   [32]byte
}

// EncodeCx1 encodes a branch's x-only key and chain code.
func EncodeCx1(pubkeyXOnly, chainCode [32]byte) string {
	var payload [64]byte
	copy(payload[:32], pubkeyXOnly[:])
	copy(payload[32:], chainCode[:])
	return encodeFixed("cx", payload[:])
}

// DecodeCx1 reads a cx1 back to its two halves.
func DecodeCx1(value string) (Cx1, error) {
	var out Cx1
	payload, err := decodeFixed("cx", value, 64)
	if err != nil {
		return out, err
	}
	copy(out.PubkeyXOnly[:], payload[:32])
	copy(out.ChainCode[:], payload[32:])
	return out, nil
}

// IsCx1 reports whether value is a well-formed cx1.
func IsCx1(value string) bool {
	_, err := DecodeCx1(value)
	return err == nil
}

// ---- the per-note key tweak ----
//
//	t    = tagged_hash("LNURLcash/derive", P || chainCode || ser32_be(i))
//	pk_i = x(lift_x(P) + t*G)
//	sk_i = ((P has even y ? p : n - p) + t) mod n
//
// BIP-341's taproot tweak, so a watcher holding only a cx1 computes the same
// pk_i the holder does. i is any uint32 and is never hardened: a watch-only
// derivation cannot harden anything, which is the whole reason a cx1 works.
// The four-byte big-endian width is what lnurl-wallet and lnurl-mint both use;
// the spec text does not pin it.
//
// t >= n is refused rather than reduced, as BIP-341 does and lnurl-mint does,
// and so is a note key at zero. Both are ~2^-128 events, but a key that
// differs from the one every other implementation derives is a note nobody can
// find, so the index is reported unusable and the caller moves to the next.

var noteDeriveTag = sha256.Sum256([]byte("LNURLcash/derive"))

func unusableIndex(index uint32) error {
	return &ProtocolError{Detail: fmt.Sprintf("note index %d is unusable on this branch - use the next index", index)}
}

func noteTweak(pubkeyXOnly, chainCode [32]byte, index uint32) (secp256k1.ModNScalar, error) {
	var ser [4]byte
	binary.BigEndian.PutUint32(ser[:], index)
	h := sha256.New()
	for _, part := range [][]byte{noteDeriveTag[:], noteDeriveTag[:], pubkeyXOnly[:], chainCode[:], ser[:]} {
		h.Write(part)
	}
	var digest [32]byte
	h.Sum(digest[:0])
	var t secp256k1.ModNScalar
	if t.SetBytes(&digest) != 0 {
		return t, unusableIndex(index)
	}
	return t, nil
}

// DeriveNotePubkey returns the i-th note key on a branch, x-only, from the
// branch's public half alone. It needs no private key, which is what lets a
// service holding a registered cx1 mint straight to the holder's next key.
func DeriveNotePubkey(branchPubkeyXOnly, chainCode [32]byte, index uint32) ([32]byte, error) {
	var out [32]byte
	t, err := noteTweak(branchPubkeyXOnly, chainCode, index)
	if err != nil {
		return out, err
	}
	// lift_x: the even-y point with this x, the only one a cx1 can name
	branch, err := secp256k1.ParsePubKey(append([]byte{secp256k1.PubKeyFormatCompressedEven}, branchPubkeyXOnly[:]...))
	if err != nil {
		return out, &ProtocolError{Detail: "that branch key is not the x coordinate of a point on the curve"}
	}
	var point, tweak, note secp256k1.JacobianPoint
	branch.AsJacobian(&point)
	secp256k1.ScalarBaseMultNonConst(&t, &tweak)
	secp256k1.AddNonConst(&point, &tweak, &note)
	if (note.X.IsZero() && note.Y.IsZero()) || note.Z.IsZero() {
		return out, unusableIndex(index)
	}
	note.ToAffine()
	note.X.PutBytes(&out)
	return out, nil
}

// DeriveNoteSecretKey is the holder's half: the i-th note's secret key.
//
// The branch key's own point may have odd y, and a cx1 carries only x, which
// names the even-y point. So an odd branch key is negated first, or its note
// keys would not be the ones a watcher derives - and a note a service minted
// from the cx1 would sit under a key nobody holds.
func DeriveNoteSecretKey(branchPrivateKey, chainCode [32]byte, index uint32) ([32]byte, error) {
	var p secp256k1.ModNScalar
	if p.SetBytes(&branchPrivateKey) != 0 || p.IsZero() {
		return [32]byte{}, &ProtocolError{Detail: "a branch private key is a 32-byte scalar in [1, n)"}
	}
	compressed := secp256k1.NewPrivateKey(&p).PubKey().SerializeCompressed()
	var branchX [32]byte
	copy(branchX[:], compressed[1:])
	t, err := noteTweak(branchX, chainCode, index)
	if err != nil {
		return [32]byte{}, err
	}
	if compressed[0] == secp256k1.PubKeyFormatCompressedOdd {
		p.Negate()
	}
	p.Add(&t)
	if p.IsZero() {
		return [32]byte{}, unusableIndex(index)
	}
	return p.Bytes(), nil
}

// ---- ownership proofs ----
//
//	sig = BIP340.Sign(sk, sha256("LNURLcash"))
//	ck1 = bech32m("ck", pk || sig)
//
// One fixed digest and fixed all-zero BIP-340 auxiliary input make the bearer
// value deterministic: re-deriving a key reproduces its one ck1 byte for byte.
// The message is hashed to 32 bytes before signing, rather than signed as the
// raw 9-byte string, because BIP-340's own reference implementation and most
// conforming Schnorr signers (libsecp256k1's schnorrsig module and btcec's
// included) only accept a 32-byte message (2026-09-16, luds#6de59b2).

var noteOwnershipMessage = []byte("LNURLcash")

var noteOwnershipDigest = sha256.Sum256(noteOwnershipMessage)

// legacyNoteOwnershipDigest is what a pre-Schnorr 65-byte ck1 was signed over.
var legacyNoteOwnershipDigest = func() [32]byte {
	inner := sha256.Sum256([]byte(lightningSignedMessagePrefix + "LNURLcash"))
	return sha256.Sum256(inner[:])
}()

// NoteOwnershipMessage returns the message every ownership signature is made
// over. Since 2026-09-16 it is signed as its sha256 digest; before that, as
// the raw bytes, which RecoverNoteOwnershipPubkey still reads back.
func NoteOwnershipMessage() []byte {
	return append([]byte(nil), noteOwnershipMessage...)
}

// decred lays a compact signature out as header || r || s, the header being 27,
// plus 4 for a compressed key, plus the recovery id. The wire puts the bare
// recovery id last instead, so every signature crossing that boundary is
// rebuilt.
const compactHeaderCompressed = 27 + 4

// SignNoteOwnership signs the ownership digest with a note's secret key and
// returns the 96-byte pk || sig payload. Encode it with EncodeCk1 to spend the
// note - which makes the result bearer material, exactly as the secret key is.
func SignNoteOwnership(secretKey [32]byte) ([96]byte, error) {
	var out [96]byte
	var key btcec.ModNScalar
	if key.SetBytes(&secretKey) != 0 || key.IsZero() {
		return out, &ProtocolError{Detail: "a note secret key is a 32-byte scalar in [1, n)"}
	}
	private := btcec.PrivKeyFromScalar(&key)
	signature, err := schnorr.Sign(private, noteOwnershipDigest[:], schnorr.CustomNonce([32]byte{}))
	if err != nil {
		return out, &ProtocolError{Detail: "could not sign the note ownership message"}
	}
	copy(out[:32], schnorr.SerializePubKey(private.PubKey()))
	copy(out[32:], signature.Serialize())
	return out, nil
}

// RecoverNoteOwnershipPubkey validates an ownership payload and returns the
// note's x-only public key. A 96-byte pk || sig is verified against the current
// sha256 digest first, then against the pre-2026-09-16 raw message, so a note
// minted under that scheme stays redeemable until it is rotated;
// SignNoteOwnership never produces that shape anymore. A legacy 65-byte
// r || s || recovery id signature is recovered as before. An error for an
// invalid proof or any other length.
func RecoverNoteOwnershipPubkey(payload []byte) ([32]byte, error) {
	var out [32]byte
	switch len(payload) {
	case 96:
		pubkey, err := schnorr.ParsePubKey(payload[:32])
		if err != nil {
			return out, &ProtocolError{Detail: "that ownership proof does not verify"}
		}
		signature, err := schnorr.ParseSignature(payload[32:])
		if err != nil {
			return out, &ProtocolError{Detail: "that ownership proof does not verify"}
		}
		if !signature.Verify(noteOwnershipDigest[:], pubkey) && !verifyBIP340(payload[:32], payload[32:], noteOwnershipMessage) {
			return out, &ProtocolError{Detail: "that ownership proof does not verify"}
		}
		copy(out[:], payload[:32])
		return out, nil
	case 65:
		if payload[64] > 3 {
			return out, &ProtocolError{Detail: "a recoverable signature ends in a recovery id of 0 to 3"}
		}
		var compact [65]byte
		compact[0] = compactHeaderCompressed + payload[64]
		copy(compact[1:], payload[:64])
		pubkey, _, err := ecdsa.RecoverCompact(compact[:], legacyNoteOwnershipDigest[:])
		if err != nil {
			return out, &ProtocolError{Detail: "that ownership signature does not recover to a key"}
		}
		copy(out[:], pubkey.SerializeCompressed()[1:])
		return out, nil
	default:
		return out, &ProtocolError{Detail: "an ownership proof is 96 bytes, or a legacy 65"}
	}
}

var bip340ChallengeTag = sha256.Sum256([]byte("BIP0340/challenge"))

// verifyBIP340 is BIP-340 verification for a message of any length, which the
// spec allows and btcec's Verify does not. It exists only to read back a ck1
// signed over the raw 9-byte message before 2026-09-16.
func verifyBIP340(pubkeyXOnly, signature, message []byte) bool {
	if len(pubkeyXOnly) != 32 || len(signature) != 64 {
		return false
	}
	pubkey, err := schnorr.ParsePubKey(pubkeyXOnly)
	if err != nil {
		return false
	}
	var r secp256k1.FieldVal
	if r.SetByteSlice(signature[:32]) {
		return false
	}
	var s secp256k1.ModNScalar
	if s.SetByteSlice(signature[32:]) {
		return false
	}
	h := sha256.New()
	for _, part := range [][]byte{bip340ChallengeTag[:], bip340ChallengeTag[:], signature[:32], pubkeyXOnly, message} {
		h.Write(part)
	}
	var e secp256k1.ModNScalar
	e.SetByteSlice(h.Sum(nil))
	e.Negate()
	var point, sG, eP, R secp256k1.JacobianPoint
	pubkey.AsJacobian(&point)
	secp256k1.ScalarBaseMultNonConst(&s, &sG)
	secp256k1.ScalarMultNonConst(&e, &point, &eP)
	secp256k1.AddNonConst(&sG, &eP, &R)
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		return false
	}
	R.ToAffine()
	return !R.Y.IsOdd() && r.Equals(&R.X)
}

// ---- a note's k1, either kind ----

// NoteIDOf returns the id a service files a note under: hex sha256(k1) for a
// Part 1 secret, and for a Part 2 ck1 the verified hex x-only key it embeds.
// An error for anything else, including a ck1 whose proof does not verify.
//
// Compare notes by this, never by an unverified payload.
func NoteIDOf(k1 string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(k1))
	if IsPreimage(value) {
		return HashK1(value)
	}
	pubkey, err := ck1Pubkey(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pubkey[:]), nil
}

// NoteLookupOf returns what to look a note up by without disclosing it: the
// hash for a Part 1 secret, and for a Part 2 note its cp1, which also brings
// its certificate back. Pass it to BuildNoteInfoURLByHash or
// Client.FetchNoteInfoByHash.
func NoteLookupOf(k1 string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(k1))
	if IsPreimage(value) {
		return HashK1(value)
	}
	pubkey, err := ck1Pubkey(value)
	if err != nil {
		return "", err
	}
	return EncodeCp1(pubkey), nil
}

func ck1Pubkey(value string) ([32]byte, error) {
	decoded, err := DecodeCk1(value)
	if err != nil {
		return [32]byte{}, &ProtocolError{Detail: "a k1 is 32 bytes of hex or a ck1"}
	}
	return RecoverNoteOwnershipPubkey(decoded.Bytes())
}

// ---- the address branch ----

// DeriveCashAddressNode returns m/139'/d1/d2/d3/d4 for one mint - the literal
// path LUD-25's text specifies, and the exact node DeriveCashDomainNode already
// derives for any service. There is no separate purpose for Part 2: an earlier
// reference-wallet extension deterministically derived Part 1 secrets off this
// same root too, under a 1' sub-purpose kept just for this branch to avoid
// colliding with it; that extension is gone (see cash.go), so there is nothing
// left to collide with.
//
// Bearer material for every note on the branch. Hand out CashNodeToCx1 of it,
// never the node.
func DeriveCashAddressNode(root CashNode, host string) (CashNode, error) {
	return DeriveCashDomainNode(root, host)
}

// CashNodeToCx1 is the watch-only half of an address node: what a holder
// hands a mint so the mint can pay to the holder's keys.
func CashNodeToCx1(node CashNode) (Cx1, error) {
	var out Cx1
	var key secp256k1.ModNScalar
	if key.SetBytes(&node.PrivateKey) != 0 || key.IsZero() {
		return out, &ProtocolError{Detail: "cash node holds an invalid private key"}
	}
	copy(out.PubkeyXOnly[:], secp256k1.NewPrivateKey(&key).PubKey().SerializeCompressed()[1:])
	out.ChainCode = node.ChainCode
	return out, nil
}

// ---- a branch rooted in a Nostr key ----
//
// Not part of LUD-25. A lightning address on a Nostr-native mint belongs to an
// npub, and a holder with no BIP39 words - a hardware signer that keeps only
// its identity key, or a wallet that never made any - can still be paid to
// keys of its own:
//
//	seed = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
//
// then the address path above from that seed, unchanged. heartwood-esp32
// derives exactly this on the device and lnurlcash-kit exports it, and all
// three are graded against conformance's nostr-seed.json. The identity key
// rebuilds every note paid to the branch, so whoever can restore that key can
// recover the notes, with or without the device that received them.

// NostrCashSeedLabel is the HMAC message a Nostr identity's seed is drawn with.
const NostrCashSeedLabel = "LNURLcash/nostr-seed"

// DeriveNostrCashSeed returns the 32-byte seed a Nostr identity's address
// branches grow from. Secret: it rebuilds every note paid to them.
func DeriveNostrCashSeed(secretKey [32]byte) [32]byte {
	mac := hmac.New(sha256.New, secretKey[:])
	mac.Write([]byte(NostrCashSeedLabel))
	var seed [32]byte
	copy(seed[:], mac.Sum(nil))
	return seed
}

// DeriveNostrAddressNode returns one mint's address branch for a Nostr
// identity. Bearer material, like any address node: hand out CashNodeToCx1 of
// it.
func DeriveNostrAddressNode(secretKey [32]byte, host string) (CashNode, error) {
	seed := DeriveNostrCashSeed(secretKey)
	root, err := DeriveCashRoot(seed[:])
	if err != nil {
		return CashNode{}, err
	}
	return DeriveCashAddressNode(root, host)
}
