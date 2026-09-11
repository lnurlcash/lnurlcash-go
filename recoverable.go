package lnurlcash

// LUD-25 Part 2: notes keyed by a public key.
//
// A Part 2 note is keyed by a public key rather than a hash. The holder keeps
// sk, discloses pk as cp1<pk>, and spends the note with ck1, a recoverable
// signature by sk over one fixed message: the service recovers pk from it and
// looks the note up. The service certifies each note with cs1, the same
// signature it has always made, over hex(pk) instead of a hash, so a recipient
// can check issuance offline with nothing but the ck1 and the cs1.
//
// A watch-only cx1 - a branch's x-only key and its chain code - lets whoever
// holds it derive every note key on the branch, which is how a service mints
// straight to a holder's next key, but spend none of them.
//
// The names follow lnurlcash-kit's recoverable.ts, which follows lnurl-wallet.
// Where the spec text and the reference wallet disagree, this follows the
// wallet: see DeriveCashAddressNode.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

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

// EncodeCk1 encodes a note's bearer secret: its 65-byte r || s || recovery id
// ownership signature, from SignNoteOwnership.
func EncodeCk1(signature [65]byte) string { return encodeFixed("ck", signature[:]) }

// DecodeCk1 reads a ck1 back to its signature.
func DecodeCk1(value string) ([65]byte, error) {
	var out [65]byte
	payload, err := decodeFixed("ck", value, len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], payload)
	return out, nil
}

// IsCk1 reports whether value is a well-formed ck1. Well-formed only: whether
// it recovers to a key is NoteIDOf's question.
func IsCk1(value string) bool {
	_, err := DecodeCk1(value)
	return err == nil
}

// EncodeCs1 encodes a service's issuance certificate: the same 65-byte layout
// as a ck1, signed by the mint over "LNURLcash:<amount_msat>:<hex(pk)>".
func EncodeCs1(signature [65]byte) string { return encodeFixed("cs", signature[:]) }

// DecodeCs1 reads a cs1 back to its signature.
func DecodeCs1(value string) ([65]byte, error) {
	var out [65]byte
	payload, err := decodeFixed("cs", value, len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], payload)
	return out, nil
}

// IsCs1 reports whether value is a well-formed cs1.
func IsCs1(value string) bool {
	_, err := DecodeCs1(value)
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
//	message = "LNURLcash"
//	digest  = sha256(sha256("Lightning Signed Message:" || message))
//
// One fixed message for every note, and RFC6979 nonces, so re-deriving a key
// reproduces the same ck1 byte for byte: the value submitted to spend a note
// is the value shown to prove it. Another signer can still produce a
// different valid ck1 for the same key - any nonce makes a signature the
// service recovers the same pk from - so a note is identified by NoteIDOf,
// never by comparing ck1 strings.

var noteOwnershipDigest = func() [32]byte {
	inner := sha256.Sum256([]byte(lightningSignedMessagePrefix + "LNURLcash"))
	return sha256.Sum256(inner[:])
}()

// decred lays a compact signature out as header || r || s, the header being 27,
// plus 4 for a compressed key, plus the recovery id. The wire puts the bare
// recovery id last instead, so every signature crossing that boundary is
// rebuilt.
const compactHeaderCompressed = 27 + 4

// SignNoteOwnership signs the ownership message with a note's secret key:
// RFC6979, low-S, laid out r || s || recovery id as the wire wants it. Encode
// it with EncodeCk1 to spend the note - which makes the result bearer
// material, exactly as the secret key is.
func SignNoteOwnership(secretKey [32]byte) ([65]byte, error) {
	var out [65]byte
	var key secp256k1.ModNScalar
	if key.SetBytes(&secretKey) != 0 || key.IsZero() {
		return out, &ProtocolError{Detail: "a note secret key is a 32-byte scalar in [1, n)"}
	}
	compact := ecdsa.SignCompact(secp256k1.NewPrivateKey(&key), noteOwnershipDigest[:], true)
	copy(out[:64], compact[1:])
	out[64] = compact[0] - compactHeaderCompressed
	return out, nil
}

// RecoverNoteOwnershipPubkey recovers a note's x-only public key, offline,
// from its ownership signature. An error for one that does not recover,
// including a recovery id outside 0 to 3.
func RecoverNoteOwnershipPubkey(signature [65]byte) ([32]byte, error) {
	var out [32]byte
	if signature[64] > 3 {
		return out, &ProtocolError{Detail: "a recoverable signature ends in a recovery id of 0 to 3"}
	}
	var compact [65]byte
	compact[0] = compactHeaderCompressed + signature[64]
	copy(compact[1:], signature[:64])
	pubkey, _, err := ecdsa.RecoverCompact(compact[:], noteOwnershipDigest[:])
	if err != nil {
		return out, &ProtocolError{Detail: "that ownership signature does not recover to a key"}
	}
	copy(out[:], pubkey.SerializeCompressed()[1:])
	return out, nil
}

// ---- a note's k1, either kind ----

// NoteIDOf returns the id a service files a note under: hex sha256(k1) for a
// Part 1 secret, and for a Part 2 ck1 the hex x-only key it recovers to. An
// error for anything else, including a ck1 that does not recover.
//
// Two different ck1 strings can share an id, so compare notes by this, never
// by their k1.
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
	signature, err := DecodeCk1(value)
	if err != nil {
		return [32]byte{}, &ProtocolError{Detail: "a k1 is 32 bytes of hex or a ck1"}
	}
	return RecoverNoteOwnershipPubkey(signature)
}

// ---- the address branch ----

const cashAddressBranch = uint32(1)

// DeriveCashAddressNode returns m/139'/1'/d1/d2/d3/d4 for one mint: the branch
// Part 2 note keys are tweaked from. d1..d4 are drawn exactly as the Part 1
// ladder draws them, from HMAC-SHA256(the private key at m/139'/1'/0, host),
// raw and hardened only by magnitude.
//
// This is lnurl-wallet's path (cashSecrets.ts), and it is the one to use. The
// spec text roots the branch at m/139'/d1/d2/d3/d4 - the very node
// DeriveCashDomainNode already returns for Part 1 - so a wallet following the
// text would find none of the reference wallet's notes, and share a node
// between two schemes besides.
//
// Bearer material for every note on the branch. Hand out CashNodeToCx1 of it,
// never the node.
func DeriveCashAddressNode(root CashNode, host string) (CashNode, error) {
	branch, err := DeriveCashChild(root, cashAddressBranch+hardened)
	if err != nil {
		return CashNode{}, err
	}
	return DeriveCashDomainNode(branch, host)
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
