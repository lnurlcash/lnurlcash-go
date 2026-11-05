package lnurlcash

// LUD-25's wire values, and notes owned by a key.
//
// Every note is a taproot output key Q, written cp1<Q> (spend.go). A key-path
// note is the case where Q is the holder's own key, used as is: the holder
// keeps sk, discloses cp1<Q>, and spends the note with a ck1, Q followed by a
// BIP-340 signature by sk over the key-path sighash for the mint's domain. The
// mint certifies every note with a cs1 over hex(Q), so a recipient can check
// issuance offline with nothing but the spend, the cs1 and the note URL's
// domain.
//
// A watch-only cx1 - a share's compressed key and its chain code, an xpub in
// BIP-32's order - lets whoever holds it derive every note key on the share with
// CKDpub, which is how a service mints straight to a holder's next key, but
// spend none of them. Below a service's root S, every key is plain BIP-32
// (LUD-26).
//
// The names follow lnurl-wallet's src/lib.

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

// EncodeCp1 encodes a note's output key Q: 32 bytes, x-only, as BIP-340.
func EncodeCp1(pubkeyXOnly [32]byte) string { return encodeFixed("cp", pubkeyXOnly[:]) }

// DecodeCp1 reads a cp1 back to its x-only key. A Q that is not the x
// coordinate of a curve point is refused, as LUD-25 has a mint refuse it: no
// spend could ever open that note, so paying into it would burn the money.
func DecodeCp1(value string) ([32]byte, error) {
	var out [32]byte
	payload, err := decodeFixed("cp", value, len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], payload)
	if !IsXOnlyPoint(out) {
		return [32]byte{}, &ProtocolError{Detail: "not a cp1: its key is not the x coordinate of a point on the curve"}
	}
	return out, nil
}

// IsCp1 reports whether value is a well-formed cp1 naming a curve point.
func IsCp1(value string) bool {
	_, err := DecodeCp1(value)
	return err == nil
}

// EncodeCk1 encodes a key-path spend: the note's 32-byte output key Q followed
// by its 64-byte BIP-340 signature, from SignNoteOwnership. Whoever has it can
// spend the note, at the one mint it was signed for.
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
// only: whether it opens its note at a mint is VerifySpend's question.
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
	// LUD-25 has a SERVICE refuse a recovery id above 3
	if payload[64] > 3 {
		return out, invalid("the recovery id is above 3")
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

// Cx1 is a share's extended public key (LUD-26): its chain code and compressed
// point, in BIP-32's order. Whoever holds one can derive every note key on the
// share with DeriveNotePubkey, and link them all to each other, but cannot
// spend any.
type Cx1 struct {
	ChainCode [32]byte
	// Pubkey is compressed, 02 or 03 first.
	Pubkey [33]byte
}

// PubkeyXOnly returns x(P): what a registration proof by this share verifies
// against.
func (c Cx1) PubkeyXOnly() [32]byte {
	var x [32]byte
	copy(x[:], c.Pubkey[1:])
	return x
}

// EncodeCx1 encodes bech32m("cx", chainCode || P), 113 characters.
func EncodeCx1(cx1 Cx1) string {
	var payload [65]byte
	copy(payload[:32], cx1.ChainCode[:])
	copy(payload[32:], cx1.Pubkey[:])
	return encodeFixed("cx", payload[:])
}

// DecodeCx1 reads a cx1 back to its two halves. A payload that is not 65 bytes
// is refused, as is a key that is not a compressed curve point: the superseded
// 64-byte shape is DecodeLegacyCx1's, and no SERVICE registers one any more.
func DecodeCx1(value string) (Cx1, error) {
	var out Cx1
	payload, err := decodeFixed("cx", value, 65)
	if err != nil {
		return out, err
	}
	copy(out.ChainCode[:], payload[:32])
	copy(out.Pubkey[:], payload[32:])
	if _, err := secp256k1.ParsePubKey(out.Pubkey[:]); err != nil {
		return Cx1{}, &ProtocolError{Detail: "not a cx1: its key is not a compressed point on the curve"}
	}
	return out, nil
}

// IsCx1 reports whether value is a well-formed cx1.
func IsCx1(value string) bool {
	_, err := DecodeCx1(value)
	return err == nil
}

// ---- LUD-26: notes below a SERVICE's root ----
//
//	S            = m/139'/d1/d2/d3/d4      see DeriveServiceRoot
//	S/a'/0/i     wallet: every note the wallet mints, rotates or merges into, and a split's p1
//	S/a'/1/i     change: a split's p2
//	S/a'/2/n'    share n, handed out as its cx1
//	S/a'/2/n'/i  note i of share n, picked and credited by the SERVICE
//
// Plain BIP-32 all the way down: a note's secret key is the private key at its
// path and its Q is x(sk*G), so any BIP-32 library derives the same tree, and a
// SERVICE holding a share's cx1 derives that share's notes with CKDpub alone.
// Accounts and shares are hardened, so no account's or share's keys can be
// derived from another's; note indices are not, and are below 2^31.

const (
	// ChainWallet is every note the wallet mints, rotates or merges into, and
	// a split's p1.
	ChainWallet uint32 = 0
	// ChainChange is a split's change p2.
	ChainChange uint32 = 1
	// ChainShare holds the shares, each exported as a cx1.
	ChainShare uint32 = 2
)

// NotePath is where a note sits below a SERVICE's root. Build one with
// WalletNotePath, ChangeNotePath or ShareNotePath.
type NotePath struct {
	// Chain is ChainWallet, ChainChange or ChainShare.
	Chain   uint32
	Account uint32
	// Share is the share's number, used only on ChainShare.
	Share uint32
	Index uint32
}

// WalletNotePath is S/account'/0/index.
func WalletNotePath(account, index uint32) NotePath {
	return NotePath{Chain: ChainWallet, Account: account, Index: index}
}

// ChangeNotePath is S/account'/1/index.
func ChangeNotePath(account, index uint32) NotePath {
	return NotePath{Chain: ChainChange, Account: account, Index: index}
}

// ShareNotePath is S/account'/2/share'/index. Only a SERVICE picks these
// indices; a wallet never names one as a resulting note itself.
func ShareNotePath(account, share, index uint32) NotePath {
	return NotePath{Chain: ChainShare, Account: account, Share: share, Index: index}
}

func belowHardened(value uint32, what string) (uint32, error) {
	if value >= hardened {
		return 0, &ProtocolError{Detail: fmt.Sprintf("%s %d is not below 2^31", what, value)}
	}
	return value, nil
}

// Indices returns the BIP-32 indices below S, hardened ones included.
func (p NotePath) Indices() ([]uint32, error) {
	account, err := belowHardened(p.Account, "an account")
	if err != nil {
		return nil, err
	}
	out := []uint32{account + hardened}
	switch p.Chain {
	case ChainWallet, ChainChange:
		out = append(out, p.Chain)
	case ChainShare:
		share, err := belowHardened(p.Share, "a share")
		if err != nil {
			return nil, err
		}
		out = append(out, ChainShare, share+hardened)
	default:
		return nil, &ProtocolError{Detail: fmt.Sprintf("%d is not a note chain", p.Chain)}
	}
	index, err := belowHardened(p.Index, "a note index")
	if err != nil {
		return nil, err
	}
	return append(out, index), nil
}

// NoteKey is a note's keys. Bearer material: the secret key spends the note.
type NoteKey struct {
	SecretKey [32]byte
	// Pubkey is compressed, so its y parity is visible: a BIP-340 signer
	// negates the secret key when it is odd.
	Pubkey [33]byte
	// OutputKey is Q = x(Pubkey), the note itself.
	OutputKey [32]byte
}

// DeriveNoteKey returns the note at path below serviceRoot (DeriveServiceRoot).
func DeriveNoteKey(serviceRoot CashNode, path NotePath) (NoteKey, error) {
	indices, err := path.Indices()
	if err != nil {
		return NoteKey{}, err
	}
	node := serviceRoot
	for _, index := range indices {
		if node, err = DeriveCashChild(node, index); err != nil {
			return NoteKey{}, err
		}
	}
	pubkey, err := CashNodePublicKey(node)
	if err != nil {
		return NoteKey{}, err
	}
	out := NoteKey{SecretKey: node.PrivateKey, Pubkey: pubkey}
	copy(out.OutputKey[:], pubkey[1:])
	return out, nil
}

// DeriveShareNode returns S/account'/2/share', the node behind a share's cx1.
// Bearer material for every note on the share: hand out CashNodeToCx1 of it,
// and sign its registration with its own key (SignAddressProof).
func DeriveShareNode(serviceRoot CashNode, account, share uint32) (CashNode, error) {
	account, err := belowHardened(account, "an account")
	if err != nil {
		return CashNode{}, err
	}
	share, err = belowHardened(share, "a share")
	if err != nil {
		return CashNode{}, err
	}
	node := serviceRoot
	for _, index := range []uint32{account + hardened, ChainShare, share + hardened} {
		if node, err = DeriveCashChild(node, index); err != nil {
			return CashNode{}, err
		}
	}
	return node, nil
}

// CashNodeToCx1 is the watch-only half of a share node: what a holder hands a
// mint so the mint can pay to the holder's keys.
func CashNodeToCx1(node CashNode) (Cx1, error) {
	pubkey, err := CashNodePublicKey(node)
	if err != nil {
		return Cx1{}, err
	}
	return Cx1{ChainCode: node.ChainCode, Pubkey: pubkey}, nil
}

// DeriveNotePubkey returns Q of note index on the share cx1 exports: CKDpub, no
// private key anywhere, which is what lets a SERVICE credit a registered
// share's next note. A hardened index is refused, and an unusable one
// (~2^-127) is an error: use the next.
func DeriveNotePubkey(cx1 Cx1, index uint32) ([32]byte, error) {
	var out [32]byte
	pubkey, _, err := DeriveCashChildPub(cx1.Pubkey, cx1.ChainCode, index)
	if err != nil {
		return out, err
	}
	copy(out[:], pubkey[1:])
	return out, nil
}

// ---- superseded: the per-note tweak ----
//
// Before LUD-26 (luds a6c4652), note keys were tweaked off one branch node,
// m/139'/d1/d2/d3/d4 over the host as stored (port included), and a cx1 was the
// 64-byte x(P) || chainCode:
//
//	t    = tagged_hash("LNURLcash/derive", P || chainCode || ser32(purpose) || ser32(i)) mod n
//	pk_i = x(lift_x(P) + t*G)
//	sk_i = ((P has even y ? p : n - p) + t) mod n
//
// purpose 0 was the wallet's own notes, 1 a split's change and 2 the Lightning
// Address rail (luds 50d740a); before purposes (luds 6e865b1) there was no
// ser32(purpose) at all. Notes minted under either are still money, so a wallet
// derives them here to find and sweep them into LUD-26 keys. Nothing new is
// ever derived or registered this way.

// LegacyPurpose is the superseded tweak's purpose counter.
type LegacyPurpose int64

const (
	// LegacyPurposeNone is the scheme before purposes existed (luds
	// 6e865b1): no purpose is hashed at all.
	LegacyPurposeNone LegacyPurpose = -1
	// LegacyPurposeWallet is the wallet's own notes.
	LegacyPurposeWallet LegacyPurpose = 0
	// LegacyPurposeChange is a split's change.
	LegacyPurposeChange LegacyPurpose = 1
	// LegacyPurposeLightningAddress is Lightning Address auto-mint and
	// internal transfer.
	LegacyPurposeLightningAddress LegacyPurpose = 2
)

// LegacyCx1 is a superseded 64-byte cx1, x(P) || chainCode.
type LegacyCx1 struct {
	PubkeyXOnly [32]byte
	ChainCode   [32]byte
}

// EncodeLegacyCx1 encodes the superseded 64-byte shape.
func EncodeLegacyCx1(cx1 LegacyCx1) string {
	var payload [64]byte
	copy(payload[:32], cx1.PubkeyXOnly[:])
	copy(payload[32:], cx1.ChainCode[:])
	return encodeFixed("cx", payload[:])
}

// DecodeLegacyCx1 reads the superseded 64-byte shape.
func DecodeLegacyCx1(value string) (LegacyCx1, error) {
	var out LegacyCx1
	payload, err := decodeFixed("cx", value, 64)
	if err != nil {
		return out, err
	}
	copy(out.PubkeyXOnly[:], payload[:32])
	copy(out.ChainCode[:], payload[32:])
	return out, nil
}

// LegacyBranchNode returns the node the superseded schemes tweaked their notes
// off: m/139'/d1/d2/d3/d4 for host exactly as the wallet stored it, port
// included. Bearer material for every note it ever held there under them.
func LegacyBranchNode(root CashNode, host string) (CashNode, error) {
	return DeriveCashDomainNode(root, host)
}

// LegacyCx1Of returns the superseded watch-only half of a LegacyBranchNode.
func LegacyCx1Of(node CashNode) (LegacyCx1, error) {
	var out LegacyCx1
	pubkey, err := CashNodePublicKey(node)
	if err != nil {
		return out, err
	}
	copy(out.PubkeyXOnly[:], pubkey[1:])
	out.ChainCode = node.ChainCode
	return out, nil
}

var noteDeriveTag = sha256.Sum256([]byte("LNURLcash/derive"))

func unusableIndex(index uint32) error {
	return &ProtocolError{Detail: fmt.Sprintf("note index %d is unusable on this branch - use the next index", index)}
}

// legacyTweak is t reduced mod n, as the spec then required and lnurl-wallet
// did (lnurl-mint refused t >= n instead; at ~2^-128 the two never meet).
func legacyTweak(pubkeyXOnly, chainCode [32]byte, purpose LegacyPurpose, index uint32) (secp256k1.ModNScalar, error) {
	if purpose < LegacyPurposeNone || purpose > 0xffffffff {
		return secp256k1.ModNScalar{}, &ProtocolError{Detail: "not a legacy purpose"}
	}
	parts := [][]byte{noteDeriveTag[:], noteDeriveTag[:], pubkeyXOnly[:], chainCode[:]}
	if purpose != LegacyPurposeNone {
		parts = append(parts, binary.BigEndian.AppendUint32(nil, uint32(purpose)))
	}
	parts = append(parts, binary.BigEndian.AppendUint32(nil, index))
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	var digest [32]byte
	h.Sum(digest[:0])
	// SetBytes reduces mod n; its overflow flag only reports that it did
	var t secp256k1.ModNScalar
	t.SetBytes(&digest)
	return t, nil
}

// LegacyDeriveNotePubkey returns a note key under the superseded tweak, x-only,
// from the legacy cx1 half alone. purpose is LegacyPurposeNone for the scheme
// before purposes existed.
func LegacyDeriveNotePubkey(cx1 LegacyCx1, purpose LegacyPurpose, index uint32) ([32]byte, error) {
	var out [32]byte
	t, err := legacyTweak(cx1.PubkeyXOnly, cx1.ChainCode, purpose, index)
	if err != nil {
		return out, err
	}
	// lift_x: the even-y point with this x, the only one a cx1 can name
	branch, err := secp256k1.ParsePubKey(append([]byte{secp256k1.PubKeyFormatCompressedEven}, cx1.PubkeyXOnly[:]...))
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

// LegacyDeriveNoteSecretKey is the secret key behind LegacyDeriveNotePubkey,
// from a LegacyBranchNode.
//
// The branch key's own point may have odd y, and a legacy cx1 carried only x,
// which names the even-y point. So an odd branch key is negated first, or its
// note keys would not be the ones a watcher derives.
func LegacyDeriveNoteSecretKey(node CashNode, purpose LegacyPurpose, index uint32) ([32]byte, error) {
	var p secp256k1.ModNScalar
	if p.SetBytes(&node.PrivateKey) != 0 || p.IsZero() {
		return [32]byte{}, &ProtocolError{Detail: "a branch private key is a 32-byte scalar in [1, n)"}
	}
	compressed := secp256k1.NewPrivateKey(&p).PubKey().SerializeCompressed()
	var branchX [32]byte
	copy(branchX[:], compressed[1:])
	t, err := legacyTweak(branchX, node.ChainCode, purpose, index)
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

// ---- key-path spends ----
//
//	sig = BIP340.Sign(sk, KeyPathSighash(Q, domain), aux_rand = 0^32)
//	ck1 = bech32m("ck", Q || sig)
//
// The sighash depends on nothing but the note and the mint, and the auxiliary
// input is fixed, so a key has exactly one ck1 per mint: re-deriving the key
// reproduces it byte for byte, which is what lets seed recovery find a note
// already held. A ck1 for one mint fails at every other.
//
// Two older ck1s are still read, never made, so notes already handed out stay
// spendable long enough to rotate: the same Q || sig shape signed over the
// fixed message sha256("LNURLcash") (and, before 2026-09-16, the raw 9-byte
// string), and the pre-Schnorr 65-byte recoverable ECDSA signature.

var noteOwnershipMessage = []byte("LNURLcash")

var noteOwnershipDigest = sha256.Sum256(noteOwnershipMessage)

// legacyNoteOwnershipDigest is what a pre-Schnorr 65-byte ck1 was signed over.
var legacyNoteOwnershipDigest = func() [32]byte {
	inner := sha256.Sum256([]byte(lightningSignedMessagePrefix + "LNURLcash"))
	return sha256.Sum256(inner[:])
}()

// decred lays a compact signature out as header || r || s, the header being 27,
// plus 4 for a compressed key, plus the recovery id. The wire puts the bare
// recovery id last instead, so every signature crossing that boundary is
// rebuilt.
const compactHeaderCompressed = 27 + 4

// SignNoteOwnership signs a key-path note's spend at one mint and returns the
// 96-byte Q || sig payload. Encode it with EncodeCk1 to spend the note - which
// makes the result bearer material, exactly as the secret key is. domain is
// the mint's, in any form SpendDomainOf reads.
func SignNoteOwnership(secretKey [32]byte, domain string) ([96]byte, error) {
	var out [96]byte
	var key btcec.ModNScalar
	if key.SetBytes(&secretKey) != 0 || key.IsZero() {
		return out, &ProtocolError{Detail: "a note secret key is a 32-byte scalar in [1, n)"}
	}
	private := btcec.PrivKeyFromScalar(&key)
	var q [32]byte
	copy(q[:], schnorr.SerializePubKey(private.PubKey()))
	sighash, err := KeyPathSighash(q, domain)
	if err != nil {
		return out, err
	}
	signature, err := schnorr.Sign(private, sighash[:], schnorr.CustomNonce([32]byte{}))
	if err != nil {
		return out, &ProtocolError{Detail: "could not sign the key-path spend"}
	}
	copy(out[:32], q[:])
	copy(out[32:], signature.Serialize())
	return out, nil
}

// NoteOwnership is the note a verified ck1 opens.
type NoteOwnership struct {
	PubkeyXOnly [32]byte
	// Legacy is a ck1 signed over a fixed message rather than the spend
	// sighash, or the pre-Schnorr recoverable shape. Rotate it.
	Legacy bool
}

// RecoverNoteOwnershipPubkey verifies a ck1's payload and returns the note it
// opens. A 96-byte Q || sig is verified against the key-path sighash for
// domain first; failing that, against the fixed messages older ck1s signed,
// which reports Legacy. A 65-byte recoverable signature is recovered, and is
// always Legacy. An error for a proof that does not verify, or any other
// length.
func RecoverNoteOwnershipPubkey(payload []byte, domain string) (NoteOwnership, error) {
	switch len(payload) {
	case 96:
		invalid := &ProtocolError{Detail: "that key-path spend does not verify"}
		pubkey, err := schnorr.ParsePubKey(payload[:32])
		if err != nil {
			return NoteOwnership{}, invalid
		}
		signature, err := schnorr.ParseSignature(payload[32:])
		if err != nil {
			return NoteOwnership{}, invalid
		}
		var owner NoteOwnership
		copy(owner.PubkeyXOnly[:], payload[:32])
		// A missing or unreadable domain only rules out the current form: the
		// fixed-message ones never had one.
		if sighash, err := KeyPathSighash(owner.PubkeyXOnly, domain); err == nil && signature.Verify(sighash[:], pubkey) {
			return owner, nil
		}
		if signature.Verify(noteOwnershipDigest[:], pubkey) || verifyBIP340(payload[:32], payload[32:], noteOwnershipMessage) {
			owner.Legacy = true
			return owner, nil
		}
		return NoteOwnership{}, invalid
	case 65:
		key, err := recoverLegacyCk1(payload)
		if err != nil {
			return NoteOwnership{}, err
		}
		return NoteOwnership{PubkeyXOnly: key, Legacy: true}, nil
	default:
		return NoteOwnership{}, &ProtocolError{Detail: "a ck1 payload is 96 bytes, or a legacy 65"}
	}
}

// recoverLegacyCk1 recovers the key behind a pre-Schnorr 65-byte ck1, an
// r || s || recovery id signature over a fixed message. Recovering a key is
// that shape's whole check: it names its note by the key it recovers to.
func recoverLegacyCk1(payload []byte) ([32]byte, error) {
	var out [32]byte
	if len(payload) != 65 || payload[64] > 3 {
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

// ---- a note's k1, any kind ----

// NoteIDOf returns the id a service files the note k1 opens under: hex(Q). A
// bearer preimage names the bearer note it opens, a cw1 the Q its control block
// commits to, a ck1 the Q it carries. An error for anything that is no spend.
//
// This names the note; it does not check that k1 opens it, which for a ck1
// needs the mint's domain. That is VerifySpend.
func NoteIDOf(k1 string) (string, error) {
	spend, err := DecodeSpend(strings.ToLower(strings.TrimSpace(k1)))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(spend.OutputKey[:]), nil
}

// NoteLookupOf returns what to look a note up by without disclosing it: a
// bearer preimage's hex h, which every mint that ever took a hash lookup
// understands, and the cp1 of anything else. Both are LUD-25's cp1 slot, and
// both bring the note's certificate back. Pass it to BuildNoteInfoURLByHash or
// Client.FetchNoteInfoByHash.
func NoteLookupOf(k1 string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(k1))
	if IsPreimage(value) {
		return HashK1(value)
	}
	spend, err := DecodeSpend(value)
	if err != nil {
		return "", err
	}
	return EncodeCp1(spend.OutputKey), nil
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
// then LUD-26's tree from that seed, unchanged. heartwood-esp32 derives
// exactly this on the device and lnurlcash-kit exports it, and all three are
// graded against conformance's nostr-seed.json. The identity key
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

// DeriveNostrServiceRoot returns one mint's LUD-26 root S for a Nostr
// identity. Bearer material, like any SERVICE root: hand out a share's cx1.
func DeriveNostrServiceRoot(secretKey [32]byte, domain string) (CashNode, error) {
	seed := DeriveNostrCashSeed(secretKey)
	root, err := DeriveCashRoot(seed[:])
	if err != nil {
		return CashNode{}, err
	}
	return DeriveServiceRoot(root, domain)
}
