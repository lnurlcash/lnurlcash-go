package lnurlcash

// LUD-25 spends: what a note is, what opens it, and what a signature signs.
//
// Every note is a BIP-341 taproot output key Q, named cp1<Q>, and a mint files
// it under hex(Q). What goes in k1 is a spend of one:
//
//	ck1<Q || sig>   key path: a BIP-340 signature by Q itself
//	cw1<...>        script path: a leaf of Q's tree, its control block and the
//	                witness the leaf consumes
//	64 hex          a bearer note's preimage, the short form of its cw1
//
// Every signature signs the BIP-341 sighash of input 0 of one fixed,
// never-broadcast transaction whose prevout is bound to the mint's domain, so
// a signature one mint has seen cannot be replayed at another:
//
//	nVersion 2, nLockTime as claimed
//	vin[0]   prevout (tagged_hash("LNURLcash/mint", domain), 0), nSequence as claimed
//	vout[0]  value 0, empty scriptPubKey
//	spent    (OP_1 <Q>, 0)
//
// The shape of that transaction never changes, so the sighash is built here by
// hand rather than through a Bitcoin library. There is no script interpreter
// either: a bearer note's hashlock is the one leaf this package evaluates, and
// any other leaf is only checked as far as its structure, its Q and the leaf
// rules go. Nothing here is secret apart from the signing key, so none of the
// point arithmetic needs to be constant-time.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	// TapleafVersion is tapscript's leaf version, the only one LUD-25 accepts.
	TapleafVersion byte = 0xc0
	// KeyPathLocktime and KeyPathSequence are the time claim every key-path
	// spend makes: none. A key therefore has one signature per mint.
	KeyPathLocktime uint32 = 0
	KeyPathSequence uint32 = 0xffffffff
)

// NumsKey is BIP-341's nothing-up-my-sleeve point H. Nobody knows its discrete
// log, so a note built on it has no key path: only its leaf can spend it.
var NumsKey = [32]byte{
	0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
	0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
}

const (
	maxMerkleDepth = 128
	// BIP-342 keeps the 520-byte cap on every initial stack element.
	maxStackElement = 520
	// No URL gets near this; it only stops a hostile string costing work.
	maxCw1Chars = 8192
	// a cw1 names each item's length in two bytes
	maxCw1Item = 0xffff
)

func taggedHash(tag string, parts ...[]byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	for _, part := range parts {
		h.Write(part)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func compactSize(n int) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n), byte(n >> 8)}
	default:
		return binary.LittleEndian.AppendUint32([]byte{0xfe}, uint32(n))
	}
}

// liftX is BIP-340's lift_x: the even-y point with this x, or an error when x
// is not the x coordinate of any point on the curve.
func liftX(x [32]byte) (*secp256k1.PublicKey, error) {
	point, err := secp256k1.ParsePubKey(append([]byte{secp256k1.PubKeyFormatCompressedEven}, x[:]...))
	if err != nil {
		return nil, &ProtocolError{Detail: "that key is not the x coordinate of a point on the curve"}
	}
	return point, nil
}

// IsXOnlyPoint reports whether x is the x coordinate of a curve point. LUD-25
// has a mint refuse a cp1 that is not: no spend could ever open it.
func IsXOnlyPoint(x [32]byte) bool {
	_, err := liftX(x)
	return err == nil
}

// TapLeafHash is BIP-341's tagged_hash("TapLeaf", version || compact_size(len) || script).
func TapLeafHash(script []byte, version byte) [32]byte {
	return taggedHash("TapLeaf", []byte{version}, compactSize(len(script)), script)
}

// TaprootTweak returns Q = lift_x(P) + tagged_hash("TapTweak", P || merkleRoot)·G,
// x-only, and whether Q has odd y. merkleRoot is 32 bytes, or empty to commit
// to no script tree at all.
func TaprootTweak(internalKey [32]byte, merkleRoot []byte) (outputKey [32]byte, oddY bool, err error) {
	if len(merkleRoot) != 0 && len(merkleRoot) != 32 {
		return outputKey, false, &ProtocolError{Detail: "a merkle root is 32 bytes, or empty"}
	}
	internal, err := liftX(internalKey)
	if err != nil {
		return outputKey, false, err
	}
	tweak := taggedHash("TapTweak", internalKey[:], merkleRoot)
	var t secp256k1.ModNScalar
	// BIP-341 fails a tweak at or above n rather than reducing it
	if t.SetBytes(&tweak) != 0 {
		return outputKey, false, &ProtocolError{Detail: "that taproot tweak is out of range"}
	}
	var point, tweakPoint, q secp256k1.JacobianPoint
	internal.AsJacobian(&point)
	secp256k1.ScalarBaseMultNonConst(&t, &tweakPoint)
	secp256k1.AddNonConst(&point, &tweakPoint, &q)
	if (q.X.IsZero() && q.Y.IsZero()) || q.Z.IsZero() {
		return outputKey, false, &ProtocolError{Detail: "that taproot tweak lands on the point at infinity"}
	}
	q.ToAffine()
	q.X.PutBytes(&outputKey)
	return outputKey, q.Y.IsOdd(), nil
}

// OutputKeyOf returns the Q a leaf and its control block commit to: the leaf
// hash folded up the merkle path with TapBranch, then the control block's
// internal key tweaked by the root. The control block's parity bit is checked
// too, so a Q returned here is exactly the one the spend is valid against.
func OutputKeyOf(script, controlBlock []byte) ([32]byte, error) {
	var out [32]byte
	if len(controlBlock) < 33 || (len(controlBlock)-33)%32 != 0 {
		return out, &ProtocolError{Detail: "a control block is 33 + 32m bytes"}
	}
	if (len(controlBlock)-33)/32 > maxMerkleDepth {
		return out, &ProtocolError{Detail: "that control block's merkle path is deeper than 128"}
	}
	node := TapLeafHash(script, controlBlock[0]&0xfe)
	for i := 33; i < len(controlBlock); i += 32 {
		sibling := controlBlock[i : i+32]
		if bytes.Compare(node[:], sibling) < 0 {
			node = taggedHash("TapBranch", node[:], sibling)
		} else {
			node = taggedHash("TapBranch", sibling, node[:])
		}
	}
	var internal [32]byte
	copy(internal[:], controlBlock[1:33])
	q, oddY, err := TaprootTweak(internal, node[:])
	if err != nil {
		return out, err
	}
	if oddY != (controlBlock[0]&1 == 1) {
		return out, &ProtocolError{Detail: "the control block names the other parity of Q, so it commits to no key"}
	}
	return q, nil
}

// ---- the bearer note ----
//
// NUMS internal key and one OP_SHA256 <h> OP_EQUAL leaf: spent by revealing
// the preimage, with no signature, and so bound to no mint. Everything but the
// preimage follows from h, which is why its short forms work.

// BearerLeaf is a bearer note's one leaf script, OP_SHA256 <h> OP_EQUAL.
func BearerLeaf(h [32]byte) []byte {
	return append(append([]byte{0xa8, 0x20}, h[:]...), 0x87)
}

// BearerNote is everything about a bearer note that follows from its h.
type BearerNote struct {
	OutputKey    [32]byte
	ControlBlock [33]byte
	Leaf         []byte
}

// BearerNoteOf builds the bearer note whose hashlock is h.
func BearerNoteOf(h [32]byte) BearerNote {
	leaf := BearerLeaf(h)
	leafHash := TapLeafHash(leaf, TapleafVersion)
	// NumsKey is a point, and a hash at or above n is a 2^-128 event
	q, oddY, err := TaprootTweak(NumsKey, leafHash[:])
	if err != nil {
		panic("lnurlcash: the bearer note tweak failed: " + err.Error())
	}
	note := BearerNote{OutputKey: q, Leaf: leaf}
	note.ControlBlock[0] = TapleafVersion
	if oddY {
		note.ControlBlock[0] |= 1
	}
	copy(note.ControlBlock[1:], NumsKey[:])
	return note
}

func parseHex32(value string) ([32]byte, bool) {
	var out [32]byte
	trimmed := strings.TrimSpace(value)
	if !IsPreimage(trimmed) {
		return out, false
	}
	raw, _ := hex.DecodeString(trimmed)
	copy(out[:], raw)
	return out, true
}

// BearerNoteID returns hex(Q) for the bearer note named by its hex h: the id a
// mint files, burns and certifies it under.
func BearerNoteID(h string) (string, error) {
	hash, ok := parseHex32(h)
	if !ok {
		return "", &ProtocolError{Detail: "a bearer note's h is 32 bytes of hex"}
	}
	q := BearerNoteOf(hash).OutputKey
	return hex.EncodeToString(q[:]), nil
}

// BearerCw1 returns the full cw1 a bearer note's preimage is the short form
// of: its leaf and control block, witness [preimage], locktime 0 and sequence
// 0xffffffff. The same spend, three times the length.
func BearerCw1(preimage string) (string, error) {
	secret, ok := parseHex32(preimage)
	if !ok {
		return "", &ProtocolError{Detail: "a bearer note's preimage is 32 bytes of hex"}
	}
	note := BearerNoteOf(sha256.Sum256(secret[:]))
	return EncodeCw1(Cw1{
		Locktime:     KeyPathLocktime,
		Sequence:     KeyPathSequence,
		Script:       note.Leaf,
		ControlBlock: note.ControlBlock[:],
		Witness:      [][]byte{secret[:]},
	})
}

// bearerHashOfLeaf returns the h inside a leaf that is exactly a bearer note's.
func bearerHashOfLeaf(script []byte) ([32]byte, bool) {
	var h [32]byte
	if len(script) != 35 || script[0] != 0xa8 || script[1] != 0x20 || script[34] != 0x87 {
		return h, false
	}
	copy(h[:], script[2:34])
	return h, true
}

// ---- what a signature signs ----

// SpendDomainOf returns the domain a spend at value is bound to: the mint's
// full hostname, lowercased, never its scheme or port. value may be a note URL
// in any spelling (https, lnurlw://, a bech32 LNURL), a withdraw link, or a
// bare host.
func SpendDomainOf(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if IsBech32Lnurl(trimmed) {
		trimmed = FromBech32Lnurl(trimmed)
	}
	expanded := FromLud17(trimmed)
	if !strings.Contains(expanded, "://") {
		expanded = "https://" + expanded
	}
	parsed, err := url.Parse(expanded)
	if err != nil || parsed.Hostname() == "" {
		return "", &ProtocolError{Detail: "a spend is bound to a mint's domain, and that names no host"}
	}
	return strings.ToLower(parsed.Hostname()), nil
}

// SpendPrevout returns the canonical spend transaction's prevout txid for a
// mint, tagged_hash("LNURLcash/mint", domain). This is what binds a signature
// to one mint.
func SpendPrevout(domain string) ([32]byte, error) {
	host, err := SpendDomainOf(domain)
	if err != nil {
		return [32]byte{}, err
	}
	return taggedHash("LNURLcash/mint", []byte(host)), nil
}

// SpendSigMsg returns BIP-341's SigMsg for input 0 of the canonical spend
// transaction under SIGHASH_DEFAULT: nil leafScript for a key path, or the
// leaf for a script path, which appends BIP-342's extension.
func SpendSigMsg(outputKey [32]byte, domain string, locktime, sequence uint32, leafScript []byte) ([]byte, error) {
	prevout, err := SpendPrevout(domain)
	if err != nil {
		return nil, err
	}
	var zero8 [8]byte
	shaPrevouts := sha256.Sum256(binary.LittleEndian.AppendUint32(prevout[:], 0))
	shaAmounts := sha256.Sum256(zero8[:])
	scriptPubKey := append([]byte{0x22, 0x51, 0x20}, outputKey[:]...)
	shaScriptPubKeys := sha256.Sum256(scriptPubKey)
	shaSequences := sha256.Sum256(binary.LittleEndian.AppendUint32(nil, sequence))
	shaOutputs := sha256.Sum256(append(zero8[:], 0x00))

	msg := make([]byte, 0, 211)
	msg = append(msg, 0x00) // hash_type: SIGHASH_DEFAULT
	msg = binary.LittleEndian.AppendUint32(msg, 2)
	msg = binary.LittleEndian.AppendUint32(msg, locktime)
	msg = append(msg, shaPrevouts[:]...)
	msg = append(msg, shaAmounts[:]...)
	msg = append(msg, shaScriptPubKeys[:]...)
	msg = append(msg, shaSequences[:]...)
	msg = append(msg, shaOutputs[:]...)
	if leafScript == nil {
		msg = append(msg, 0x00) // spend_type: key path, no annex
	} else {
		msg = append(msg, 0x02) // spend_type: script path, no annex
	}
	msg = binary.LittleEndian.AppendUint32(msg, 0) // input_index
	if leafScript != nil {
		leafHash := TapLeafHash(leafScript, TapleafVersion)
		msg = append(msg, leafHash[:]...)
		msg = append(msg, 0x00)                   // key_version
		msg = append(msg, 0xff, 0xff, 0xff, 0xff) // no OP_CODESEPARATOR
	}
	return msg, nil
}

func tapSighash(sigMsg []byte) [32]byte {
	return taggedHash("TapSighash", []byte{0x00}, sigMsg)
}

// KeyPathSighash is what a ck1's signature signs: the key-path sighash for
// this note at this mint, with no time claim.
func KeyPathSighash(outputKey [32]byte, domain string) ([32]byte, error) {
	msg, err := SpendSigMsg(outputKey, domain, KeyPathLocktime, KeyPathSequence, nil)
	if err != nil {
		return [32]byte{}, err
	}
	return tapSighash(msg), nil
}

// ScriptPathSighash is what a SIGHASH_DEFAULT signature inside a cw1's leaf
// signs, for the time the spend claims.
func ScriptPathSighash(outputKey [32]byte, domain string, leafScript []byte, locktime, sequence uint32) ([32]byte, error) {
	if leafScript == nil {
		leafScript = []byte{}
	}
	msg, err := SpendSigMsg(outputKey, domain, locktime, sequence, leafScript)
	if err != nil {
		return [32]byte{}, err
	}
	return tapSighash(msg), nil
}

// ---- cw1 ----

// Cw1 is a script-path spend: the claimed time, the leaf, its control block,
// and the witness items the leaf consumes, bottom of the stack first.
type Cw1 struct {
	Locktime     uint32
	Sequence     uint32
	Script       []byte
	ControlBlock []byte
	Witness      [][]byte
}

// EncodeCw1 encodes a script-path spend. Whoever holds the result can spend
// the note, as far as the leaf allows.
func EncodeCw1(spend Cw1) (string, error) {
	payload := binary.BigEndian.AppendUint32(nil, spend.Locktime)
	payload = binary.BigEndian.AppendUint32(payload, spend.Sequence)
	for _, item := range append([][]byte{spend.Script, spend.ControlBlock}, spend.Witness...) {
		if len(item) > maxCw1Item {
			return "", &ProtocolError{Detail: "a cw1 item is at most 65535 bytes"}
		}
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(item)))
		payload = append(payload, item...)
	}
	return encodeFixed("cw", payload), nil
}

// DecodeCw1 reads a cw1 back into its parts. Structure only: the length
// prefixes must consume the payload exactly, and a script and a control block
// must be there. Whether the control block commits to a key is OutputKeyOf's
// question.
func DecodeCw1(value string) (Cw1, error) {
	invalid := func(why string) error {
		return &ProtocolError{Detail: "not a cw1: " + why}
	}
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > maxCw1Chars {
		return Cw1{}, invalid("it is longer than any note URL could carry")
	}
	prefix, words, version, err := bech32.DecodeNoLimitWithVersion(trimmed)
	switch {
	case err != nil:
		return Cw1{}, invalid("not a well-formed bech32m string")
	case version != bech32.VersionM:
		return Cw1{}, invalid("the checksum is bech32, not bech32m")
	case prefix != "cw":
		return Cw1{}, invalid("the prefix is not cw1")
	}
	payload, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil {
		return Cw1{}, invalid("the padding is not zero")
	}
	if len(payload) < 8 {
		return Cw1{}, invalid("shorter than its locktime and sequence")
	}
	out := Cw1{
		Locktime: binary.BigEndian.Uint32(payload[0:4]),
		Sequence: binary.BigEndian.Uint32(payload[4:8]),
	}
	var items [][]byte
	for i := 8; i < len(payload); {
		if i+2 > len(payload) {
			return Cw1{}, invalid("a length prefix is cut short")
		}
		n := int(binary.BigEndian.Uint16(payload[i : i+2]))
		i += 2
		if i+n > len(payload) {
			return Cw1{}, invalid("a length prefix claims more bytes than remain")
		}
		items = append(items, append([]byte(nil), payload[i:i+n]...))
		i += n
	}
	if len(items) < 2 {
		return Cw1{}, invalid("a script and a control block are both required")
	}
	out.Script, out.ControlBlock, out.Witness = items[0], items[1], items[2:]
	return out, nil
}

// IsCw1 reports whether value is a well-formed cw1, structurally.
func IsCw1(value string) bool {
	_, err := DecodeCw1(value)
	return err == nil
}

// OutputKeyOfCw1 returns the Q a cw1 opens, recomputed from its leaf and
// control block. Nothing about its witness is checked.
func OutputKeyOfCw1(value string) ([32]byte, error) {
	spend, err := DecodeCw1(value)
	if err != nil {
		return [32]byte{}, err
	}
	return OutputKeyOf(spend.Script, spend.ControlBlock)
}

// ---- the leaf and time rules ----

// isOpSuccess is BIP-342's OP_SUCCESSx: 80, 98, 126-129, 131-134, 137-138,
// 141-142, 149-153 and 187-254.
func isOpSuccess(op byte) bool {
	switch {
	case op == 80, op == 98, op == 137, op == 138, op == 141, op == 142:
		return true
	case op >= 126 && op <= 129, op >= 131 && op <= 134, op >= 149 && op <= 153, op >= 187 && op <= 254:
		return true
	}
	return false
}

// CheckLeafPolicy applies LUD-25's one exception to "anything consensus
// accepts": tapscript's upgrade hooks. A leaf version other than 0xc0, or an
// OP_SUCCESSx opcode anywhere outside pushed data, succeeds unconditionally
// under consensus today and would make the leaf spendable by anyone who saw
// it, so a mint refuses both before anything runs. version is the control
// block's first byte with the parity bit cleared.
func CheckLeafPolicy(version byte, script []byte) error {
	if version != TapleafVersion {
		return &ProtocolError{Detail: fmt.Sprintf("leaf version 0x%02x is not tapscript's 0xc0", version)}
	}
	for i := 0; i < len(script); {
		op := script[i]
		i++
		var n int
		switch {
		case op >= 0x01 && op <= 0x4b:
			n = int(op)
		case op == 0x4c:
			if i+1 > len(script) {
				return &ProtocolError{Detail: "a push runs past the end of the leaf"}
			}
			n = int(script[i])
			i++
		case op == 0x4d:
			if i+2 > len(script) {
				return &ProtocolError{Detail: "a push runs past the end of the leaf"}
			}
			n = int(binary.LittleEndian.Uint16(script[i:]))
			i += 2
		case op == 0x4e:
			if i+4 > len(script) {
				return &ProtocolError{Detail: "a push runs past the end of the leaf"}
			}
			n = int(binary.LittleEndian.Uint32(script[i:]))
			i += 4
		default:
			if isOpSuccess(op) {
				return &ProtocolError{Detail: fmt.Sprintf("the leaf uses OP_SUCCESS%d, a reserved upgrade hook", op)}
			}
			continue
		}
		// consensus fails a script whose push is cut short before it could
		// ever reach an OP_SUCCESS after it
		if n < 0 || i+n > len(script) {
			return &ProtocolError{Detail: "a push runs past the end of the leaf"}
		}
		i += n
	}
	return nil
}

const (
	locktimeThreshold    = 500_000_000
	sequenceDisableFlag  = 1 << 31
	sequenceTypeFlag     = 1 << 22
	sequenceValueMask    = 0xffff
	sequenceGranularityS = 512
)

// CheckTimeClaim judges a script-path spend's claimed nLockTime and nSequence
// against a clock, in Unix seconds: now, and lockedAt, when the mint credited
// the note. It is the mint's clock that decides, so a wallet can only use this
// to predict the answer. A timelock a mint honours is the mint asserting its
// own clock, a custodial policy and never a trustless guarantee.
func CheckTimeClaim(locktime, sequence uint32, now, lockedAt int64) error {
	if locktime != 0 {
		if locktime < locktimeThreshold {
			return &ProtocolError{Detail: "a block-height locktime has no meaning without a chain"}
		}
		if int64(locktime) > now {
			return &ProtocolError{Detail: fmt.Sprintf("locktime %d has not been reached (now %d)", locktime, now)}
		}
	}
	if sequence&sequenceDisableFlag != 0 {
		return nil
	}
	if sequence&sequenceTypeFlag == 0 {
		return &ProtocolError{Detail: "a block-count relative lock has no meaning without a chain"}
	}
	required := int64(sequence&sequenceValueMask) * sequenceGranularityS
	if elapsed := now - lockedAt; elapsed < required {
		return &ProtocolError{Detail: fmt.Sprintf("a relative lock of %ds has not yet run (%ds elapsed)", required, max(elapsed, 0))}
	}
	return nil
}

// ---- spends ----

// SpendKind says how a spend opens its note.
type SpendKind int

const (
	// KeyPathSpend is a ck1: Q and a BIP-340 signature.
	KeyPathSpend SpendKind = iota + 1
	// ScriptPathSpend is a cw1, or a bearer note's hex preimage, its short form.
	ScriptPathSpend
	// RecoveredKeySpend is a pre-Schnorr 65-byte ck1: a recoverable ECDSA
	// signature over a fixed message, whose key is recovered rather than read.
	// Deprecated, and only ever read.
	RecoveredKeySpend
)

// Spend is what a k1 decodes to: the note it names and how it opens it.
type Spend struct {
	Kind      SpendKind
	OutputKey [32]byte
	// Signature is a key-path spend's BIP-340 signature.
	Signature [64]byte
	// ScriptPath is a script-path spend's leaf, control block and witness. A
	// bearer preimage decodes to its full cw1.
	ScriptPath Cw1
}

// DecodeSpend reads what a redeemer put in k1 and names the note it opens.
// Nothing here checks a signature or a witness: for that, VerifySpend.
func DecodeSpend(k1 string) (Spend, error) {
	value := strings.TrimSpace(k1)
	if secret, ok := parseHex32(value); ok {
		note := BearerNoteOf(sha256.Sum256(secret[:]))
		return Spend{
			Kind:      ScriptPathSpend,
			OutputKey: note.OutputKey,
			ScriptPath: Cw1{
				Locktime:     KeyPathLocktime,
				Sequence:     KeyPathSequence,
				Script:       note.Leaf,
				ControlBlock: note.ControlBlock[:],
				Witness:      [][]byte{secret[:]},
			},
		}, nil
	}
	if decoded, err := DecodeCk1(value); err == nil {
		if decoded.IsLegacy {
			key, err := recoverLegacyCk1(decoded.Legacy[:])
			if err != nil {
				return Spend{}, err
			}
			return Spend{Kind: RecoveredKeySpend, OutputKey: key}, nil
		}
		spend := Spend{Kind: KeyPathSpend}
		copy(spend.OutputKey[:], decoded.Current[:32])
		copy(spend.Signature[:], decoded.Current[32:])
		return spend, nil
	}
	if strings.HasPrefix(strings.ToLower(value), "cw1") {
		script, err := DecodeCw1(value)
		if err != nil {
			return Spend{}, err
		}
		q, err := OutputKeyOf(script.Script, script.ControlBlock)
		if err != nil {
			return Spend{}, err
		}
		return Spend{Kind: ScriptPathSpend, OutputKey: q, ScriptPath: script}, nil
	}
	return Spend{}, &ProtocolError{Detail: "a k1 is a ck1, a cw1, or a bearer note's 32-byte hex preimage"}
}

// VerifiedSpend is a spend that opens its note, as far as this package can
// judge without the mint's clock.
type VerifiedSpend struct {
	OutputKey [32]byte
	// Legacy is a ck1 signed under a scheme LUD-25 has replaced: over a fixed
	// message rather than the spend sighash, or the pre-Schnorr recoverable
	// shape. Still read, so notes already handed out stay spendable; rotate it
	// into a current ck1 at the first chance.
	Legacy bool
	// Unevaluated is a script-path spend whose leaf is not a bearer hashlock,
	// the one leaf this package runs. Its structure, its Q and the leaf rules
	// were checked; whether its witness satisfies the leaf is the mint's call.
	Unevaluated bool
}

// VerifySpend checks that k1 opens the note it names, the way a mint would
// (LUD-25 "Output keys and spends"), leaving only its time claims to the
// mint's clock. domain is the mint's, in any form SpendDomainOf reads: a
// key-path signature is bound to it. A bearer note's spend checks no
// signature, so it opens its note at any domain.
func VerifySpend(k1, domain string) (VerifiedSpend, error) {
	spend, err := DecodeSpend(k1)
	if err != nil {
		return VerifiedSpend{}, err
	}
	switch spend.Kind {
	case RecoveredKeySpend:
		return VerifiedSpend{OutputKey: spend.OutputKey, Legacy: true}, nil
	case KeyPathSpend:
		var payload [96]byte
		copy(payload[:32], spend.OutputKey[:])
		copy(payload[32:], spend.Signature[:])
		owner, err := RecoverNoteOwnershipPubkey(payload[:], domain)
		if err != nil {
			return VerifiedSpend{}, err
		}
		return VerifiedSpend{OutputKey: owner.PubkeyXOnly, Legacy: owner.Legacy}, nil
	}
	script := spend.ScriptPath
	if err := CheckLeafPolicy(script.ControlBlock[0]&0xfe, script.Script); err != nil {
		return VerifiedSpend{}, err
	}
	h, isBearer := bearerHashOfLeaf(script.Script)
	if !isBearer {
		return VerifiedSpend{OutputKey: spend.OutputKey, Unevaluated: true}, nil
	}
	// OP_SHA256 <h> OP_EQUAL leaves exactly one element, true only for a lone
	// witness item under the stack-element cap that hashes to h. That is the
	// whole of what Bitcoin Core would decide about this leaf.
	if len(script.Witness) != 1 || len(script.Witness[0]) > maxStackElement || sha256.Sum256(script.Witness[0]) != h {
		return VerifiedSpend{}, &ProtocolError{Detail: "the witness does not satisfy the bearer note's hashlock"}
	}
	return VerifiedSpend{OutputKey: spend.OutputKey}, nil
}
