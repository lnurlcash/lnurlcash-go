package lnurlcash

// LUD-25 seed-recoverable note secrets: the specified scheme.
//
// LUD-25's "Seed-recoverable note secrets" section, in full:
//
//	cashHashingKey   = derive(masterKey, m/139'/0)
//	domainMaterial   = hmacSha256(cashHashingKey, full SERVICE domain)
//	(d1, d2, d3, d4) = first 16 bytes of domainMaterial as 4 uint32
//	secret_i         = derive(masterKey, m/139'/d1/d2/d3/d4/i')
//
// "exactly as LUD-05", says the draft of the middle two lines, and that
// reference settles the one thing the path shape leaves open. d1..d4 are raw
// uint32 drawn from a hash, and BIP-32 already reads any index >= 2^31 as
// hardened, so roughly half of any given mint's four levels are hardened by
// magnitude alone. They are used exactly as they fall: nothing is masked, and
// nothing is forced hardened. That is what LUD-05's own corpus does with the
// same four longs, and what the reference wallet does. Only i is deliberately
// hardened, by the spec's own i'.
//
// An implementation that masks the top bit, or hardens all four, derives a
// different tree from every conforming wallet - and a restore against it finds
// nothing, silently, and only once the money is gone.
//
// This is NOT the scheme in secrets.go's DeriveNoteRoot. That one (HMAC-SHA256
// under "lnurlcash-note-v1") predates this section and is now the legacy
// scheme: still derived, still scanned on restore, so nothing already minted
// goes missing, but not what a new wallet should mint under.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	hardened    = uint32(0x80000000)
	cashPurpose = uint32(139)
)

// CashNode is a BIP-32 extended private key, reduced to the two things
// deriving a child actually needs.
//
// Bearer material for every note derived beneath it. A domain node is the unit
// a hardware signer is provisioned with (see CashNodeToHex), so this is plain
// bytes rather than an xprv.
type CashNode struct {
	PrivateKey [32]byte
	ChainCode  [32]byte
}

func hmac512(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// DeriveCashChild performs one BIP-32 CKDpriv step. Hardened when index is at
// or above 2^31, by the index's own magnitude and nothing else, which is the
// whole of the convention question above: the caller passes the raw uint32 and
// this decides.
//
// Exported so a consumer can check this package against BIP-32's own published
// test vectors rather than taking the derivation on trust, and so a host
// provisioning a hardware signer can walk the intermediate levels.
func DeriveCashChild(node CashNode, index uint32) (CashNode, error) {
	var out CashNode

	var kpar secp256k1.ModNScalar
	if kpar.SetBytes(&node.PrivateKey) != 0 || kpar.IsZero() {
		return out, &ProtocolError{Detail: "cash node holds an invalid private key"}
	}

	data := make([]byte, 37)
	if index >= hardened {
		// 0x00 || ser256(kpar): the leading zero pads the 32-byte scalar out
		// to the 33 bytes a serialised point occupies, so the two legs hash
		// over the same length and can never collide.
		copy(data[1:33], node.PrivateKey[:])
	} else {
		priv := secp256k1.NewPrivateKey(&kpar)
		copy(data[:33], priv.PubKey().SerializeCompressed())
	}
	binary.BigEndian.PutUint32(data[33:], index)

	material := hmac512(node.ChainCode[:], data)
	var il [32]byte
	copy(il[:], material[:32])

	// "In case parse256(IL) >= n or ki = 0, proceed with the next value for
	// i." Both are ~2^-127 events and no wallet will ever see one, but a
	// silently wrong answer here is a note nobody can spend, so both are
	// checked rather than assumed away.
	var tweak secp256k1.ModNScalar
	if tweak.SetBytes(&il) != 0 {
		return out, &ProtocolError{Detail: fmt.Sprintf("BIP-32 derivation at %d is out of range", index)}
	}
	tweak.Add(&kpar)
	if tweak.IsZero() {
		return out, &ProtocolError{Detail: fmt.Sprintf("BIP-32 derivation at %d is out of range", index)}
	}

	out.PrivateKey = tweak.Bytes()
	copy(out.ChainCode[:], material[32:])
	return out, nil
}

// DeriveCashMaster returns a seed's BIP-32 master node. Exported beside
// DeriveCashChild for the same reason: a consumer walking a path this package
// does not name (nsec-tree's m/44'/1237'/727'/0'/0', say) starts here.
func DeriveCashMaster(seed []byte) (CashNode, error) {
	return masterFrom(seed)
}

func masterFrom(seed []byte) (CashNode, error) {
	var out CashNode
	if len(seed) < 16 || len(seed) > 64 {
		return out, &ProtocolError{Detail: fmt.Sprintf("a BIP-32 seed must be 16 to 64 bytes, not %d", len(seed))}
	}
	material := hmac512([]byte("Bitcoin seed"), seed)
	copy(out.PrivateKey[:], material[:32])
	var key secp256k1.ModNScalar
	if key.SetBytes(&out.PrivateKey) != 0 || key.IsZero() {
		return CashNode{}, &ProtocolError{Detail: "this seed does not produce a valid BIP-32 master key"}
	}
	copy(out.ChainCode[:], material[32:])
	return out, nil
}

// DeriveCashRoot returns m/139' - the wallet's own root for note secrets,
// under its own purpose so it never shares key material with LUD-05's m/138'
// linking-key branch.
//
// seed is raw bytes. A 64-byte BIP39 seed is the interop case, and what the
// reference wallet feeds in, but nothing here depends on BIP39 - which is also
// what keeps a mnemonic wordlist out of every consumer's binary.
func DeriveCashRoot(seed []byte) (CashNode, error) {
	master, err := masterFrom(seed)
	if err != nil {
		return CashNode{}, err
	}
	return DeriveCashChild(master, cashPurpose+hardened)
}

// CashDomainIndices returns the four raw uint32 levels a mint's subtree hangs
// off. Exported because they are the whole of what a conformance vector has to
// pin, and because a wallet debugging a restore that finds nothing wants them.
func CashDomainIndices(root CashNode, host string) ([4]uint32, error) {
	var out [4]uint32
	hashing, err := DeriveCashChild(root, 0)
	if err != nil {
		return out, err
	}
	mac := hmac.New(sha256.New, hashing.PrivateKey[:])
	mac.Write([]byte(host))
	material := mac.Sum(nil)
	for i := range out {
		out[i] = binary.BigEndian.Uint32(material[i*4 : i*4+4])
	}
	return out, nil
}

// DeriveCashDomainNode returns m/139'/d1/d2/d3/d4 for one mint: everything
// above a note's own index.
//
// Worth having as its own step, and not only to derive it once for a run of
// secrets. Every unhardened level in the path is at or above this node, so a
// signer given THIS rather than the seed needs no elliptic curve at all - each
// i' beneath it is HMAC-SHA512 plus one modular addition. That is the
// difference between a hardware wallet that can do LUD-25 recovery and one
// that would need secp256k1 added to its firmware for it.
//
// The cost is that whoever derives it can derive every note secret the wallet
// will ever hold AT THIS MINT, so it is provisioning material rather than
// something to hand out: one mint's subtree, not the wallet.
//
// host is the mint host exactly as the wallet stores it - lowercase, port
// included where there is one - which is what the reference wallet passes, so
// the two derive the same tree.
func DeriveCashDomainNode(root CashNode, host string) (CashNode, error) {
	indices, err := CashDomainIndices(root, host)
	if err != nil {
		return CashNode{}, err
	}
	node := root
	for _, index := range indices {
		if node, err = DeriveCashChild(node, index); err != nil {
			return CashNode{}, err
		}
	}
	return node, nil
}

func requireIndex(index uint32) error {
	if index >= hardened {
		return &ProtocolError{Detail: fmt.Sprintf("a note index must be below 2^31, not %d", index)}
	}
	return nil
}

// CashSecretAt returns the i-th note secret beneath a mint's domain node, as
// 32 bytes of hex - the size of a payment preimage, so HashK1 and every wire
// path treat it exactly as they treat a randomly drawn one. The service sees
// no difference: it only ever receives sha256(k1).
func CashSecretAt(domainNode CashNode, index uint32) (string, error) {
	if err := requireIndex(index); err != nil {
		return "", err
	}
	leaf, err := DeriveCashChild(domainNode, index+hardened)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(leaf.PrivateKey[:]), nil
}

// DeriveCashSecret is the convenience form, from the root. It re-derives the
// domain node on every call, which is up to four point multiplications - fine
// for one secret, wasteful for a run of them. Use CashSecretSource for those.
func DeriveCashSecret(root CashNode, host string, index uint32) (string, error) {
	node, err := DeriveCashDomainNode(root, host)
	if err != nil {
		return "", err
	}
	return CashSecretAt(node, index)
}

// CashNodeToHex renders a node as privateKey || chainCode, 64 bytes of hex.
// Not a BIP-32 extended key: no version bytes, no depth, no parent
// fingerprint, no base58check. This is the same 64 bytes the reference wallet
// persists for its own root and the shape a hardware signer is provisioned
// with, and nothing here is ever meant to leave a wallet as a portable xprv.
func CashNodeToHex(node CashNode) string {
	return hex.EncodeToString(node.PrivateKey[:]) + hex.EncodeToString(node.ChainCode[:])
}

// CashNodeFromHex reads one back.
func CashNodeFromHex(value string) (CashNode, error) {
	var out CashNode
	raw, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(value)))
	if err != nil {
		return out, &ProtocolError{Detail: "a cash node is 64 bytes of hex"}
	}
	if len(raw) != 64 {
		return out, &ProtocolError{Detail: fmt.Sprintf("a cash node is 64 bytes - a 32-byte key and a 32-byte chain code - not %d", len(raw))}
	}
	copy(out.PrivateKey[:], raw[:32])
	copy(out.ChainCode[:], raw[32:])
	var key secp256k1.ModNScalar
	if key.SetBytes(&out.PrivateKey) != 0 || key.IsZero() {
		return CashNode{}, &ProtocolError{Detail: "that cash node holds an invalid private key"}
	}
	return out, nil
}

// CashSecretSource walks a mint's indices in order, so a caller can hand it to
// any mutating call and let rotate, split and merge draw derived secrets
// without knowing anything about derivation. NextIndex reads back the next
// unused index afterwards - a split consumes two, a rotate one - which is the
// number the wallet persists as its counter for that host. The domain node is
// derived once, in NewCashSecretSource, rather than per secret.
//
// Persist that counter in the SAME write that stages the new records, and do
// it BEFORE the hash goes on the wire. A crash between the bump and the
// request wastes an index, which costs nothing; a crash the other way round
// re-derives a secret the mint has already seen, and the second note minted at
// it collides with the first.
//
// The counter is not secret - an index reveals nothing without the root - so
// it belongs in an ordinary backup, and a restore should merge counters
// upwards only. It is also not optional: a gap scan cannot see a burned index
// (LUD-25 requires a hash lookup to answer for a spent note exactly as it
// answers for one that never existed), so a wallet that has rotated more times
// than its gap limit cannot rediscover its own position from the mint alone.
type CashSecretSource struct {
	domainNode CashNode
	next       uint32
}

// NewCashSecretSource derives the mint's domain node once and starts at start.
func NewCashSecretSource(root CashNode, host string, start uint32) (*CashSecretSource, error) {
	if err := requireIndex(start); err != nil {
		return nil, err
	}
	node, err := DeriveCashDomainNode(root, host)
	if err != nil {
		return nil, err
	}
	return &CashSecretSource{domainNode: node, next: start}, nil
}

// Next returns the next secret and advances the counter. It satisfies
// SecretSource.
func (s *CashSecretSource) Next() (string, error) {
	secret, err := CashSecretAt(s.domainNode, s.next)
	if err != nil {
		return "", err
	}
	s.next++
	return secret, nil
}

// NextIndex is the next unused index - what the wallet persists.
func (s *CashSecretSource) NextIndex() uint32 {
	return s.next
}
