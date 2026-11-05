package lnurlcash

// LUD-26's m/139' service-root derivation: the BIP-32 walk from a wallet's cash
// root down to a per-service root S, exactly as its "Seed & derivation"
// section specifies it:
//
//	cashHashingKey   = derive(masterKey, m/139'/0)
//	domainMaterial   = hmacSha256(cashHashingKey, full SERVICE domain)
//	(d1, d2, d3, d4) = first 16 bytes of domainMaterial as 4 uint32
//	S                = derive(masterKey, m/139'/d1/d2/d3/d4)
//
// domain is the string LUD-25's canonical spend transaction commits to: the
// mint's lowercase hostname, never its port (see DeriveServiceRoot). Everything
// below S is plain BIP-32 too, laid out in recoverable.go.
//
// "exactly as LUD-05", says the draft of the middle two lines, and that
// reference settles the one thing the path shape leaves open. d1..d4 are raw
// uint32 drawn from a hash, and BIP-32 already reads any index >= 2^31 as
// hardened, so roughly half of any given mint's four levels are hardened by
// magnitude alone. They are used exactly as they fall: nothing is masked, and
// nothing is forced hardened. That is what LUD-05's own corpus does with the
// same four longs, and what the reference wallet does.
//
// An implementation that masks the top bit, or hardens all four, derives a
// different tree from every conforming wallet - and a restore against it finds
// nothing, silently, and only once the money is gone.
//
// Bearer preimages are NOT derived from this node, or from the seed at all -
// LUD-25 has the wallet generate plain randomness. An earlier
// reference-wallet extension did derive them deterministically from
// this node, hardened at the note's own index; it has since been dropped as
// unspecified, and this package no longer provides it. secrets.go's legacy
// scheme (HMAC-SHA256 under "lnurlcash-note-v1", predating LUD-25 entirely) is
// still derived and still scanned on restore, so nothing already minted under
// it goes missing.
//
// DeriveCashDomainNode is the same walk over the host exactly as the wallet
// stored it, port included. That is the node the superseded tweak schemes hung
// their notes off, kept so a wallet can still sweep them (see
// LegacyBranchNode).

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

// DeriveCashDomainNode returns m/139'/d1/d2/d3/d4 over host exactly as given,
// port included: the node the superseded tweak schemes derived their notes
// from. LUD-26's root is DeriveServiceRoot, which hashes the domain without its
// port; for a host without one the two are the same node.
//
// Whoever derives it can derive every note key the wallet held under those
// schemes AT THIS MINT, so it is bearer material for one mint's subtree.
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

// DeriveServiceRoot returns S = m/139'/d1/d2/d3/d4, one SERVICE's LUD-26 root,
// from the wallet's m/139' root (DeriveCashRoot).
//
// domain may be a mint URL, a note URL or a bare host: it is reduced to the
// lowercase hostname without scheme or port, the same string every signature at
// that mint commits to (see SpendDomainOf). A domain hosts exactly one mint, so
// seed plus domain recovers everything a wallet holds there.
//
// Bearer material for every note the wallet will ever hold at this mint: a
// wallet hands out a share's cx1, never this node.
func DeriveServiceRoot(root CashNode, domain string) (CashNode, error) {
	host, err := SpendDomainOf(domain)
	if err != nil {
		return CashNode{}, &ProtocolError{Detail: "a SERVICE root is derived for a domain"}
	}
	return DeriveCashDomainNode(root, host)
}

// CashNodePublicKey returns a node's compressed public key, P in BIP-32's
// terms.
func CashNodePublicKey(node CashNode) ([33]byte, error) {
	var out [33]byte
	var key secp256k1.ModNScalar
	if key.SetBytes(&node.PrivateKey) != 0 || key.IsZero() {
		return out, &ProtocolError{Detail: "cash node holds an invalid private key"}
	}
	copy(out[:], secp256k1.NewPrivateKey(&key).PubKey().SerializeCompressed())
	return out, nil
}

// DeriveCashChildPub performs one BIP-32 CKDpub step from a compressed public
// key and its chain code: what a SERVICE holding only a share's cx1 derives
// each of its notes with. A hardened index is refused, since only the private
// key can take one. Returns the child's compressed key and chain code.
func DeriveCashChildPub(pubkey [33]byte, chainCode [32]byte, index uint32) ([33]byte, [32]byte, error) {
	var outKey [33]byte
	var outChain [32]byte
	if index >= hardened {
		return outKey, outChain, &ProtocolError{Detail: fmt.Sprintf("a public key has no hardened child, and %d is one", index)}
	}
	parent, err := secp256k1.ParsePubKey(pubkey[:])
	if err != nil {
		return outKey, outChain, &ProtocolError{Detail: "not a compressed secp256k1 point"}
	}
	data := make([]byte, 37)
	copy(data[:33], pubkey[:])
	binary.BigEndian.PutUint32(data[33:], index)
	material := hmac512(chainCode[:], data)

	// the same two ~2^-127 failures as CKDpriv: a tweak at or above the group
	// order, and a child at infinity
	var il [32]byte
	copy(il[:], material[:32])
	var tweak secp256k1.ModNScalar
	if tweak.SetBytes(&il) != 0 {
		return outKey, outChain, &ProtocolError{Detail: fmt.Sprintf("BIP-32 derivation at %d is out of range", index)}
	}
	var point, tweakPoint, child secp256k1.JacobianPoint
	parent.AsJacobian(&point)
	secp256k1.ScalarBaseMultNonConst(&tweak, &tweakPoint)
	secp256k1.AddNonConst(&point, &tweakPoint, &child)
	if (child.X.IsZero() && child.Y.IsZero()) || child.Z.IsZero() {
		return outKey, outChain, &ProtocolError{Detail: fmt.Sprintf("BIP-32 derivation at %d is out of range", index)}
	}
	child.ToAffine()
	copy(outKey[:], secp256k1.NewPublicKey(&child.X, &child.Y).SerializeCompressed())
	copy(outChain[:], material[32:])
	return outKey, outChain, nil
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
