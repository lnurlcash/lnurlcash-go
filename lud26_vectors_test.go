package lnurlcash_test

// LUD-26's tree below each SERVICE root, graded against lnurlcash-conformance:
// part2.json (this project's own fixtures, with the superseded tweak schemes
// kept as negatives and as read-only derivations), nostr-seed.json, and the
// lud25 and lud26 sections of spec-vectors.json, which are the luds repository's
// own published vectors.
//
// part2.json and nostr-seed.json are decoded strictly. A field these tests do
// not know is a field nobody is grading, so a vector that gains one fails here
// until it is.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	lnurlcash "github.com/lnurlcash/lnurlcash-go"
)

// ---- loose JSON access, for the spec vectors ----

func loadObject(t *testing.T, name string) map[string]any {
	t.Helper()
	path := filepath.Join(vectorsDir(t), name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("conformance vectors not found at %s - check out lnurlcash-conformance v0.16.2 or later alongside this repo, or set LNURLCASH_CONFORMANCE", path)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("%s is not valid JSON: %v", path, err)
	}
	return parsed
}

func jstr(t *testing.T, v map[string]any, key string) string {
	t.Helper()
	s, ok := v[key].(string)
	if !ok {
		t.Fatalf("vector field %q is not a string", key)
	}
	return s
}

func jobj(t *testing.T, v map[string]any, key string) map[string]any {
	t.Helper()
	o, ok := v[key].(map[string]any)
	if !ok {
		t.Fatalf("vector field %q is not an object", key)
	}
	return o
}

func jlist(t *testing.T, v map[string]any, key string) []map[string]any {
	t.Helper()
	items, ok := v[key].([]any)
	if !ok {
		t.Fatalf("vector field %q is not a list", key)
	}
	out := make([]map[string]any, len(items))
	for i, item := range items {
		if out[i], ok = item.(map[string]any); !ok {
			t.Fatalf("vector field %q[%d] is not an object", key, i)
		}
	}
	return out
}

func jnum(t *testing.T, v map[string]any, key string) int64 {
	t.Helper()
	n, ok := v[key].(float64)
	if !ok {
		t.Fatalf("vector field %q is not a number", key)
	}
	return int64(n)
}

// ---- part2.json and nostr-seed.json ----

type part2Note struct {
	Index                uint32 `json:"index"`
	Path                 string `json:"path"`
	NoteSecretKey        string `json:"noteSecretKey"`
	NotePubkeyCompressed string `json:"notePubkeyCompressed"`
	NotePubkey           string `json:"notePubkey"`
	Cp1                  string `json:"cp1"`
	Sighash              string `json:"sighash"`
	KeyPathSignature     string `json:"keyPathSignature"`
	Ck1                  string `json:"ck1"`
}

type part2Share struct {
	Share        uint32      `json:"share"`
	Path         string      `json:"path"`
	SharePrivate string      `json:"sharePrivateKey"`
	SharePubkey  string      `json:"sharePubkey"`
	ChainCode    string      `json:"chainCode"`
	Cx1          string      `json:"cx1"`
	Notes        []part2Note `json:"notes"`
}

type part2Account struct {
	Account uint32       `json:"account"`
	Wallet  []part2Note  `json:"wallet"`
	Change  []part2Note  `json:"change"`
	Shares  []part2Share `json:"shares"`
}

type part2Branch struct {
	Mnemonic       string         `json:"mnemonic"`
	SeedHex        string         `json:"seedHex"`
	Host           string         `json:"host"`
	Domain         string         `json:"domain"`
	CashHashingKey string         `json:"cashHashingKey"`
	DomainIndices  []uint32       `json:"domainIndices"`
	ServiceRoot    string         `json:"serviceRoot"`
	Accounts       []part2Account `json:"accounts"`
}

type part2Certificate struct {
	Superseded bool   `json:"superseded"`
	Domain     string `json:"domain"`
	NotePubkey string `json:"notePubkey"`
	AmountMsat int64  `json:"amountMsat"`
	Message    string `json:"message"`
	Digest     string `json:"digest"`
	Signature  string `json:"signature"`
	Cs1        string `json:"cs1"`
}

type part2LegacyNote struct {
	Purpose       uint32 `json:"purpose"`
	Index         uint32 `json:"index"`
	NotePubkey    string `json:"notePubkey"`
	Cp1           string `json:"cp1"`
	NoteSecretKey string `json:"noteSecretKey"`
}

type part2Vectors struct {
	Version     int            `json:"version"`
	Spec        string         `json:"spec"`
	Description string         `json:"description"`
	Conventions map[string]any `json:"conventions"`
	Mint        struct {
		PrivateKey string `json:"privateKey"`
		MintPubkey string `json:"mintPubkey"`
	} `json:"mint"`
	Branches           []part2Branch      `json:"branches"`
	Certificates       []part2Certificate `json:"certificates"`
	LegacyCertificates []part2Certificate `json:"legacyCertificates"`
	AddressProofs      []struct {
		Role      string `json:"role"`
		Action    string `json:"action"`
		Domain    string `json:"domain"`
		Username  string `json:"username"`
		Cx1       string `json:"cx1"`
		Message   string `json:"message"`
		Digest    string `json:"digest"`
		SignerCx1 string `json:"signerCx1"`
		SignerKey string `json:"signerPubkey"`
		Signature string `json:"signature"`
	} `json:"addressProofs"`
	Legacy struct {
		Superseded  bool   `json:"superseded"`
		Description string `json:"description"`
		Branches    []struct {
			Mnemonic     string            `json:"mnemonic"`
			Host         string            `json:"host"`
			AddressNode  string            `json:"addressNode"`
			BranchPubkey string            `json:"branchPubkey"`
			BranchParity string            `json:"branchParity"`
			ChainCode    string            `json:"chainCode"`
			Cx1          string            `json:"cx1"`
			Notes        []part2LegacyNote `json:"notes"`
			PrePurpose   []part2LegacyNote `json:"prePurpose"`
		} `json:"branches"`
	} `json:"legacy"`
	Valid []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Bytes string `json:"bytes"`
		Why   string `json:"why"`
	} `json:"valid"`
	Invalid []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Why   string `json:"why"`
	} `json:"invalid"`
}

type nostrSeedVectors struct {
	Version     int    `json:"version"`
	Spec        string `json:"spec"`
	Extension   bool   `json:"extension"`
	Description string `json:"description"`
	Label       string `json:"label"`
	Cases       []struct {
		Identity       string         `json:"identity"`
		IdentityPubkey string         `json:"identityPubkey"`
		Host           string         `json:"host"`
		Domain         string         `json:"domain"`
		Seed           string         `json:"seed"`
		ServiceRoot    string         `json:"serviceRoot"`
		Accounts       []part2Account `json:"accounts"`
	} `json:"cases"`
}

func allNotes(accounts []part2Account) []part2Note {
	var out []part2Note
	for _, account := range accounts {
		out = append(out, account.Wallet...)
		out = append(out, account.Change...)
		for _, share := range account.Shares {
			out = append(out, share.Notes...)
		}
	}
	return out
}

func secretKeyHex(t *testing.T, secretKey [32]byte) string {
	t.Helper()
	return hex.EncodeToString(publicKeyOf(t, secretKey)[1:])
}

// gradeKeyPathNote grades one key-path note's spend fields, as part2.json and
// nostr-seed.json both carry them: the sighash for its domain, the signature,
// the ck1, and what the SERVICE makes of it there and elsewhere.
func gradeKeyPathNote(t *testing.T, note part2Note, secret [32]byte, host, domain string) {
	t.Helper()
	pubkey := hex32(t, note.NotePubkey)
	sighash, err := lnurlcash.KeyPathSighash(pubkey, domain)
	if err != nil || hex.EncodeToString(sighash[:]) != note.Sighash {
		t.Errorf("sighash = %x (%v), want %s", sighash, err, note.Sighash)
	}
	// Fixed BIP-340 auxiliary input: the same key reproduces the same ck1 for
	// the same domain byte for byte, for seed recovery. Signing from the host
	// as stored reduces it to the domain first.
	payload, err := lnurlcash.SignNoteOwnership(secret, host)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !bytes.Equal(payload[:32], pubkey[:]) {
		t.Errorf("ck1 payload key = %x, want %s", payload[:32], note.NotePubkey)
	}
	if got := hex.EncodeToString(payload[32:]); got != note.KeyPathSignature {
		t.Errorf("key-path signature = %s, want %s", got, note.KeyPathSignature)
	}
	// independently of the package: a BIP-340 signature over the vector's sighash
	schnorrKey, err := schnorr.ParsePubKey(pubkey[:])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := schnorr.ParseSignature(hexBytes(t, note.KeyPathSignature, 64))
	if err != nil || !signature.Verify(hexBytes(t, note.Sighash, 32), schnorrKey) {
		t.Errorf("the vector's key-path signature does not verify over its sighash: %v", err)
	}
	if got := lnurlcash.EncodeCk1(payload); got != note.Ck1 {
		t.Errorf("ck1 = %s, want %s", got, note.Ck1)
	}

	// the SERVICE's side: the ck1 it is handed verifies as the note it files
	decoded, err := lnurlcash.DecodeCk1(note.Ck1)
	if err != nil || decoded.IsLegacy || decoded.Current != payload {
		t.Errorf("ck1 decodes to %x (%v), want %x", decoded.Bytes(), err, payload)
	}
	owner, err := lnurlcash.RecoverNoteOwnershipPubkey(payload[:], domain)
	if err != nil || owner.PubkeyXOnly != pubkey || owner.Legacy {
		t.Errorf("ck1 verifies as %+v (%v), want %s, current", owner, err, note.NotePubkey)
	}
	if verified, err := lnurlcash.VerifySpend(note.Ck1, domain); err != nil || verified.OutputKey != pubkey || verified.Legacy {
		t.Errorf("VerifySpend = %+v (%v), want the note, current", verified, err)
	}
	// and it is bound to that mint: anywhere else it opens nothing
	if _, err := lnurlcash.VerifySpend(note.Ck1, "elsewhere.example"); err == nil {
		t.Error("the ck1 verified at another domain")
	}
	for _, spelling := range []string{note.Ck1, strings.ToUpper(note.Ck1)} {
		if id, err := lnurlcash.NoteIDOf(spelling); err != nil || id != note.NotePubkey {
			t.Errorf("NoteIDOf = %s (%v), want %s", id, err, note.NotePubkey)
		}
	}
	if lookup, err := lnurlcash.NoteLookupOf(note.Ck1); err != nil || lookup != note.Cp1 {
		t.Errorf("NoteLookupOf = %s (%v), want %s", lookup, err, note.Cp1)
	}
}

// gradeNote grades one note's keys, derived from the SERVICE root at path, and
// its spend.
func gradeNote(t *testing.T, root lnurlcash.CashNode, path lnurlcash.NotePath, note part2Note, host, domain string) {
	t.Helper()
	key, err := lnurlcash.DeriveNoteKey(root, path)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got := hex.EncodeToString(key.SecretKey[:]); got != note.NoteSecretKey {
		t.Errorf("note secret key = %s, want %s", got, note.NoteSecretKey)
	}
	if got := hex.EncodeToString(key.Pubkey[:]); got != note.NotePubkeyCompressed {
		t.Errorf("note pubkey = %s, want %s", got, note.NotePubkeyCompressed)
	}
	if got := hex.EncodeToString(key.OutputKey[:]); got != note.NotePubkey {
		t.Errorf("Q = %s, want %s", got, note.NotePubkey)
	}
	// and the key is the secret key's own: x(sk.G) is Q, worked out here
	if got := secretKeyHex(t, key.SecretKey); got != note.NotePubkey {
		t.Errorf("x(sk.G) = %s, want %s", got, note.NotePubkey)
	}
	if got := lnurlcash.EncodeCp1(key.OutputKey); got != note.Cp1 {
		t.Errorf("cp1 = %s, want %s", got, note.Cp1)
	}
	if decoded, err := lnurlcash.DecodeCp1(note.Cp1); err != nil || decoded != key.OutputKey {
		t.Errorf("cp1 does not decode to Q: %v", err)
	}
	gradeKeyPathNote(t, note, key.SecretKey, host, domain)
}

// gradeAccounts grades every account as part2.json and nostr-seed.json carry
// them: each wallet and change note from the root, each share's cx1, and each
// share note both from the root and, as a SERVICE derives it, from the cx1
// alone.
func gradeAccounts(t *testing.T, root lnurlcash.CashNode, accounts []part2Account, host, domain string) {
	t.Helper()
	for _, account := range accounts {
		a := account.Account
		for _, note := range account.Wallet {
			t.Run(fmt.Sprintf("%d'/0/%d", a, note.Index), func(t *testing.T) {
				gradeNote(t, root, lnurlcash.WalletNotePath(a, note.Index), note, host, domain)
			})
		}
		for _, note := range account.Change {
			t.Run(fmt.Sprintf("%d'/1/%d", a, note.Index), func(t *testing.T) {
				gradeNote(t, root, lnurlcash.ChangeNotePath(a, note.Index), note, host, domain)
			})
		}
		for _, share := range account.Shares {
			n := share.Share
			t.Run(fmt.Sprintf("%d'/2/%d'", a, n), func(t *testing.T) {
				node, err := lnurlcash.DeriveShareNode(root, a, n)
				if err != nil {
					t.Fatal(err)
				}
				if got := hex.EncodeToString(node.PrivateKey[:]); got != share.SharePrivate {
					t.Errorf("share key = %s, want %s", got, share.SharePrivate)
				}
				if got := hex.EncodeToString(node.ChainCode[:]); got != share.ChainCode {
					t.Errorf("chain code = %s, want %s", got, share.ChainCode)
				}
				cx1, err := lnurlcash.CashNodeToCx1(node)
				if err != nil {
					t.Fatal(err)
				}
				if got := hex.EncodeToString(cx1.Pubkey[:]); got != share.SharePubkey {
					t.Errorf("share pubkey = %s, want %s", got, share.SharePubkey)
				}
				if got := lnurlcash.EncodeCx1(cx1); got != share.Cx1 {
					t.Errorf("cx1 = %s, want %s", got, share.Cx1)
				}
				if len(share.Cx1) != 113 {
					t.Errorf("a cx1 is 113 characters, not %d", len(share.Cx1))
				}
				// a SERVICE starts from the string, never the node
				watched, err := lnurlcash.DecodeCx1(share.Cx1)
				if err != nil || watched != cx1 {
					t.Fatalf("cx1 does not decode to the share: %v", err)
				}
				for _, note := range share.Notes {
					t.Run(fmt.Sprintf("%d", note.Index), func(t *testing.T) {
						gradeNote(t, root, lnurlcash.ShareNotePath(a, n, note.Index), note, host, domain)
						pubkey, err := lnurlcash.DeriveNotePubkey(watched, note.Index)
						if err != nil || hex.EncodeToString(pubkey[:]) != note.NotePubkey {
							t.Errorf("CKDpub from the cx1 = %x (%v), want %s", pubkey, err, note.NotePubkey)
						}
					})
				}
			})
		}
	}
}

func TestPart2Vectors(t *testing.T) {
	var vectors part2Vectors
	loadVectorsStrict(t, "part2.json", &vectors)
	if vectors.Version != 1 {
		t.Fatalf("part2.json is format version %d; these tests read version 1", vectors.Version)
	}

	// What this package implements. A vector describing anything else is a
	// different scheme, and every value below would fail for that reason alone.
	for key, want := range map[string]string{
		"serviceRoot":        "m/139'/d1/d2/d3/d4",
		"hashingKey":         "m/139'/0",
		"walletChain":        "S/a'/0/i",
		"changeChain":        "S/a'/1/i",
		"shareNote":          "S/a'/2/n'/i",
		"certificateMessage": "LNURLcash:<domain>:<amount_msat>:<hex(Q)>",
	} {
		if got, _ := vectors.Conventions[key].(string); got != want {
			t.Fatalf("the vectors describe %s as %q, not the %q this package implements", key, got, want)
		}
	}

	mintPubkey := vectors.Mint.MintPubkey
	if got := hex.EncodeToString(publicKeyOf(t, hex32(t, vectors.Mint.PrivateKey))); got != mintPubkey {
		t.Fatalf("mint private key is the key of %s, not %s", got, mintPubkey)
	}

	// a host with a port is where the host as stored and the domain part
	// company, and the derivation now follows the domain
	portHost := false
	var notes []part2Note
	for _, branch := range vectors.Branches {
		portHost = portHost || branch.Host != branch.Domain
		notes = append(notes, allNotes(branch.Accounts)...)
	}
	if !portHost {
		t.Error("no branch where the host and the domain differ")
	}
	// both parities, so the BIP-340 signer's negation is exercised, and the
	// largest index that is not a hardened step
	var even, odd, top bool
	for _, note := range notes {
		even = even || strings.HasPrefix(note.NotePubkeyCompressed, "02")
		odd = odd || strings.HasPrefix(note.NotePubkeyCompressed, "03")
		top = top || note.Index == 0x7fffffff
	}
	if !even || !odd || !top {
		t.Errorf("notes cover even y %v, odd y %v, index 2^31-1 %v; all three are needed", even, odd, top)
	}

	for _, branch := range vectors.Branches {
		t.Run(fmt.Sprintf("%s under %.8s", branch.Host, branch.SeedHex), func(t *testing.T) {
			if got, err := lnurlcash.SpendDomainOf(branch.Host); err != nil || got != branch.Domain {
				t.Errorf("spend domain of %s = %q (%v), want %q", branch.Host, got, err, branch.Domain)
			}
			seed := bip39Seed(t, branch.Mnemonic)
			if got := hex.EncodeToString(seed); got != branch.SeedHex {
				t.Fatalf("seed = %s, want %s", got, branch.SeedHex)
			}
			root, err := lnurlcash.DeriveCashRoot(seed)
			if err != nil {
				t.Fatal(err)
			}
			hashing, err := lnurlcash.DeriveCashChild(root, 0)
			if err != nil || hex.EncodeToString(hashing.PrivateKey[:]) != branch.CashHashingKey {
				t.Errorf("hashing key = %x (%v), want %s", hashing.PrivateKey, err, branch.CashHashingKey)
			}
			indices, err := lnurlcash.CashDomainIndices(root, branch.Domain)
			if err != nil {
				t.Fatal(err)
			}
			if len(branch.DomainIndices) != len(indices) {
				t.Fatalf("%d domain indices, want %d", len(branch.DomainIndices), len(indices))
			}
			for i, want := range branch.DomainIndices {
				if indices[i] != want {
					t.Errorf("d%d = %d, want %d", i+1, indices[i], want)
				}
			}
			// from the host as stored, which drops its port first
			serviceRoot, err := lnurlcash.DeriveServiceRoot(root, branch.Host)
			if err != nil {
				t.Fatal(err)
			}
			if got := lnurlcash.CashNodeToHex(serviceRoot); got != branch.ServiceRoot {
				t.Fatalf("service root = %s, want %s", got, branch.ServiceRoot)
			}
			gradeAccounts(t, serviceRoot, branch.Accounts, branch.Host, branch.Domain)
		})
	}

	// a note index is never a hardened step
	root, err := lnurlcash.DeriveCashRoot(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	serviceRoot, err := lnurlcash.DeriveServiceRoot(root, "mint.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []lnurlcash.NotePath{
		lnurlcash.WalletNotePath(0, 0x80000000),
		lnurlcash.ChangeNotePath(0x80000000, 0),
		lnurlcash.ShareNotePath(0, 0x80000000, 0),
		{Chain: 3},
	} {
		if _, err := lnurlcash.DeriveNoteKey(serviceRoot, path); err == nil {
			t.Errorf("derived %+v", path)
		}
	}
	if _, err := lnurlcash.DeriveShareNode(serviceRoot, 0x80000000, 0); err == nil {
		t.Error("derived a share of a hardened account number")
	}
	shareNode, err := lnurlcash.DeriveShareNode(serviceRoot, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	share, err := lnurlcash.CashNodeToCx1(shareNode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lnurlcash.DeriveNotePubkey(share, 0x80000000); err == nil {
		t.Error("CKDpub took a hardened index")
	}
	if _, err := lnurlcash.DeriveServiceRoot(root, ""); err == nil {
		t.Error("derived a service root for no domain")
	}
}

// The tweak schemes before LUD-26, kept so a wallet can find and sweep the
// notes it holds under them.
func TestPart2LegacyTweakVectors(t *testing.T) {
	var vectors part2Vectors
	loadVectorsStrict(t, "part2.json", &vectors)
	if !vectors.Legacy.Superseded || len(vectors.Legacy.Branches) == 0 {
		t.Fatal("part2.json no longer carries the superseded tweak schemes")
	}
	parities := map[string]bool{}
	for _, branch := range vectors.Legacy.Branches {
		parities[branch.BranchParity] = true
		t.Run(branch.Host, func(t *testing.T) {
			root, err := lnurlcash.DeriveCashRoot(bip39Seed(t, branch.Mnemonic))
			if err != nil {
				t.Fatal(err)
			}
			// the host as stored, port included
			node, err := lnurlcash.LegacyBranchNode(root, branch.Host)
			if err != nil {
				t.Fatal(err)
			}
			if got := lnurlcash.CashNodeToHex(node); got != branch.AddressNode {
				t.Fatalf("legacy node = %s, want %s", got, branch.AddressNode)
			}
			compressed := publicKeyOf(t, node.PrivateKey)
			if parity := map[byte]string{2: "even", 3: "odd"}[compressed[0]]; parity != branch.BranchParity {
				t.Errorf("branch parity = %s, want %s", parity, branch.BranchParity)
			}
			cx1, err := lnurlcash.LegacyCx1Of(node)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(cx1.PubkeyXOnly[:]); got != branch.BranchPubkey {
				t.Errorf("branch pubkey = %s, want %s", got, branch.BranchPubkey)
			}
			if got := hex.EncodeToString(cx1.ChainCode[:]); got != branch.ChainCode {
				t.Errorf("chain code = %s, want %s", got, branch.ChainCode)
			}
			if got := lnurlcash.EncodeLegacyCx1(cx1); got != branch.Cx1 {
				t.Errorf("legacy cx1 = %s, want %s", got, branch.Cx1)
			}
			if decoded, err := lnurlcash.DecodeLegacyCx1(branch.Cx1); err != nil || decoded != cx1 {
				t.Errorf("legacy cx1 does not decode to the branch: %v", err)
			}
			if lnurlcash.IsCx1(branch.Cx1) {
				t.Error("the 64-byte shape is still a cx1")
			}

			type scheme struct {
				purpose lnurlcash.LegacyPurpose
				note    part2LegacyNote
			}
			var all []scheme
			for _, note := range branch.Notes {
				all = append(all, scheme{lnurlcash.LegacyPurpose(note.Purpose), note})
			}
			for _, note := range branch.PrePurpose {
				all = append(all, scheme{lnurlcash.LegacyPurposeNone, note})
			}
			if len(branch.Notes) == 0 || len(branch.PrePurpose) == 0 {
				t.Fatal("both the purpose and the pre-purpose schemes are needed")
			}
			for _, c := range all {
				at := fmt.Sprintf("purpose %d index %d", c.purpose, c.note.Index)
				pubkey, err := lnurlcash.LegacyDeriveNotePubkey(cx1, c.purpose, c.note.Index)
				if err != nil || hex.EncodeToString(pubkey[:]) != c.note.NotePubkey {
					t.Errorf("%s: pubkey = %x (%v), want %s", at, pubkey, err, c.note.NotePubkey)
				}
				if got := lnurlcash.EncodeCp1(pubkey); got != c.note.Cp1 {
					t.Errorf("%s: cp1 = %s, want %s", at, got, c.note.Cp1)
				}
				secret, err := lnurlcash.LegacyDeriveNoteSecretKey(node, c.purpose, c.note.Index)
				if err != nil || hex.EncodeToString(secret[:]) != c.note.NoteSecretKey {
					t.Errorf("%s: secret key = %x (%v), want %s", at, secret, err, c.note.NoteSecretKey)
				}
				if got := secretKeyHex(t, secret); got != c.note.NotePubkey {
					t.Errorf("%s: x(sk.G) = %s, want %s", at, got, c.note.NotePubkey)
				}
			}
			if _, err := lnurlcash.LegacyDeriveNotePubkey(cx1, lnurlcash.LegacyPurpose(-2), 0); err == nil {
				t.Error("derived under a purpose below none")
			}
		})
	}
	if !parities["even"] || !parities["odd"] {
		t.Errorf("the legacy branches cover parities %v; both even and odd are needed", parities)
	}
}

func TestPart2AddressProofVectors(t *testing.T) {
	var vectors part2Vectors
	loadVectorsStrict(t, "part2.json", &vectors)

	shareKey := map[string][32]byte{}
	for _, branch := range vectors.Branches {
		for _, account := range branch.Accounts {
			for _, share := range account.Shares {
				shareKey[share.Cx1] = hex32(t, share.SharePrivate)
			}
		}
	}
	actions := map[string]bool{}
	for _, proof := range vectors.AddressProofs {
		actions[proof.Action] = true
		t.Run(proof.Action+"/"+proof.Username+"@"+proof.Domain, func(t *testing.T) {
			secret, ok := shareKey[proof.SignerCx1]
			if !ok {
				t.Fatal("the signer is a share in the file")
			}
			if got := secretKeyHex(t, secret); got != proof.SignerKey {
				t.Errorf("signer pubkey = %s, want %s", got, proof.SignerKey)
			}
			// the SERVICE's own domain, however the caller happens to spell it
			for _, spelling := range []string{proof.Domain, strings.ToUpper(proof.Domain), "https://" + proof.Domain + ":8443/w"} {
				message, err := lnurlcash.AddressProofMessage(proof.Action, spelling, proof.Username, proof.Cx1)
				if err != nil || message != proof.Message {
					t.Errorf("message at %q = %q (%v), want %q", spelling, message, err, proof.Message)
				}
			}
			// and the username in any case
			if message, err := lnurlcash.AddressProofMessage(proof.Action, proof.Domain, strings.ToUpper(proof.Username), proof.Cx1); err != nil || message != proof.Message {
				t.Errorf("message for an upper-case username = %q (%v), want %q", message, err, proof.Message)
			}
			digest, err := lnurlcash.AddressProofDigest(proof.Action, proof.Domain, proof.Username, proof.Cx1)
			if err != nil || hex.EncodeToString(digest) != proof.Digest {
				t.Errorf("digest = %x (%v), want %s", digest, err, proof.Digest)
			}
			signature, err := lnurlcash.SignAddressProof(secret, proof.Action, proof.Domain, proof.Username, proof.Cx1)
			if err != nil || hex.EncodeToString(signature[:]) != proof.Signature {
				t.Fatalf("signature = %x (%v), want %s", signature, err, proof.Signature)
			}

			// what the SERVICE checks: BIP-340 against x(P) of the signer's cx1
			if !lnurlcash.VerifyAddressProof(proof.SignerCx1, signature[:], proof.Action, proof.Domain, proof.Username, proof.Cx1) {
				t.Error("the proof does not verify")
			}
			// bound to its domain, its signer and, where there is one, its cx1
			if lnurlcash.VerifyAddressProof(proof.SignerCx1, signature[:], proof.Action, "elsewhere.example", proof.Username, proof.Cx1) {
				t.Error("verified at another SERVICE")
			}
			// another share: neither the signer nor the cx1 the proof binds
			var other string
			for cx1 := range shareKey {
				if cx1 != proof.SignerCx1 && cx1 != proof.Cx1 {
					other = cx1
					break
				}
			}
			if lnurlcash.VerifyAddressProof(other, signature[:], proof.Action, proof.Domain, proof.Username, proof.Cx1) {
				t.Error("verified against another signer")
			}
			if proof.Cx1 != "" && lnurlcash.VerifyAddressProof(proof.SignerCx1, signature[:], proof.Action, proof.Domain, proof.Username, other) {
				t.Error("verified over another cx1")
			}
			if lnurlcash.VerifyAddressProof(proof.SignerCx1, signature[:63], proof.Action, proof.Domain, proof.Username, proof.Cx1) {
				t.Error("verified a short signature")
			}
		})
	}
	for _, action := range []string{"register", "update", "unregister"} {
		if !actions[action] {
			t.Errorf("no %s proof", action)
		}
	}

	cx1 := ""
	for key := range shareKey {
		cx1 = key
		break
	}
	legacy := vectors.Legacy.Branches[0].Cx1
	for _, c := range []struct{ action, cx1 string }{
		{"register", ""},
		{"update", ""},
		{"unregister", cx1},
		{"delete", cx1},
		{"register", legacy},
	} {
		if message, err := lnurlcash.AddressProofMessage(c.action, "mint.example", "alice", c.cx1); err == nil {
			t.Errorf("built %q for %s with cx1 %q", message, c.action, c.cx1)
		}
	}
	if _, err := lnurlcash.AddressProofMessage("register", "", "alice", cx1); err == nil {
		t.Error("built an address proof bound to no mint")
	}
	if _, err := lnurlcash.AddressProofMessage("unregister", "mint.example", " ", ""); err == nil {
		t.Error("built an address proof for no username")
	}
}

func signCertificate(t *testing.T, mintSecret [32]byte, digest []byte) [65]byte {
	t.Helper()
	var key secp256k1.ModNScalar
	key.SetBytes(&mintSecret)
	compact := ecdsa.SignCompact(secp256k1.NewPrivateKey(&key), digest, true)
	var signature [65]byte
	copy(signature[:64], compact[1:])
	signature[64] = compact[0] - 27 - 4
	return signature
}

func TestPart2CertificateVectors(t *testing.T) {
	var vectors part2Vectors
	loadVectorsStrict(t, "part2.json", &vectors)
	mintSecret := hex32(t, vectors.Mint.PrivateKey)
	mintPubkey := vectors.Mint.MintPubkey

	// Every note in the file by key, so each certificate is checked the way a
	// recipient checks one: from the note's ck1 and its domain, nothing else.
	type held struct{ ck1, domain string }
	notes := map[string]held{}
	for _, branch := range vectors.Branches {
		for _, note := range allNotes(branch.Accounts) {
			notes[note.NotePubkey] = held{note.Ck1, branch.Domain}
		}
	}

	if len(vectors.Certificates) == 0 {
		t.Fatal("no certificates")
	}
	for _, c := range vectors.Certificates {
		t.Run(fmt.Sprintf("%d msat at %s", c.AmountMsat, c.Domain), func(t *testing.T) {
			if message, err := lnurlcash.NoteSignatureMessageForHash(c.NotePubkey, c.Domain, c.AmountMsat); err != nil || message != c.Message {
				t.Errorf("message = %q (%v), want %q", message, err, c.Message)
			}
			digest, err := lnurlcash.NoteSignatureDigestForHash(c.NotePubkey, c.Domain, c.AmountMsat)
			if err != nil || hex.EncodeToString(digest) != c.Digest {
				t.Errorf("digest = %x (%v), want %s", digest, err, c.Digest)
			}
			note, ok := notes[c.NotePubkey]
			if !ok {
				t.Fatalf("certifies %s, which no branch holds", c.NotePubkey)
			}
			if message, err := lnurlcash.NoteSignatureMessage(note.ck1, c.Domain, c.AmountMsat); err != nil || message != c.Message {
				t.Errorf("message from the ck1 = %q (%v), want %q", message, err, c.Message)
			}
			if digest, err := lnurlcash.NoteSignatureDigest(note.ck1, c.Domain, c.AmountMsat); err != nil || hex.EncodeToString(digest) != c.Digest {
				t.Errorf("digest from the ck1 = %x (%v), want %s", digest, err, c.Digest)
			}

			signature := hex65(t, c.Signature)
			requireLayout(t, signature)
			if got, err := lnurlcash.EncodeCs1WithAmount(c.AmountMsat, signature); err != nil || got != c.Cs1 {
				t.Errorf("cs1 = %s (%v), want %s", got, err, c.Cs1)
			}
			decoded, err := lnurlcash.DecodeCs1WithAmount(c.Cs1)
			if err != nil || decoded.AmountMsat != c.AmountMsat || decoded.Signature != signature {
				t.Fatalf("cs1 does not decode to the signature: %v", err)
			}
			if lnurlcash.IsCs1(c.Cs1) || !lnurlcash.IsCs1WithAmount(c.Cs1) {
				t.Error("a current cs1 was mistaken for a legacy certificate")
			}
			if any, err := lnurlcash.DecodeAnyCs1(c.Cs1); err != nil || any != signature || !lnurlcash.IsAnyCs1(c.Cs1) {
				t.Errorf("the migration API did not accept the current certificate: %v", err)
			}
			legacy := lnurlcash.EncodeCs1(signature)
			if old, err := lnurlcash.DecodeCs1(legacy); err != nil || old != signature || !lnurlcash.IsCs1(legacy) {
				t.Errorf("the legacy certificate stopped working: %v", err)
			}
			if _, err := lnurlcash.DecodeCs1WithAmount(legacy); err == nil || lnurlcash.IsCs1WithAmount(legacy) {
				t.Error("a legacy cs1 was assigned an amount it does not carry")
			}
			// RFC 6979 on the mint's side too: its key over the digest
			// reproduces the certificate, and it recovers to the mint's key
			if got := signCertificate(t, mintSecret, hexBytes(t, c.Digest, 32)); got != signature {
				t.Errorf("the mint's key signs %x, want %x", got, signature)
			}
			if got := recoverCompressed(t, signature, hexBytes(t, c.Digest, 32)); got != mintPubkey {
				t.Errorf("cs1 recovers to %s, want the mint's %s", got, mintPubkey)
			}

			// each recovers to the mint's key by the note's id, at the
			// certificate's domain and nowhere else. A current certificate is
			// a cs1, never raw hex.
			if !lnurlcash.VerifyNoteCertificate(c.NotePubkey, c.Domain, c.AmountMsat, c.Cs1, mintPubkey) {
				t.Error("the certificate does not verify")
			}
			if lnurlcash.VerifyNoteCertificate(c.NotePubkey, c.Domain, c.AmountMsat, c.Signature, mintPubkey) {
				t.Error("raw hex verified as a current certificate")
			}
			if lnurlcash.VerifyNoteCertificate(c.NotePubkey, "elsewhere.example", c.AmountMsat, c.Cs1, mintPubkey) {
				t.Error("verified at another domain")
			}
			if got := lnurlcash.VerifyNoteSignatureForKey(c.NotePubkey, c.Domain, c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.CertifiedOverQ {
				t.Errorf("by the note's key = %v", got)
			}
			if got := lnurlcash.VerifyNoteSignatureForKey(c.NotePubkey, "elsewhere.example", c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.NotCertified {
				t.Errorf("by the note's key at another domain = %v", got)
			}
			// a cs1 whose prefix states another amount than the one it signs
			// proves nothing, whichever amount is asked about
			relabelled, _ := lnurlcash.EncodeCs1WithAmount(c.AmountMsat+1000, signature)
			for _, asked := range []int64{c.AmountMsat, c.AmountMsat + 1000} {
				if lnurlcash.VerifyNoteCertificate(c.NotePubkey, c.Domain, asked, relabelled, mintPubkey) {
					t.Errorf("a relabelled cs1 verified for %d", asked)
				}
			}

			// A certificate for another domain than the note's own vouches for
			// nothing there.
			if c.Domain != note.domain {
				if got := lnurlcash.VerifyNoteSignature(note.ck1, note.domain, c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.NotCertified {
					t.Errorf("certified at %s too: %v", note.domain, got)
				}
				return
			}
			if got := lnurlcash.VerifyNoteSignature(note.ck1, c.Domain, c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.CertifiedOverQ {
				t.Errorf("a ck1 and its cs1 = %v", got)
			}
			if got := lnurlcash.VerifyNoteSignature(note.ck1, c.Domain, c.AmountMsat+1, c.Cs1, mintPubkey); got != lnurlcash.NotCertified {
				t.Errorf("for an amount nobody certified: %v", got)
			}
			for other, held := range notes {
				if other != c.NotePubkey {
					if got := lnurlcash.VerifyNoteSignature(held.ck1, held.domain, c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.NotCertified {
						t.Errorf("the certificate verified for another note: %v", got)
					}
					break
				}
			}
			// The certificate is public, and so is Q. A ck1 pairing them with a
			// signature that does not open the note must not pass as the note,
			// and the genuine ck1 does not at any other mint.
			forged, _ := lnurlcash.DecodeCk1(note.ck1)
			forged.Current[40] ^= 0x01
			if got := lnurlcash.VerifyNoteSignature(lnurlcash.EncodeCk1(forged.Current), c.Domain, c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.NotCertified {
				t.Errorf("a forged spend = %v", got)
			}
			if got := lnurlcash.VerifyNoteSignature(note.ck1, "elsewhere.example", c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.NotCertified {
				t.Errorf("at another mint = %v", got)
			}
		})
	}

	// Certificates over the superseded message without a domain: still read on
	// notes people hold, reported as legacy, and never as the current one.
	if len(vectors.LegacyCertificates) == 0 {
		t.Fatal("no legacy certificates")
	}
	for _, c := range vectors.LegacyCertificates {
		t.Run(fmt.Sprintf("legacy %d msat", c.AmountMsat), func(t *testing.T) {
			if got := lnurlcash.LegacyNoteSignatureMessageForHash(c.NotePubkey, c.AmountMsat); got != c.Message {
				t.Errorf("message = %q, want %q", got, c.Message)
			}
			if got := hex.EncodeToString(lnurlcash.LegacyNoteSignatureDigestForHash(c.NotePubkey, c.AmountMsat)); got != c.Digest {
				t.Errorf("digest = %s, want %s", got, c.Digest)
			}
			if !lnurlcash.VerifyLegacyNoteSignatureHash(c.NotePubkey, c.AmountMsat, c.Cs1, mintPubkey) {
				t.Error("the legacy certificate does not verify")
			}
			if lnurlcash.VerifyNoteCertificate(c.NotePubkey, "mint.example", c.AmountMsat, c.Cs1, mintPubkey) {
				t.Error("a legacy certificate verified as a current one")
			}
			note := notes[c.NotePubkey]
			if got := lnurlcash.VerifyNoteSignature(note.ck1, note.domain, c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.CertifiedOverLegacyQ {
				t.Errorf("a ck1 and its legacy cs1 = %v", got)
			}
			if got := lnurlcash.VerifyNoteSignatureForKey(c.NotePubkey, note.domain, c.AmountMsat, c.Cs1, mintPubkey); got != lnurlcash.CertifiedOverLegacyQ {
				t.Errorf("by the note's key = %v", got)
			}
			// raw hex and the other recovery-id layout are legacy readings too
			if !lnurlcash.VerifyLegacyNoteSignatureHash(c.NotePubkey, c.AmountMsat, c.Signature, mintPubkey) {
				t.Error("raw hex did not verify as a legacy certificate")
			}
			leading := hex65(t, c.Signature)
			leading = [65]byte(append([]byte{leading[64]}, leading[:64]...))
			if !lnurlcash.VerifyLegacyNoteSignatureHash(c.NotePubkey, c.AmountMsat, hex.EncodeToString(leading[:]), mintPubkey) {
				t.Error("the leading recovery-id layout did not verify as a legacy certificate")
			}
			if lnurlcash.VerifyLegacyNoteSignatureHash(c.NotePubkey, c.AmountMsat+1, c.Cs1, mintPubkey) {
				t.Error("verified for another amount")
			}
		})
	}
}

func TestPart2StringVectors(t *testing.T) {
	var vectors part2Vectors
	loadVectorsStrict(t, "part2.json", &vectors)

	decoders := map[string]func(string) (string, error){
		"cp1": func(v string) (string, error) { b, err := lnurlcash.DecodeCp1(v); return hex.EncodeToString(b[:]), err },
		"ck1": func(v string) (string, error) {
			d, err := lnurlcash.DecodeCk1(v)
			return hex.EncodeToString(d.Bytes()), err
		},
		"cs1": func(v string) (string, error) {
			c, err := lnurlcash.DecodeCs1WithAmount(v)
			return hex.EncodeToString(c.Signature[:]), err
		},
		"cx1": func(v string) (string, error) {
			c, err := lnurlcash.DecodeCx1(v)
			return hex.EncodeToString(c.ChainCode[:]) + hex.EncodeToString(c.Pubkey[:]), err
		},
	}
	checks := map[string]func(string) bool{
		"cp1": lnurlcash.IsCp1, "ck1": lnurlcash.IsCk1, "cs1": lnurlcash.IsCs1WithAmount, "cx1": lnurlcash.IsCx1,
	}
	for _, valid := range vectors.Valid {
		decode, ok := decoders[valid.Type]
		if !ok {
			t.Fatalf("a valid %q: not a type this package decodes", valid.Type)
		}
		if got, err := decode(valid.Value); err != nil || got != valid.Bytes {
			t.Errorf("%s %q = %s (%v), want %s (%s)", valid.Type, valid.Value, got, err, valid.Bytes, valid.Why)
		}
		if !checks[valid.Type](valid.Value) {
			t.Errorf("Is%s(%q) = false (%s)", valid.Type, valid.Value, valid.Why)
		}
	}
	if len(vectors.Invalid) == 0 {
		t.Fatal("no invalid strings")
	}
	for _, invalid := range vectors.Invalid {
		decode, ok := decoders[invalid.Type]
		if !ok {
			t.Fatalf("an invalid %q: not a type this package decodes", invalid.Type)
		}
		if _, err := decode(invalid.Value); err == nil {
			t.Errorf("%s accepted %q, which is %s", invalid.Type, invalid.Value, invalid.Why)
		}
		if checks[invalid.Type](invalid.Value) {
			t.Errorf("Is%s(%q) = true, but it is %s", invalid.Type, invalid.Value, invalid.Why)
		}
	}
}

// TestNostrSeedVectors grades nostr-seed.json: an extension, not LUD-25 or
// LUD-26. LUD-26's tree rooted in a Nostr identity key, the same file
// heartwood-esp32 and lnurlcash-kit grade against, so all three derive one
// tree from one key.
func TestNostrSeedVectors(t *testing.T) {
	var vectors nostrSeedVectors
	loadVectorsStrict(t, "nostr-seed.json", &vectors)
	if vectors.Version != 1 {
		t.Fatalf("nostr-seed.json is format version %d; these tests read version 1", vectors.Version)
	}
	if !vectors.Extension {
		t.Fatal("nostr-seed.json no longer calls itself an extension, and this package documents it as one")
	}
	if vectors.Label != lnurlcash.NostrCashSeedLabel {
		t.Fatalf("label = %q, want %q", vectors.Label, lnurlcash.NostrCashSeedLabel)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range vectors.Cases {
		t.Run(fmt.Sprintf("%s under %.8s", c.Host, c.IdentityPubkey), func(t *testing.T) {
			if got, err := lnurlcash.SpendDomainOf(c.Host); err != nil || got != c.Domain {
				t.Errorf("spend domain of %s = %q (%v), want %q", c.Host, got, err, c.Domain)
			}
			identity := hex32(t, c.Identity)
			if got := secretKeyHex(t, identity); got != c.IdentityPubkey {
				t.Errorf("identity pubkey = %s, want %s", got, c.IdentityPubkey)
			}
			seed := lnurlcash.DeriveNostrCashSeed(identity)
			if got := hex.EncodeToString(seed[:]); got != c.Seed {
				t.Errorf("seed = %s, want %s", got, c.Seed)
			}
			root, err := lnurlcash.DeriveNostrServiceRoot(identity, c.Host)
			if err != nil {
				t.Fatal(err)
			}
			if got := lnurlcash.CashNodeToHex(root); got != c.ServiceRoot {
				t.Fatalf("service root = %s, want %s", got, c.ServiceRoot)
			}
			// and it is LUD-26's ordinary tree from that seed, unchanged
			cashRoot, err := lnurlcash.DeriveCashRoot(seed[:])
			if err != nil {
				t.Fatal(err)
			}
			if ordinary, err := lnurlcash.DeriveServiceRoot(cashRoot, c.Host); err != nil || ordinary != root {
				t.Errorf("not the service root from the seed: %v", err)
			}
			gradeAccounts(t, root, c.Accounts, c.Host, c.Domain)
		})
	}
}

// TestLnurlWalletCheckVector is an independent value from lnurl-wallet on the
// superseded purpose-0 tweak, from outside the conformance repo: a BIP39
// mnemonic (no passphrase) at mint.lnurlcash.com. It stays as a check on the
// read-only legacy derivation, which finds notes minted before LUD-26.
func TestLnurlWalletCheckVector(t *testing.T) {
	seed := bip39Seed(t, "dragon spell warfare girl patrol false erase surprise satisfy lucky curious ill")
	if got := hex.EncodeToString(seed); got != "1c77403f77e0c9c558fa00cdea65ec5c5b7eb9bd10880219b9f5d8fa259aad14a81e9ad409641fd61ba3024de788cd88a1f0a27f0ff0a1a8ae140bd17bc3ee5c" {
		t.Fatalf("seed = %s", got)
	}
	root, err := lnurlcash.DeriveCashRoot(seed)
	if err != nil {
		t.Fatal(err)
	}
	branch, err := lnurlcash.LegacyBranchNode(root, "mint.lnurlcash.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(branch.PrivateKey[:]); got != "ec94d2f4f89e8ea4f4335970e9a7781e30b4223eb405b070f9e3930afccbdc9b" {
		t.Errorf("branch private key = %s", got)
	}
	if got := hex.EncodeToString(branch.ChainCode[:]); got != "62ba198d1cf6f086f85f867aff7f8d6845a65dd93152df219f1815d1f707bc99" {
		t.Errorf("chain code = %s", got)
	}
	cx, err := lnurlcash.LegacyCx1Of(branch)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := lnurlcash.LegacyDeriveNotePubkey(cx, lnurlcash.LegacyPurposeWallet, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pk[:]); got != "be5f31ff0b2bc0329961bcb08722b3033ab77a8bb35c776236a15d35afd911ab" {
		t.Errorf("index-0 note pubkey = %s", got)
	}
	// and the pre-purpose scheme is a different key
	pre, err := lnurlcash.LegacyDeriveNotePubkey(cx, lnurlcash.LegacyPurposeNone, 0)
	if err != nil || pre == pk {
		t.Errorf("the pre-purpose scheme derived the purpose-0 key (%v)", err)
	}
}

// ---- spec-vectors.json: the luds repository's own published vectors ----

// gradeKeyPathSpend grades a spec vector's key_path_spend against this
// package's real functions and returns its ck1.
func gradeKeyPathSpend(t *testing.T, v map[string]any, sk [32]byte) string {
	t.Helper()
	q := hex32(t, jstr(t, v, "Q"))
	domain := jstr(t, v, "domain")
	if got := secretKeyHex(t, sk); got != jstr(t, v, "Q") {
		t.Fatalf("Q = %s, want %s", got, jstr(t, v, "Q"))
	}
	if got := lnurlcash.EncodeCp1(q); got != jstr(t, v, "cp1") {
		t.Errorf("cp1 = %s, want %s", got, jstr(t, v, "cp1"))
	}
	prevout, err := lnurlcash.SpendPrevout(domain)
	if err != nil || hex.EncodeToString(prevout[:]) != jstr(t, v, "prevout_txid") {
		t.Errorf("prevout = %x (%v), want %s", prevout, err, jstr(t, v, "prevout_txid"))
	}
	if got := "5120" + jstr(t, v, "Q"); got != jstr(t, v, "spent_script_pubkey") {
		t.Errorf("spent scriptPubKey is %s, not OP_1 <Q>", jstr(t, v, "spent_script_pubkey"))
	}
	sigMsg, err := lnurlcash.SpendSigMsg(q, domain, lnurlcash.KeyPathLocktime, lnurlcash.KeyPathSequence, nil)
	if err != nil || hex.EncodeToString(sigMsg) != jstr(t, v, "sigmsg") || len(sigMsg) != 174 {
		t.Errorf("SigMsg = %x (%v), want %s", sigMsg, err, jstr(t, v, "sigmsg"))
	}
	// every SigMsg field, in order, is exactly the whole SigMsg
	fields := jobj(t, v, "sigmsg_fields")
	var joined string
	for _, name := range []string{"hash_type", "nVersion", "nLockTime", "sha_prevouts", "sha_amounts", "sha_scriptpubkeys", "sha_sequences", "sha_outputs", "spend_type", "input_index"} {
		joined += jstr(t, fields, name)
	}
	if joined != jstr(t, v, "sigmsg") {
		t.Errorf("the SigMsg fields do not concatenate to the SigMsg")
	}
	sighash, err := lnurlcash.KeyPathSighash(q, domain)
	if err != nil || hex.EncodeToString(sighash[:]) != jstr(t, v, "sighash") {
		t.Errorf("sighash = %x (%v), want %s", sighash, err, jstr(t, v, "sighash"))
	}
	if jstr(t, v, "aux_rand") != strings.Repeat("00", 32) {
		t.Fatalf("aux_rand = %s, want all zero", jstr(t, v, "aux_rand"))
	}
	payload, err := lnurlcash.SignNoteOwnership(sk, domain)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(payload[32:]); got != jstr(t, v, "sig") {
		t.Errorf("signature = %s, want %s", got, jstr(t, v, "sig"))
	}
	// the canonical spend transaction, serialised here with its witness rather
	// than by the package: version, segwit marker and flag, one input spending
	// (prevout, 0) with an empty scriptSig and a final sequence, one empty
	// zero-value output, the witness [sig], locktime 0
	tx := "02000000" + "0001" + "01" + jstr(t, v, "prevout_txid") + "00000000" + "00" + "ffffffff" +
		"01" + "0000000000000000" + "00" + "01" + "40" + jstr(t, v, "sig") + "00000000"
	if tx != jstr(t, v, "spend_tx") {
		t.Errorf("spend transaction = %s, want %s", tx, jstr(t, v, "spend_tx"))
	}
	ck1 := jstr(t, v, "ck1")
	if got := lnurlcash.EncodeCk1(payload); got != ck1 {
		t.Errorf("ck1 = %s, want %s", got, ck1)
	}
	if id, err := lnurlcash.NoteIDOf(ck1); err != nil || id != jstr(t, v, "Q") {
		t.Errorf("ck1 is filed under %s (%v), want %s", id, err, jstr(t, v, "Q"))
	}
	if verified, err := lnurlcash.VerifySpend(ck1, domain); err != nil || verified.OutputKey != q || verified.Legacy {
		t.Errorf("VerifySpend = %+v (%v)", verified, err)
	}
	// "The same ck1 submitted to a SERVICE on any other domain fails"
	if _, err := lnurlcash.VerifySpend(ck1, "moneyer.dev"); err == nil {
		t.Error("the ck1 verified at another domain")
	}
	return ck1
}

// TestLUD25SpecVectors grades spec-vectors.json's lud25: LUD-25's own published
// test vectors, every value what the spec document itself publishes.
func TestLUD25SpecVectors(t *testing.T) {
	vectors := loadObject(t, "spec-vectors.json")
	v := jobj(t, vectors, "lud25")

	spend := jobj(t, v, "key_path_spend")
	ck1 := gradeKeyPathSpend(t, spend, hex32(t, jstr(t, spend, "sk")))
	spendDomain := jstr(t, spend, "domain")

	certificates := jobj(t, v, "certificates")
	mintSecret := hex32(t, jstr(t, certificates, "service_sk"))
	mintPubkey := hex.EncodeToString(publicKeyOf(t, mintSecret))
	if mintPubkey != jstr(t, certificates, "mintPubkey") {
		t.Fatalf("mint pubkey = %s, want %s", mintPubkey, jstr(t, certificates, "mintPubkey"))
	}
	q := jstr(t, certificates, "Q")
	domain := jstr(t, certificates, "domain")
	if q != jstr(t, spend, "Q") {
		t.Fatalf("the certificates are over %s, not the key-path note %s", q, jstr(t, spend, "Q"))
	}
	for _, cert := range jlist(t, certificates, "cases") {
		amount := jnum(t, cert, "amount_msat")
		at := fmt.Sprintf("%d msat", amount)
		if got, err := lnurlcash.NoteSignatureMessageForHash(q, domain, amount); err != nil || got != jstr(t, cert, "message") {
			t.Errorf("%s: message = %q (%v), want %q", at, got, err, jstr(t, cert, "message"))
		}
		digest, err := lnurlcash.NoteSignatureDigestForHash(q, domain, amount)
		if err != nil || hex.EncodeToString(digest) != jstr(t, cert, "digest") {
			t.Fatalf("%s: digest = %x (%v), want %s", at, digest, err, jstr(t, cert, "digest"))
		}
		signature := signCertificate(t, mintSecret, digest)
		if got := hex.EncodeToString(signature[:]); got != jstr(t, cert, "signature") {
			t.Errorf("%s: signature = %s, want %s", at, got, jstr(t, cert, "signature"))
		}
		cs1, err := lnurlcash.EncodeCs1WithAmount(amount, signature)
		if err != nil || cs1 != jstr(t, cert, "cs1") {
			t.Errorf("%s: cs1 = %s (%v), want %s", at, cs1, err, jstr(t, cert, "cs1"))
		}
		if !lnurlcash.VerifyNoteCertificate(q, domain, amount, cs1, mintPubkey) {
			t.Errorf("%s: the certificate does not verify", at)
		}
		if got := lnurlcash.VerifyNoteSignature(ck1, spendDomain, amount, cs1, mintPubkey); got != lnurlcash.CertifiedOverQ {
			t.Errorf("%s: a ck1 and its cs1 = %v", at, got)
		}
		if got := lnurlcash.VerifyNoteSignature(ck1, "moneyer.dev", amount, cs1, mintPubkey); got != lnurlcash.NotCertified {
			t.Errorf("%s: at another mint = %v", at, got)
		}
	}

	// a bearer note, from preimage to cw1 and its certificate
	b := jobj(t, v, "bearer_note")
	preimage := jstr(t, b, "preimage")
	h := sha256.Sum256(hexBytes(t, preimage, 32))
	if got := hex.EncodeToString(h[:]); got != jstr(t, b, "h") {
		t.Errorf("h = %s, want %s", got, jstr(t, b, "h"))
	}
	leaf := lnurlcash.BearerLeaf(h)
	if got := hex.EncodeToString(leaf); got != jstr(t, b, "leaf") {
		t.Errorf("leaf = %s, want %s", got, jstr(t, b, "leaf"))
	}
	leafHash := lnurlcash.TapLeafHash(leaf, lnurlcash.TapleafVersion)
	if got := hex.EncodeToString(leafHash[:]); got != jstr(t, b, "tapleaf_hash") {
		t.Errorf("tapleaf hash = %s, want %s", got, jstr(t, b, "tapleaf_hash"))
	}
	if got := hex.EncodeToString(lnurlcash.NumsKey[:]); got != jstr(t, b, "H") {
		t.Errorf("H = %s, want %s", got, jstr(t, b, "H"))
	}
	// t, independently: tagged_hash("TapTweak", H || tapleaf_hash)
	tag := sha256.Sum256([]byte("TapTweak"))
	tweak := sha256.Sum256(append(append(append(tag[:], tag[:]...), lnurlcash.NumsKey[:]...), leafHash[:]...))
	if got := hex.EncodeToString(tweak[:]); got != jstr(t, b, "tweak") {
		t.Errorf("t = %s, want %s", got, jstr(t, b, "tweak"))
	}
	note := lnurlcash.BearerNoteOf(h)
	bq := jstr(t, b, "Q")
	if got := hex.EncodeToString(note.OutputKey[:]); got != bq {
		t.Errorf("Q = %s, want %s", got, bq)
	}
	if got := hex.EncodeToString(note.ControlBlock[:]); got != jstr(t, b, "control_block") {
		t.Errorf("control block = %s, want %s", got, jstr(t, b, "control_block"))
	}
	cp1 := jstr(t, b, "cp1")
	if got := lnurlcash.EncodeCp1(note.OutputKey); got != cp1 {
		t.Errorf("cp1 = %s, want %s", got, cp1)
	}
	if got, err := lnurlcash.BearerNoteID(jstr(t, b, "h")); err != nil || got != bq {
		t.Errorf("bearer note id = %s (%v), want %s", got, err, bq)
	}
	cw1 := jstr(t, b, "cw1")
	if got, err := lnurlcash.BearerCw1(preimage); err != nil || got != cw1 {
		t.Errorf("cw1 = %s (%v), want %s", got, err, cw1)
	}
	// the preimage and the full cw1 are the same spend, and open Q at any
	// domain since the leaf checks no signature
	for _, spend := range []string{preimage, cw1} {
		for _, domain := range []string{"mint.example", "moneyer.dev"} {
			verified, err := lnurlcash.VerifySpend(spend, domain)
			if err != nil || hex.EncodeToString(verified.OutputKey[:]) != bq || verified.Legacy || verified.Unevaluated {
				t.Errorf("%.16s... at %s = %+v (%v)", spend, domain, verified, err)
			}
		}
		if id, err := lnurlcash.NoteIDOf(spend); err != nil || id != bq {
			t.Errorf("%.16s... is filed under %s (%v), want %s", spend, id, err, bq)
		}
	}
	if lookup, err := lnurlcash.NoteLookupOf(preimage); err != nil || lookup != jstr(t, b, "h") {
		t.Errorf("the preimage is looked up by %s (%v), want its h", lookup, err)
	}
	if lookup, err := lnurlcash.NoteLookupOf(cw1); err != nil || lookup != cp1 {
		t.Errorf("the cw1 is looked up by %s (%v), want its cp1", lookup, err)
	}

	cert := jobj(t, b, "certificate")
	amount := jnum(t, cert, "amount_msat")
	url := jstr(t, b, "note_url")
	if got, err := lnurlcash.NoteSignatureMessage(preimage, url, amount); err != nil || got != jstr(t, cert, "message") {
		t.Errorf("message from the preimage = %q (%v), want %q", got, err, jstr(t, cert, "message"))
	}
	digest, err := lnurlcash.NoteSignatureDigest(preimage, url, amount)
	if err != nil || hex.EncodeToString(digest) != jstr(t, cert, "digest") {
		t.Fatalf("digest = %x (%v), want %s", digest, err, jstr(t, cert, "digest"))
	}
	signature := signCertificate(t, mintSecret, digest)
	if got := hex.EncodeToString(signature[:]); got != jstr(t, cert, "signature") {
		t.Errorf("signature = %s, want %s", got, jstr(t, cert, "signature"))
	}
	requireLayout(t, signature)
	cs1 := jstr(t, cert, "cs1")
	if got, err := lnurlcash.EncodeCs1WithAmount(amount, signature); err != nil || got != cs1 {
		t.Errorf("cs1 = %s (%v), want %s", got, err, cs1)
	}
	noteDomain, err := lnurlcash.SpendDomainOf(url)
	if err != nil {
		t.Fatal(err)
	}
	for _, spend := range []string{preimage, cw1} {
		if got := lnurlcash.VerifyNoteSignature(spend, noteDomain, amount, cs1, mintPubkey); got != lnurlcash.CertifiedOverQ {
			t.Errorf("%.16s... and its cs1 = %v", spend, got)
		}
		// the spend opens Q anywhere, but the certificate names one mint
		if got := lnurlcash.VerifyNoteSignature(spend, "moneyer.dev", amount, cs1, mintPubkey); got != lnurlcash.NotCertified {
			t.Errorf("%.16s... at another mint = %v", spend, got)
		}
	}
	if got := lnurlcash.VerifyNoteSignatureHash(jstr(t, b, "h"), noteDomain, amount, cs1, mintPubkey); got != lnurlcash.CertifiedOverQ {
		t.Errorf("by h = %v", got)
	}
	// the certified note, in short form, checked from its URL alone
	if got, verdict := lnurlcash.VerifyNoteURL(url, mintPubkey); verdict != lnurlcash.CertifiedOverQ || got != amount {
		t.Errorf("the certified note URL = %d msat, %v", got, verdict)
	}
	if lnurlcash.ResolveNoteInput(url) == "" {
		t.Error("the certified note URL does not resolve as a note")
	}
}

// TestLUD26SpecVectors grades spec-vectors.json's lud26: LUD-26's own published
// test vectors, for both BIP-32 test seeds.
func TestLUD26SpecVectors(t *testing.T) {
	vectors := loadObject(t, "spec-vectors.json")
	v := jobj(t, vectors, "lud26")

	var serviceRoots []lnurlcash.CashNode
	for _, dv := range jlist(t, v, "derivation") {
		domain := jstr(t, dv, "domain")
		root, err := lnurlcash.DeriveCashRoot(hexBytes(t, jstr(t, dv, "seed"), len(jstr(t, dv, "seed"))/2))
		if err != nil {
			t.Fatal(err)
		}
		hashing, err := lnurlcash.DeriveCashChild(root, 0)
		if err != nil || hex.EncodeToString(hashing.PrivateKey[:]) != jstr(t, dv, "cashHashingKey") {
			t.Errorf("%s: hashing key = %x (%v), want %s", domain, hashing.PrivateKey, err, jstr(t, dv, "cashHashingKey"))
		}
		indices, err := lnurlcash.CashDomainIndices(root, domain)
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range dv["d"].([]any) {
			if float64(indices[i]) != want.(float64) {
				t.Errorf("%s: d%d = %d, want %v", domain, i+1, indices[i], want)
			}
		}
		serviceRoot, err := lnurlcash.DeriveServiceRoot(root, domain)
		if err != nil {
			t.Fatal(err)
		}

		grade := func(path lnurlcash.NotePath, note map[string]any, at string) {
			t.Helper()
			key, err := lnurlcash.DeriveNoteKey(serviceRoot, path)
			if err != nil {
				t.Errorf("%s: %v", at, err)
				return
			}
			if got := hex.EncodeToString(key.SecretKey[:]); got != jstr(t, note, "sk") {
				t.Errorf("%s: sk = %s, want %s", at, got, jstr(t, note, "sk"))
			}
			if got := hex.EncodeToString(key.Pubkey[:]); got != jstr(t, note, "pk") {
				t.Errorf("%s: pk = %s, want %s", at, got, jstr(t, note, "pk"))
			}
			if got := hex.EncodeToString(key.OutputKey[:]); got != jstr(t, note, "Q") {
				t.Errorf("%s: Q = %s, want %s", at, got, jstr(t, note, "Q"))
			}
			if got := lnurlcash.EncodeCp1(key.OutputKey); got != jstr(t, note, "cp1") {
				t.Errorf("%s: cp1 = %s, want %s", at, got, jstr(t, note, "cp1"))
			}
		}
		for _, account := range jlist(t, dv, "accounts") {
			a := uint32(jnum(t, account, "account"))
			for _, note := range jlist(t, jobj(t, account, "wallet"), "notes") {
				i := uint32(jnum(t, note, "i"))
				grade(lnurlcash.WalletNotePath(a, i), note, fmt.Sprintf("%s %d'/0/%d", domain, a, i))
			}
			for _, note := range jlist(t, jobj(t, account, "change"), "notes") {
				i := uint32(jnum(t, note, "i"))
				grade(lnurlcash.ChangeNotePath(a, i), note, fmt.Sprintf("%s %d'/1/%d", domain, a, i))
			}
			for _, share := range jlist(t, account, "shareable") {
				n := uint32(jnum(t, share, "share"))
				at := fmt.Sprintf("%s %d'/2/%d'", domain, a, n)
				node, err := lnurlcash.DeriveShareNode(serviceRoot, a, n)
				if err != nil {
					t.Fatalf("%s: %v", at, err)
				}
				if got := hex.EncodeToString(node.PrivateKey[:]); got != jstr(t, share, "p") {
					t.Errorf("%s: p = %s, want %s", at, got, jstr(t, share, "p"))
				}
				if got := hex.EncodeToString(node.ChainCode[:]); got != jstr(t, share, "chaincode") {
					t.Errorf("%s: chaincode = %s, want %s", at, got, jstr(t, share, "chaincode"))
				}
				cx1, err := lnurlcash.CashNodeToCx1(node)
				if err != nil {
					t.Fatal(err)
				}
				if got := hex.EncodeToString(cx1.Pubkey[:]); got != jstr(t, share, "P") {
					t.Errorf("%s: P = %s, want %s", at, got, jstr(t, share, "P"))
				}
				if got := lnurlcash.EncodeCx1(cx1); got != jstr(t, share, "cx1") {
					t.Errorf("%s: cx1 = %s, want %s", at, got, jstr(t, share, "cx1"))
				}
				watched, err := lnurlcash.DecodeCx1(jstr(t, share, "cx1"))
				if err != nil || watched != cx1 {
					t.Fatalf("%s: cx1 does not decode: %v", at, err)
				}
				for _, note := range jlist(t, share, "notes") {
					i := uint32(jnum(t, note, "i"))
					grade(lnurlcash.ShareNotePath(a, n, i), note, fmt.Sprintf("%s/%d", at, i))
					pubkey, err := lnurlcash.DeriveNotePubkey(watched, i)
					if err != nil || hex.EncodeToString(pubkey[:]) != jstr(t, note, "Q") {
						t.Errorf("%s/%d: CKDpub = %x (%v), want %s", at, i, pubkey, err, jstr(t, note, "Q"))
					}
				}
			}
		}
		serviceRoots = append(serviceRoots, serviceRoot)
	}
	if len(serviceRoots) < 2 {
		t.Fatalf("%d derivations; both BIP-32 test seeds are needed", len(serviceRoots))
	}

	// a key-path spend of an odd-y note: the signer negates the key
	spend := jobj(t, v, "key_path_spend")
	first := jlist(t, jobj(t, jlist(t, jlist(t, v, "derivation")[0], "accounts")[0], "wallet"), "notes")[0]
	if jstr(t, spend, "path") != jstr(t, first, "path") {
		t.Errorf("the spend is at %s, not the first wallet note %s", jstr(t, spend, "path"), jstr(t, first, "path"))
	}
	key, err := lnurlcash.DeriveNoteKey(serviceRoots[0], lnurlcash.WalletNotePath(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key.SecretKey[:]) != jstr(t, spend, "sk") || hex.EncodeToString(key.Pubkey[:]) != jstr(t, spend, "pk") {
		t.Errorf("the spend's key is %x / %x, want %s / %s", key.SecretKey, key.Pubkey, jstr(t, spend, "sk"), jstr(t, spend, "pk"))
	}
	if key.Pubkey[0] != 0x03 {
		t.Error("the vector's note has odd y")
	}
	var scalar secp256k1.ModNScalar
	scalar.SetBytes(&key.SecretKey)
	scalar.Negate()
	negated := scalar.Bytes()
	if got := hex.EncodeToString(negated[:]); got != jstr(t, spend, "signing_sk") {
		t.Errorf("signing_sk = %s, want %s", got, jstr(t, spend, "signing_sk"))
	}
	gradeKeyPathSpend(t, spend, key.SecretKey)

	// register share 0, update to share 1, unregister with share 1
	r := jobj(t, v, "registration")
	domain, username := jstr(t, r, "domain"), jstr(t, r, "username")
	second := jlist(t, v, "derivation")[1]
	if domain != jstr(t, second, "domain") {
		t.Fatalf("the registration is at %s, not %s", domain, jstr(t, second, "domain"))
	}
	shares := jlist(t, jlist(t, second, "accounts")[0], "shareable")
	old, err := lnurlcash.DeriveShareNode(serviceRoots[1], 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := lnurlcash.DeriveShareNode(serviceRoots[1], 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	cx1, newCx1 := jstr(t, r, "cx1"), jstr(t, r, "new_cx1")
	if cx1 != jstr(t, shares[0], "cx1") || newCx1 != jstr(t, shares[1], "cx1") {
		t.Fatal("the registration is not for shares 0 and 1")
	}
	update := jobj(t, r, "update")
	for _, c := range []struct {
		proof     map[string]any
		action    string
		bound     string
		signer    lnurlcash.CashNode
		signerCx1 string
		sigKey    string
	}{
		{jobj(t, r, "register"), "register", cx1, old, cx1, "sig"},
		{jobj(t, update, "sig"), "update", newCx1, old, cx1, "sig"},
		{jobj(t, update, "newsig"), "register", newCx1, newer, newCx1, "sig"},
		{jobj(t, r, "unregister"), "unregister", "", newer, newCx1, "sig"},
	} {
		at := c.action
		if got, err := lnurlcash.AddressProofMessage(c.action, domain, username, c.bound); err != nil || got != jstr(t, c.proof, "message") {
			t.Errorf("%s: message = %q (%v), want %q", at, got, err, jstr(t, c.proof, "message"))
		}
		if got, err := lnurlcash.AddressProofDigest(c.action, domain, username, c.bound); err != nil || hex.EncodeToString(got) != jstr(t, c.proof, "digest") {
			t.Errorf("%s: digest = %x (%v), want %s", at, got, err, jstr(t, c.proof, "digest"))
		}
		signature, err := lnurlcash.SignAddressProof(c.signer.PrivateKey, c.action, domain, username, c.bound)
		if err != nil || hex.EncodeToString(signature[:]) != jstr(t, c.proof, c.sigKey) {
			t.Errorf("%s: sig = %x (%v), want %s", at, signature, err, jstr(t, c.proof, c.sigKey))
		}
		if !lnurlcash.VerifyAddressProof(c.signerCx1, signature[:], c.action, domain, username, c.bound) {
			t.Errorf("%s: the proof does not verify", at)
		}
	}
}
