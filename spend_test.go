package lnurlcash_test

// spends.json: what opens a note, graded field by field. Bearer notes of both
// parities from preimage to cw1, one key's ck1 at several mints and the
// cross-mint spends that must fail, a three-leaf script tree, a CHECKSIG
// leaf's script-path sighash, the leaf and time rules, and the malformed
// values that must name no note. Decoded strictly, like the other vector
// files: a field nobody grades fails here until somebody does.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	lnurlcash "github.com/lnurlcash/lnurlcash-go"
)

type spendVectors struct {
	Version     int    `json:"version"`
	Spec        string `json:"spec"`
	Description string `json:"description"`
	Conventions struct {
		Domain                    string `json:"domain"`
		CanonicalSpendTransaction string `json:"canonicalSpendTransaction"`
		SigMsg                    string `json:"sigMsg"`
		Sighash                   string `json:"sighash"`
		KeyPath                   string `json:"keyPath"`
		Cw1Payload                string `json:"cw1Payload"`
		LeafPolicy                struct {
			LeafVersion string            `json:"leafVersion"`
			OpSuccess   []json.RawMessage `json:"opSuccess"`
			Scan        string            `json:"scan"`
		} `json:"leafPolicy"`
		TimeClaims struct {
			LocktimeThreshold   int64  `json:"locktimeThreshold"`
			Locktime            string `json:"locktime"`
			SequenceDisableFlag int64  `json:"sequenceDisableFlag"`
			SequenceTypeFlag    int64  `json:"sequenceTypeFlag"`
			SequenceValueMask   int64  `json:"sequenceValueMask"`
			GranularitySeconds  int64  `json:"granularitySeconds"`
			Sequence            string `json:"sequence"`
		} `json:"timeClaims"`
	} `json:"conventions"`
	Nums    string `json:"nums"`
	Bearers []struct {
		Name         string `json:"name"`
		Preimage     string `json:"preimage"`
		H            string `json:"h"`
		Leaf         string `json:"leaf"`
		TapleafHash  string `json:"tapleafHash"`
		Tweak        string `json:"tweak"`
		Q            string `json:"Q"`
		Parity       int    `json:"parity"`
		ControlBlock string `json:"controlBlock"`
		Cp1          string `json:"cp1"`
		Cw1          string `json:"cw1"`
	} `json:"bearers"`
	KeyPath struct {
		SecretKey string `json:"secretKey"`
		Q         string `json:"Q"`
		Cp1       string `json:"cp1"`
		Spends    []struct {
			Domain           string `json:"domain"`
			NormalisedDomain string `json:"normalisedDomain"`
			PrevoutTxid      string `json:"prevoutTxid"`
			Sighash          string `json:"sighash"`
			Signature        string `json:"signature"`
			Ck1              string `json:"ck1"`
		} `json:"spends"`
		CrossDomain []struct {
			SignedFor  string `json:"signedFor"`
			VerifiedAt string `json:"verifiedAt"`
			Valid      bool   `json:"valid"`
			Why        string `json:"why"`
		} `json:"crossDomain"`
	} `json:"keyPath"`
	Domains []struct {
		URL    string `json:"url"`
		Domain string `json:"domain"`
	} `json:"domains"`
	Tree struct {
		InternalSecretKey string `json:"internalSecretKey"`
		InternalKey       string `json:"internalKey"`
		Shape             string `json:"shape"`
		MerkleRoot        string `json:"merkleRoot"`
		Tweak             string `json:"tweak"`
		Q                 string `json:"Q"`
		Parity            int    `json:"parity"`
		Cp1               string `json:"cp1"`
		Leaves            []struct {
			Version      int      `json:"version"`
			Script       string   `json:"script"`
			TapleafHash  string   `json:"tapleafHash"`
			ControlBlock string   `json:"controlBlock"`
			Witness      []string `json:"witness"`
			Cw1          string   `json:"cw1"`
			Verdict      string   `json:"verdict"`
			Reason       *string  `json:"reason"`
		} `json:"leaves"`
		KeyPath struct {
			Domain           string `json:"domain"`
			TweakedSecretKey string `json:"tweakedSecretKey"`
			Sighash          string `json:"sighash"`
			Signature        string `json:"signature"`
			Ck1              string `json:"ck1"`
		} `json:"keyPath"`
	} `json:"tree"`
	Checksig struct {
		SecretKey    string `json:"secretKey"`
		Pubkey       string `json:"pubkey"`
		Leaf         string `json:"leaf"`
		ControlBlock string `json:"controlBlock"`
		Q            string `json:"Q"`
		Cp1          string `json:"cp1"`
		Domain       string `json:"domain"`
		Spends       []struct {
			Locktime  uint32 `json:"locktime"`
			Sequence  uint32 `json:"sequence"`
			SigMsg    string `json:"sigMsg"`
			Sighash   string `json:"sighash"`
			Signature string `json:"signature"`
			Cw1       string `json:"cw1"`
		} `json:"spends"`
	} `json:"checksig"`
	TimeClaims []struct {
		Name     string `json:"name"`
		Locktime uint32 `json:"locktime"`
		Sequence uint32 `json:"sequence"`
		Now      int64  `json:"now"`
		LockedAt int64  `json:"lockedAt"`
		Verdict  string `json:"verdict"`
		Why      string `json:"why"`
	} `json:"timeClaims"`
	LeafPolicy []struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
		Script  string `json:"script"`
		Verdict string `json:"verdict"`
		Why     string `json:"why"`
	} `json:"leafPolicy"`
	MalformedCw1 []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Why   string `json:"why"`
	} `json:"malformedCw1"`
	InvalidCp1 []struct {
		X   string `json:"x"`
		Cp1 string `json:"cp1"`
		Why string `json:"why"`
	} `json:"invalidCp1"`
	ShortForms []struct {
		Q       string `json:"Q"`
		Cp1Slot struct {
			Hex    string `json:"hex"`
			SameAs string `json:"sameAs"`
		} `json:"cp1Slot"`
		K1Slot struct {
			Hex    string `json:"hex"`
			SameAs string `json:"sameAs"`
		} `json:"k1Slot"`
	} `json:"shortForms"`
}

func loadSpends(t *testing.T) spendVectors {
	t.Helper()
	var vectors spendVectors
	loadVectorsStrict(t, "spends.json", &vectors)
	if vectors.Version != 1 {
		t.Fatalf("spends.json is format version %d; these tests read version 1", vectors.Version)
	}
	return vectors
}

func hexOf(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("vector value %q is not hex", value)
	}
	return raw
}

func taggedHashOf(tag string, parts ...[]byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func TestSpendConventions(t *testing.T) {
	v := loadSpends(t)
	if got := hex.EncodeToString(lnurlcash.NumsKey[:]); got != v.Nums {
		t.Errorf("NUMS key = %s, want %s", got, v.Nums)
	}
	claims := v.Conventions.TimeClaims
	if claims.LocktimeThreshold != 500_000_000 || claims.SequenceDisableFlag != 1<<31 || claims.SequenceTypeFlag != 1<<22 ||
		claims.SequenceValueMask != 0xffff || claims.GranularitySeconds != 512 {
		t.Errorf("the time rules have moved: %+v", claims)
	}
	// every OP_SUCCESSx, and nothing else, is refused as a leaf's only opcode
	success := map[int]bool{}
	for _, raw := range v.Conventions.LeafPolicy.OpSuccess {
		var single int
		var run string
		switch {
		case json.Unmarshal(raw, &single) == nil:
			success[single] = true
		case json.Unmarshal(raw, &run) == nil:
			var from, to int
			if _, err := fmt.Sscanf(run, "%d-%d", &from, &to); err != nil {
				t.Fatalf("opSuccess %q is not a range", run)
			}
			for op := from; op <= to; op++ {
				success[op] = true
			}
		default:
			t.Fatalf("opSuccess entry %s is neither a number nor a range", raw)
		}
	}
	for op := 0; op < 256; op++ {
		// pushes consume what follows them, so each opcode stands alone
		if op >= 0x01 && op <= 0x4e {
			continue
		}
		err := lnurlcash.CheckLeafPolicy(lnurlcash.TapleafVersion, []byte{byte(op)})
		if refused := err != nil; refused != success[op] {
			t.Errorf("opcode %d refused = %v, want %v", op, refused, success[op])
		}
	}
}

func TestBearerNoteVectors(t *testing.T) {
	v := loadSpends(t)
	parities := map[int]bool{}
	for _, b := range v.Bearers {
		parities[b.Parity] = true
		t.Run(b.Name, func(t *testing.T) {
			preimage := hexOf(t, b.Preimage)
			h := sha256.Sum256(preimage)
			if got := hex.EncodeToString(h[:]); got != b.H {
				t.Errorf("h = %s, want %s", got, b.H)
			}
			leaf := lnurlcash.BearerLeaf(h)
			if got := hex.EncodeToString(leaf); got != b.Leaf {
				t.Errorf("leaf = %s, want %s", got, b.Leaf)
			}
			leafHash := lnurlcash.TapLeafHash(leaf, lnurlcash.TapleafVersion)
			if got := hex.EncodeToString(leafHash[:]); got != b.TapleafHash {
				t.Errorf("tapleaf hash = %s, want %s", got, b.TapleafHash)
			}
			if got := hex.EncodeToString(taggedHashOf("TapTweak", lnurlcash.NumsKey[:], leafHash[:])); got != b.Tweak {
				t.Errorf("tweak = %s, want %s", got, b.Tweak)
			}
			q, oddY, err := lnurlcash.TaprootTweak(lnurlcash.NumsKey, leafHash[:])
			if err != nil || hex.EncodeToString(q[:]) != b.Q || oddY != (b.Parity == 1) {
				t.Errorf("tweak(H) = %x odd %v (%v), want %s parity %d", q, oddY, err, b.Q, b.Parity)
			}
			note := lnurlcash.BearerNoteOf(h)
			if got := hex.EncodeToString(note.ControlBlock[:]); got != b.ControlBlock {
				t.Errorf("control block = %s, want %s", got, b.ControlBlock)
			}
			if got := lnurlcash.EncodeCp1(note.OutputKey); got != b.Cp1 {
				t.Errorf("cp1 = %s, want %s", got, b.Cp1)
			}
			if got, err := lnurlcash.BearerCw1(b.Preimage); err != nil || got != b.Cw1 {
				t.Errorf("cw1 = %s (%v), want %s", got, err, b.Cw1)
			}
			decoded, err := lnurlcash.DecodeCw1(b.Cw1)
			if err != nil || decoded.Locktime != 0 || decoded.Sequence != 0xffffffff ||
				!bytes.Equal(decoded.Script, leaf) || !bytes.Equal(decoded.ControlBlock, note.ControlBlock[:]) ||
				len(decoded.Witness) != 1 || !bytes.Equal(decoded.Witness[0], preimage) {
				t.Errorf("cw1 decodes to %+v (%v)", decoded, err)
			}
			if q, err := lnurlcash.OutputKeyOfCw1(b.Cw1); err != nil || hex.EncodeToString(q[:]) != b.Q {
				t.Errorf("Q of the cw1 = %x (%v), want %s", q, err, b.Q)
			}
			if id, err := lnurlcash.BearerNoteID(b.H); err != nil || id != b.Q {
				t.Errorf("bearer note id = %s (%v), want %s", id, err, b.Q)
			}
			// one note, one spend, three spellings, no signature and so no mint
			for _, spend := range []string{b.Preimage, strings.ToUpper(b.Preimage), b.Cw1} {
				verified, err := lnurlcash.VerifySpend(spend, "any.example")
				if err != nil || hex.EncodeToString(verified.OutputKey[:]) != b.Q || verified.Legacy || verified.Unevaluated {
					t.Errorf("%.12s... opens %+v (%v), want %s", spend, verified, err, b.Q)
				}
			}
		})
	}
	if !parities[0] || !parities[1] {
		t.Errorf("the bearer notes cover parities %v; both are needed", parities)
	}
}

func TestKeyPathSpendVectors(t *testing.T) {
	v := loadSpends(t)
	key := hex32(t, v.KeyPath.SecretKey)
	q := hex32(t, v.KeyPath.Q)
	if got := hex.EncodeToString(publicKeyOf(t, key)[1:]); got != v.KeyPath.Q {
		t.Fatalf("Q = %s, want %s", got, v.KeyPath.Q)
	}
	if got := lnurlcash.EncodeCp1(q); got != v.KeyPath.Cp1 {
		t.Errorf("cp1 = %s, want %s", got, v.KeyPath.Cp1)
	}
	byDomain := map[string]string{}
	for _, spend := range v.KeyPath.Spends {
		byDomain[strings.ToLower(spend.Domain)] = spend.Ck1
		t.Run(spend.Domain, func(t *testing.T) {
			if got, err := lnurlcash.SpendDomainOf(spend.Domain); err != nil || got != spend.NormalisedDomain {
				t.Errorf("domain = %q (%v), want %q", got, err, spend.NormalisedDomain)
			}
			if prevout, err := lnurlcash.SpendPrevout(spend.Domain); err != nil || hex.EncodeToString(prevout[:]) != spend.PrevoutTxid {
				t.Errorf("prevout = %x (%v), want %s", prevout, err, spend.PrevoutTxid)
			}
			if sighash, err := lnurlcash.KeyPathSighash(q, spend.Domain); err != nil || hex.EncodeToString(sighash[:]) != spend.Sighash {
				t.Errorf("sighash = %x (%v), want %s", sighash, err, spend.Sighash)
			}
			payload, err := lnurlcash.SignNoteOwnership(key, spend.Domain)
			if err != nil || hex.EncodeToString(payload[32:]) != spend.Signature || lnurlcash.EncodeCk1(payload) != spend.Ck1 {
				t.Errorf("signed %x (%v), want %s", payload[32:], err, spend.Signature)
			}
			if verified, err := lnurlcash.VerifySpend(spend.Ck1, spend.Domain); err != nil || verified.OutputKey != q || verified.Legacy {
				t.Errorf("VerifySpend = %+v (%v)", verified, err)
			}
		})
	}
	for _, c := range v.KeyPath.CrossDomain {
		ck1, ok := byDomain[strings.ToLower(c.SignedFor)]
		if !ok {
			t.Fatalf("no ck1 signed for %s", c.SignedFor)
		}
		_, err := lnurlcash.VerifySpend(ck1, c.VerifiedAt)
		if (err == nil) != c.Valid {
			t.Errorf("signed for %s, verified at %s: %v, want valid %v (%s)", c.SignedFor, c.VerifiedAt, err, c.Valid, c.Why)
		}
	}
	for _, d := range v.Domains {
		if got, err := lnurlcash.SpendDomainOf(d.URL); err != nil || got != d.Domain {
			t.Errorf("domain of %s = %q (%v), want %q", d.URL, got, err, d.Domain)
		}
	}
}

func TestScriptTreeVectors(t *testing.T) {
	tree := loadSpends(t).Tree
	internal := hex32(t, tree.InternalKey)
	if got := hex.EncodeToString(publicKeyOf(t, hex32(t, tree.InternalSecretKey))[1:]); got != tree.InternalKey {
		t.Errorf("internal key = %s, want %s", got, tree.InternalKey)
	}
	if tree.Shape != "root = branch(branch(leaves[0], leaves[1]), leaves[2])" || len(tree.Leaves) != 3 {
		t.Fatalf("the tree has changed shape: %s", tree.Shape)
	}
	// the root, independently: TapBranch sorts its two children
	branch := func(a, b []byte) []byte {
		if bytes.Compare(a, b) > 0 {
			a, b = b, a
		}
		return taggedHashOf("TapBranch", a, b)
	}
	var leafHashes [][]byte
	for _, leaf := range tree.Leaves {
		leafHash := lnurlcash.TapLeafHash(hexOf(t, leaf.Script), byte(leaf.Version))
		if got := hex.EncodeToString(leafHash[:]); got != leaf.TapleafHash {
			t.Errorf("tapleaf hash = %s, want %s", got, leaf.TapleafHash)
		}
		leafHashes = append(leafHashes, leafHash[:])
	}
	root := branch(branch(leafHashes[0], leafHashes[1]), leafHashes[2])
	if got := hex.EncodeToString(root); got != tree.MerkleRoot {
		t.Errorf("merkle root = %s, want %s", got, tree.MerkleRoot)
	}
	if got := hex.EncodeToString(taggedHashOf("TapTweak", internal[:], root)); got != tree.Tweak {
		t.Errorf("tweak = %s, want %s", got, tree.Tweak)
	}
	q, oddY, err := lnurlcash.TaprootTweak(internal, root)
	if err != nil || hex.EncodeToString(q[:]) != tree.Q || oddY != (tree.Parity == 1) {
		t.Errorf("Q = %x odd %v (%v), want %s parity %d", q, oddY, err, tree.Q, tree.Parity)
	}
	if got := lnurlcash.EncodeCp1(q); got != tree.Cp1 {
		t.Errorf("cp1 = %s, want %s", got, tree.Cp1)
	}

	for i, leaf := range tree.Leaves {
		t.Run(fmt.Sprintf("leaf %d", i), func(t *testing.T) {
			var witness [][]byte
			for _, item := range leaf.Witness {
				witness = append(witness, hexOf(t, item))
			}
			encoded, err := lnurlcash.EncodeCw1(lnurlcash.Cw1{
				Locktime: 0, Sequence: 0xffffffff,
				Script: hexOf(t, leaf.Script), ControlBlock: hexOf(t, leaf.ControlBlock), Witness: witness,
			})
			if err != nil || encoded != leaf.Cw1 {
				t.Errorf("cw1 = %s (%v), want %s", encoded, err, leaf.Cw1)
			}
			// every leaf commits to the one Q, whatever the leaf rules say of it
			if got, err := lnurlcash.OutputKeyOf(hexOf(t, leaf.Script), hexOf(t, leaf.ControlBlock)); err != nil || got != q {
				t.Errorf("Q from the control block = %x (%v), want %x", got, err, q)
			}
			verified, err := lnurlcash.VerifySpend(leaf.Cw1, tree.KeyPath.Domain)
			switch leaf.Verdict {
			case "accept":
				if err != nil || verified.OutputKey != q {
					t.Errorf("an accepted leaf = %+v (%v)", verified, err)
				}
			case "reject":
				if err == nil {
					t.Errorf("a leaf refused for %v was accepted", leaf.Reason)
				}
			default:
				t.Fatalf("verdict %q", leaf.Verdict)
			}
		})
	}

	kp := tree.KeyPath
	if got := hex.EncodeToString(publicKeyOf(t, hex32(t, kp.TweakedSecretKey))[1:]); got != tree.Q {
		t.Errorf("the tweaked secret key's own key = %s, want Q %s", got, tree.Q)
	}
	if sighash, err := lnurlcash.KeyPathSighash(q, kp.Domain); err != nil || hex.EncodeToString(sighash[:]) != kp.Sighash {
		t.Errorf("key-path sighash = %x (%v), want %s", sighash, err, kp.Sighash)
	}
	payload, err := lnurlcash.SignNoteOwnership(hex32(t, kp.TweakedSecretKey), kp.Domain)
	if err != nil || hex.EncodeToString(payload[32:]) != kp.Signature || lnurlcash.EncodeCk1(payload) != kp.Ck1 {
		t.Errorf("the key path signs %x (%v), want %s", payload[32:], err, kp.Signature)
	}
	if verified, err := lnurlcash.VerifySpend(kp.Ck1, kp.Domain); err != nil || verified.OutputKey != q {
		t.Errorf("the tree's key path = %+v (%v)", verified, err)
	}
}

func TestChecksigLeafVectors(t *testing.T) {
	c := loadSpends(t).Checksig
	pubkey := hex32(t, c.Pubkey)
	if got := hex.EncodeToString(publicKeyOf(t, hex32(t, c.SecretKey))[1:]); got != c.Pubkey {
		t.Errorf("pubkey = %s, want %s", got, c.Pubkey)
	}
	leaf := hexOf(t, c.Leaf)
	if want := append(append([]byte{0x20}, pubkey[:]...), 0xac); !bytes.Equal(leaf, want) {
		t.Fatalf("the leaf is not <pubkey> OP_CHECKSIG: %s", c.Leaf)
	}
	q, err := lnurlcash.OutputKeyOf(leaf, hexOf(t, c.ControlBlock))
	if err != nil || hex.EncodeToString(q[:]) != c.Q {
		t.Fatalf("Q = %x (%v), want %s", q, err, c.Q)
	}
	if got := lnurlcash.EncodeCp1(q); got != c.Cp1 {
		t.Errorf("cp1 = %s, want %s", got, c.Cp1)
	}
	schnorrKey, err := schnorr.ParsePubKey(pubkey[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, spend := range c.Spends {
		t.Run(fmt.Sprintf("locktime %d sequence %d", spend.Locktime, spend.Sequence), func(t *testing.T) {
			sigMsg, err := lnurlcash.SpendSigMsg(q, c.Domain, spend.Locktime, spend.Sequence, leaf)
			if err != nil || hex.EncodeToString(sigMsg) != spend.SigMsg {
				t.Errorf("SigMsg = %x (%v), want %s", sigMsg, err, spend.SigMsg)
			}
			if len(sigMsg) != 211 {
				t.Errorf("a script-path SigMsg is %d bytes, want 211", len(sigMsg))
			}
			sighash, err := lnurlcash.ScriptPathSighash(q, c.Domain, leaf, spend.Locktime, spend.Sequence)
			if err != nil || hex.EncodeToString(sighash[:]) != spend.Sighash {
				t.Errorf("sighash = %x (%v), want %s", sighash, err, spend.Sighash)
			}
			signature, err := schnorr.ParseSignature(hexOf(t, spend.Signature))
			if err != nil || !signature.Verify(sighash[:], schnorrKey) {
				t.Errorf("the leaf's signature does not verify over the sighash: %v", err)
			}
			decoded, err := lnurlcash.DecodeCw1(spend.Cw1)
			if err != nil || decoded.Locktime != spend.Locktime || decoded.Sequence != spend.Sequence ||
				!bytes.Equal(decoded.Script, leaf) || len(decoded.Witness) != 1 || hex.EncodeToString(decoded.Witness[0]) != spend.Signature {
				t.Errorf("cw1 decodes to %+v (%v)", decoded, err)
			}
			if encoded, err := lnurlcash.EncodeCw1(decoded); err != nil || encoded != spend.Cw1 {
				t.Errorf("cw1 round trip = %s (%v)", encoded, err)
			}
			// a CHECKSIG leaf is not one this package runs: structure and Q only
			verified, err := lnurlcash.VerifySpend(spend.Cw1, c.Domain)
			if err != nil || verified.OutputKey != q || !verified.Unevaluated {
				t.Errorf("VerifySpend = %+v (%v), want Q, unevaluated", verified, err)
			}
		})
	}
}

func TestTimeClaimVectors(t *testing.T) {
	v := loadSpends(t)
	if len(v.TimeClaims) == 0 {
		t.Fatal("no time claims")
	}
	for _, c := range v.TimeClaims {
		err := lnurlcash.CheckTimeClaim(c.Locktime, c.Sequence, c.Now, c.LockedAt)
		switch c.Verdict {
		case "accept":
			if err != nil {
				t.Errorf("%s: refused (%v), but %s", c.Name, err, c.Why)
			}
		case "reject":
			if err == nil {
				t.Errorf("%s: accepted, but %s", c.Name, c.Why)
			}
		default:
			t.Fatalf("%s: verdict %q", c.Name, c.Verdict)
		}
	}
}

func TestLeafPolicyVectors(t *testing.T) {
	v := loadSpends(t)
	for _, c := range v.LeafPolicy {
		err := lnurlcash.CheckLeafPolicy(byte(c.Version), hexOf(t, c.Script))
		switch c.Verdict {
		case "allowed":
			if err != nil {
				t.Errorf("%s: refused (%v), but %s", c.Name, err, c.Why)
			}
		case "refused":
			if err == nil {
				t.Errorf("%s: allowed, but %s", c.Name, c.Why)
			}
		default:
			t.Fatalf("%s: verdict %q", c.Name, c.Verdict)
		}
	}
}

func TestMalformedValuesNameNoNote(t *testing.T) {
	v := loadSpends(t)
	if len(v.MalformedCw1) == 0 || len(v.InvalidCp1) == 0 {
		t.Fatal("no malformed values")
	}
	for _, c := range v.MalformedCw1 {
		if _, err := lnurlcash.OutputKeyOfCw1(c.Value); err == nil {
			t.Errorf("%s: a Q came out of it, but %s", c.Name, c.Why)
		}
		if _, err := lnurlcash.DecodeSpend(c.Value); err == nil {
			t.Errorf("%s: decoded as a spend, but %s", c.Name, c.Why)
		}
		if _, err := lnurlcash.NoteIDOf(c.Value); err == nil {
			t.Errorf("%s: named a note, but %s", c.Name, c.Why)
		}
	}
	for _, c := range v.InvalidCp1 {
		if got := lnurlcash.EncodeCp1(hex32(t, c.X)); got != c.Cp1 {
			t.Errorf("cp1 of %s = %s, want %s", c.X, got, c.Cp1)
		}
		if _, err := lnurlcash.DecodeCp1(c.Cp1); err == nil || lnurlcash.IsCp1(c.Cp1) {
			t.Errorf("%s decoded, but %s", c.Cp1, c.Why)
		}
		if lnurlcash.BuildNoteInfoURLByHash("https://mint.example/w", c.Cp1) != "" {
			t.Errorf("built a lookup for %s, but %s", c.Cp1, c.Why)
		}
	}
}

func TestShortFormVectors(t *testing.T) {
	v := loadSpends(t)
	for _, c := range v.ShortForms {
		// the cp1 slot: hex h and its cp1 name one note
		if id, err := lnurlcash.BearerNoteID(c.Cp1Slot.Hex); err != nil || id != c.Q {
			t.Errorf("h %s names %s (%v), want %s", c.Cp1Slot.Hex, id, err, c.Q)
		}
		if key, err := lnurlcash.DecodeCp1(c.Cp1Slot.SameAs); err != nil || hex.EncodeToString(key[:]) != c.Q {
			t.Errorf("%s names %x (%v), want %s", c.Cp1Slot.SameAs, key, err, c.Q)
		}
		// the k1 slot: the preimage and its cw1 are one spend
		if got, err := lnurlcash.BearerCw1(c.K1Slot.Hex); err != nil || got != c.K1Slot.SameAs {
			t.Errorf("the cw1 of %s = %s (%v), want %s", c.K1Slot.Hex, got, err, c.K1Slot.SameAs)
		}
		for _, spend := range []string{c.K1Slot.Hex, c.K1Slot.SameAs} {
			if id, err := lnurlcash.NoteIDOf(spend); err != nil || id != c.Q {
				t.Errorf("%.12s... opens %s (%v), want %s", spend, id, err, c.Q)
			}
		}
		// either spelling of an output goes to the mint as p1
		for _, output := range []string{c.Cp1Slot.Hex, c.Cp1Slot.SameAs} {
			request, err := lnurlcash.RotateRequestWithHash("https://mint.example/w/cb", c.K1Slot.Hex, output)
			if err != nil || queryOf(t, request.URL).Get("p1") != output {
				t.Errorf("a rotate to %.12s... = %s (%v)", output, request.URL, err)
			}
		}
	}
}

// DecodeCw1 and the spend verification never panic, and a cw1 that decodes
// re-encodes to itself.
func FuzzSpendDecoders(f *testing.F) {
	for _, seed := range []string{"", "cw1", "cw1qqqqqq8llllsfyw4xk", strings.Repeat("0", 64), "ck1qqqqqq"} {
		f.Add(seed)
	}
	if cw1, err := lnurlcash.BearerCw1(strings.Repeat("11", 32)); err == nil {
		f.Add(cw1)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if spend, err := lnurlcash.DecodeCw1(value); err == nil {
			if encoded, err := lnurlcash.EncodeCw1(spend); err != nil || encoded != strings.ToLower(strings.TrimSpace(value)) {
				t.Errorf("cw1 %q re-encodes to %q (%v)", value, encoded, err)
			}
		}
		_, _ = lnurlcash.DecodeSpend(value)
		_, _ = lnurlcash.VerifySpend(value, "mint.example")
		_, _ = lnurlcash.OutputKeyOfCw1(value)
		_ = lnurlcash.CheckLeafPolicy(lnurlcash.TapleafVersion, []byte(value))
		_, _ = lnurlcash.SpendDomainOf(value)
	})
}
