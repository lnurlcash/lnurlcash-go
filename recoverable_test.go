package lnurlcash_test

// Part 2 behaviour the vectors do not state on their own: which parameter each
// call puts a ck1 or a cp1 in, and what is refused before anything is sent.
// Every key and signature here is one of part2.json's, so nothing is invented.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	lnurlcash "github.com/lnurlcash/lnurlcash-go"
)

type part2Sample struct {
	a, b, c    part2Note
	cs1        string
	mintPubkey string
	cx1        string
}

func loadPart2(t *testing.T) part2Sample {
	t.Helper()
	var vectors part2Vectors
	loadVectorsStrict(t, "part2.json", &vectors)
	notes := vectors.Branches[0].Notes
	return part2Sample{
		a:          notes[0],
		b:          notes[1],
		c:          notes[2],
		cs1:        vectors.Certificates[0].Cs1,
		mintPubkey: vectors.Mint.MintPubkey,
		cx1:        vectors.Branches[0].Cx1,
	}
}

func queryOf(t *testing.T, raw string) url.Values {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("%q does not parse: %v", raw, err)
	}
	return parsed.Query()
}

func TestNoteIDOfFilesEitherKindOfNote(t *testing.T) {
	part2 := loadPart2(t)
	k1 := secret(0x11)
	hash, _ := lnurlcash.HashK1(k1)

	if id, err := lnurlcash.NoteIDOf(k1); err != nil || id != hash {
		t.Errorf("a Part 1 secret is filed under %s (%v), want its hash %s", id, err, hash)
	}
	if lookup, err := lnurlcash.NoteLookupOf(k1); err != nil || lookup != hash {
		t.Errorf("a Part 1 secret is looked up by %s (%v), want its hash", lookup, err)
	}
	if id, err := lnurlcash.NoteIDOf(part2.a.Ck1); err != nil || id != part2.a.NotePubkey {
		t.Errorf("a ck1 is filed under %s (%v), want its key", id, err)
	}
	if lookup, err := lnurlcash.NoteLookupOf(part2.a.Ck1); err != nil || lookup != part2.a.Cp1 {
		t.Errorf("a ck1 is looked up by %s (%v), want its cp1", lookup, err)
	}

	last := part2.a.Ck1[len(part2.a.Ck1)-1:]
	swap := "q"
	if last == "q" {
		swap = "p"
	}
	corrupted := part2.a.Ck1[:len(part2.a.Ck1)-1] + swap
	// a cp1 and a cs1 name a note and certify one; neither spends it
	for _, bad := range []string{"", "zz", strings.Repeat("11", 31), part2.a.Cp1, part2.cs1, corrupted} {
		if _, err := lnurlcash.NoteIDOf(bad); err == nil {
			t.Errorf("NoteIDOf accepted %q", bad)
		}
		if _, err := lnurlcash.NoteLookupOf(bad); err == nil {
			t.Errorf("NoteLookupOf accepted %q", bad)
		}
	}
}

func TestTheSignedMessageNamesAPart2NoteByItsKey(t *testing.T) {
	part2 := loadPart2(t)
	message, err := lnurlcash.NoteSignatureMessage(part2.a.Ck1, 21000)
	if err != nil || message != "LNURLcash:21000:"+part2.a.NotePubkey {
		t.Errorf("message = %q (%v)", message, err)
	}
	if _, err := lnurlcash.NoteSignatureMessage("not a k1", 21000); err == nil {
		t.Error("built a message over something that is not a k1")
	}
}

func TestANoteURLCarryingACk1IsANote(t *testing.T) {
	part2 := loadPart2(t)
	note := "https://mint.example/w?k1=" + part2.a.Ck1 + "&amount=21000&sig=" + part2.cs1
	if got := lnurlcash.ResolveNoteInput(note); got != note {
		t.Errorf("resolve = %q, want the note back", got)
	}
	// a cp1 is the note's public name, not what spends it
	if got := lnurlcash.ResolveNoteInput("https://mint.example/w?k1=" + part2.a.Cp1 + "&amount=21000"); got != "" {
		t.Errorf("a cp1 in k1 resolved to %q", got)
	}
}

func TestLooksAPart2NoteUpByPAndAHashByH(t *testing.T) {
	part2 := loadPart2(t)
	hash, _ := lnurlcash.HashK1(secret(0x11))
	const link = "https://mint.example/w?k1=" + "22" + "&amount=5&sig=ab"

	byKey := queryOf(t, lnurlcash.BuildNoteInfoURLByHash(link, part2.a.Cp1))
	if byKey.Get("p") != part2.a.Cp1 || byKey.Has("h") {
		t.Errorf("a cp1 lookup sent %v, want p alone", byKey)
	}
	byHash := queryOf(t, lnurlcash.BuildNoteInfoURLByHash(link, hash))
	if byHash.Get("h") != hash || byHash.Has("p") {
		t.Errorf("a hash lookup sent %v, want h alone", byHash)
	}
	// A lookup exists to disclose as little as possible, amount=0 included:
	// a strict mint may refuse a placeholder rather than ignore it.
	for _, query := range []url.Values{byKey, byHash} {
		for _, dropped := range []string{"k1", "amount", "sig"} {
			if query.Has(dropped) {
				t.Errorf("a lookup carried %s: %v", dropped, query)
			}
		}
	}
	// the value that spends a note is never a way to look it up
	if got := lnurlcash.BuildNoteInfoURLByHash(link, part2.a.Ck1); got != "" {
		t.Errorf("built a lookup from a ck1: %s", got)
	}
}

func TestEachMutationOutputGoesUnderTheNameForItsKind(t *testing.T) {
	part2 := loadPart2(t)
	k1 := secret(0x11)
	hash, _ := lnurlcash.HashK1(k1)
	const callback = "https://mint.example/w/cb"

	rotate, err := lnurlcash.RotateRequestWithHash(callback, part2.a.Ck1, part2.b.Cp1)
	if err != nil {
		t.Fatal(err)
	}
	if q := queryOf(t, rotate.URL); q.Get("k1") != part2.a.Ck1 || q.Get("p1") != part2.b.Cp1 || q.Has("h") {
		t.Errorf("rotate into a key sent %v", q)
	}
	// a hash keeps h, which every mint understands
	rotate, _ = lnurlcash.RotateRequestWithHash(callback, part2.a.Ck1, hash)
	if q := queryOf(t, rotate.URL); q.Get("h") != hash || q.Has("p1") {
		t.Errorf("rotate into a hash sent %v", q)
	}

	split, _ := lnurlcash.SplitRequestWithHash(callback, []string{part2.a.Ck1}, 5000, part2.b.Cp1, hash)
	if q := queryOf(t, split.URL); q.Get("p1") != part2.b.Cp1 || q.Get("h2") != hash || q.Has("h") || q.Has("p2") {
		t.Errorf("split into a key and a hash sent %v", q)
	}
	split, _ = lnurlcash.SplitRequestWithHash(callback, []string{part2.a.Ck1}, 5000, hash, part2.b.Cp1)
	if q := queryOf(t, split.URL); q.Get("h") != hash || q.Get("p2") != part2.b.Cp1 || q.Has("p1") || q.Has("h2") {
		t.Errorf("split into a hash and a key sent %v", q)
	}

	merge, _ := lnurlcash.MergeRequestWithHash(callback, []string{k1, part2.a.Ck1}, part2.c.Cp1)
	q := queryOf(t, merge.URL)
	if inputs := q["k1"]; len(inputs) != 2 || inputs[0] != k1 || inputs[1] != part2.a.Ck1 || q.Get("p1") != part2.c.Cp1 {
		t.Errorf("merging a secret and a ck1 into a key sent %v", q)
	}
}

func TestMintsToAKeyWithTheCommentAlone(t *testing.T) {
	part2 := loadPart2(t)
	hash, _ := lnurlcash.HashK1(secret(0x11))
	const pay = "https://mint.example/p/cb"

	for _, spelling := range []string{part2.a.Cp1, strings.ToUpper(part2.a.Cp1)} {
		request, err := lnurlcash.MintInvoiceRequestWithHash(pay, 21000, spelling)
		if err != nil {
			t.Fatal(err)
		}
		// h is a hash-only extension, and a mint may refuse a key under it
		if q := queryOf(t, request.URL); q.Get("comment") != part2.a.Cp1 || q.Has("h") {
			t.Errorf("minting to a key sent %v", q)
		}
	}
	request, _ := lnurlcash.MintInvoiceRequestWithHash(pay, 21000, hash)
	if q := queryOf(t, request.URL); q.Get("comment") != hash || q.Get("h") != hash {
		t.Errorf("minting to a hash sent %v", q)
	}
	if _, err := lnurlcash.MintInvoiceRequestWithHash(pay, 21000, part2.a.Ck1); !errors.Is(err, lnurlcash.ErrRequestRefused) {
		t.Errorf("minting to a ck1 = %v, want refused before anything was sent", err)
	}
}

// highSTwin is a ck1's other valid spelling: (r, n - s) with the recovery id's
// parity flipped. Anyone can make it from the ck1 alone, and it recovers to the
// same key - which is why a note is compared by id, never by its ck1.
func highSTwin(t *testing.T, ck1 string) string {
	t.Helper()
	signature, err := lnurlcash.DecodeCk1(ck1)
	if err != nil {
		t.Fatal(err)
	}
	var s secp256k1.ModNScalar
	s.SetByteSlice(signature[32:64])
	s.Negate()
	flipped := s.Bytes()
	copy(signature[32:64], flipped[:])
	signature[64] ^= 1
	return lnurlcash.EncodeCk1(signature)
}

func TestAnEchoedCk1IsComparedByTheNoteItNames(t *testing.T) {
	part2 := loadPart2(t)
	twin := highSTwin(t, part2.a.Ck1)
	if twin == part2.a.Ck1 {
		t.Fatal("the twin is the same string")
	}
	if id, err := lnurlcash.NoteIDOf(twin); err != nil || id != part2.a.NotePubkey {
		t.Fatalf("the twin recovers to %s (%v), not the note", id, err)
	}

	queried := "https://mint.example/w?k1=" + part2.a.Ck1
	answer := func(k1 string) []byte {
		body, _ := json.Marshal(map[string]any{
			"tag": "withdrawRequest", "callback": "https://mint.example/w/cb", "k1": k1,
			"maxWithdrawable": 21000, "mintPubkey": part2.mintPubkey,
		})
		return body
	}
	if _, err := lnurlcash.ParseNoteInfo(answer(twin), queried, lnurlcash.Policy{}); err != nil {
		t.Errorf("another spelling of the same note was refused: %v", err)
	}
	var protocol *lnurlcash.ProtocolError
	if _, err := lnurlcash.ParseNoteInfo(answer(part2.b.Ck1), queried, lnurlcash.Policy{}); !errors.As(err, &protocol) {
		t.Errorf("a different note's ck1 was accepted as the echo: %v", err)
	}
}

func TestPart2RefusesWhatIsNotAKey(t *testing.T) {
	part2 := loadPart2(t)
	var zero, chainCode [32]byte
	order, _ := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	var n [32]byte
	copy(n[:], order)
	var beyondPrime [32]byte
	for i := range beyondPrime {
		beyondPrime[i] = 0xff
	}

	if _, err := lnurlcash.DeriveNotePubkey(beyondPrime, chainCode, 0); err == nil {
		t.Error("derived from a branch key that is no point's x")
	}
	for _, key := range [][32]byte{zero, n} {
		if _, err := lnurlcash.DeriveNoteSecretKey(key, chainCode, 0); err == nil {
			t.Errorf("derived from branch key %x", key)
		}
		if _, err := lnurlcash.SignNoteOwnership(key); err == nil {
			t.Errorf("signed with %x", key)
		}
		if _, err := lnurlcash.CashNodeToCx1(lnurlcash.CashNode{PrivateKey: key}); err == nil {
			t.Errorf("made a cx1 from %x", key)
		}
	}

	signature, _ := lnurlcash.DecodeCk1(part2.a.Ck1)
	badRecovery := signature
	badRecovery[64] = 4
	if _, err := lnurlcash.RecoverNoteOwnershipPubkey(badRecovery); err == nil {
		t.Error("recovered with a recovery id of 4")
	}
	corrupted := signature
	corrupted[10] ^= 0xff
	if recovered, err := lnurlcash.RecoverNoteOwnershipPubkey(corrupted); err == nil && hex.EncodeToString(recovered[:]) == part2.a.NotePubkey {
		t.Error("a corrupted signature still recovers to the note")
	}
}

func TestTellsTheFourEncodingsApart(t *testing.T) {
	part2 := loadPart2(t)
	for _, c := range []struct {
		value string
		want  [4]bool
	}{
		{part2.a.Cp1, [4]bool{true, false, false, false}},
		{part2.a.Ck1, [4]bool{false, true, false, false}},
		{part2.cs1, [4]bool{false, false, true, false}},
		{part2.cx1, [4]bool{false, false, false, true}},
		// a Part 1 secret is never mistaken for any of them
		{secret(0x11), [4]bool{}},
	} {
		got := [4]bool{lnurlcash.IsCp1(c.value), lnurlcash.IsCk1(c.value), lnurlcash.IsCs1(c.value), lnurlcash.IsCx1(c.value)}
		if got != c.want {
			t.Errorf("%.12s...: cp1/ck1/cs1/cx1 = %v, want %v", c.value, got, c.want)
		}
	}
}

// Padding is the one malleability bech32m leaves to the decoder: bits after
// the payload that the checksum covers but the bytes do not. Refusing any that
// are not zero leaves each payload exactly one encoding.
func TestRefusesNonZeroPadding(t *testing.T) {
	part2 := loadPart2(t)
	for _, c := range []struct {
		hrp    string
		value  string
		decode func(string) error
	}{
		{"cp", part2.a.Cp1, func(v string) error { _, err := lnurlcash.DecodeCp1(v); return err }},
		{"cx", part2.cx1, func(v string) error { _, err := lnurlcash.DecodeCx1(v); return err }},
	} {
		_, words, err := bech32.DecodeNoLimit(c.value)
		if err != nil {
			t.Fatal(err)
		}
		words[len(words)-1] |= 1
		padded, err := bech32.EncodeM(c.hrp, words)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.decode(padded); err == nil {
			t.Errorf("%s1 with a padding bit set was accepted", c.hrp)
		}
	}
}

func TestTheMasterStepIsTheRootsFirst(t *testing.T) {
	seed := make([]byte, 64)
	master, err := lnurlcash.DeriveCashMaster(seed)
	if err != nil {
		t.Fatal(err)
	}
	viaMaster, err := lnurlcash.DeriveCashChild(master, 139+0x80000000)
	if err != nil {
		t.Fatal(err)
	}
	root, err := lnurlcash.DeriveCashRoot(seed)
	if err != nil || root != viaMaster {
		t.Errorf("m/139' by hand differs from DeriveCashRoot: %v", err)
	}
	if _, err := lnurlcash.DeriveCashMaster(seed[:15]); err == nil {
		t.Error("took a 15-byte seed")
	}
}

// ---- the Client's hash-parameterised calls ----

type captured struct {
	mu   sync.Mutex
	urls []*url.URL
}

func (c *captured) all() []*url.URL {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*url.URL(nil), c.urls...)
}

// capture answers every request with body and records what was asked.
func capture(t *testing.T, body map[string]any) (string, *captured) {
	t.Helper()
	encoded, _ := json.Marshal(body)
	seen := &captured{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.urls = append(seen.urls, r.URL)
		seen.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.Copy(w, strings.NewReader(string(encoded)))
	}))
	t.Cleanup(server.Close)
	return server.URL, seen
}

func TestTheClientTakesPart2NotesEndToEnd(t *testing.T) {
	part2 := loadPart2(t)
	client := lnurlcash.NewClient()
	background := context.Background()
	hash, _ := lnurlcash.HashK1(secret(0x11))

	t.Run("lookup", func(t *testing.T) {
		base, seen := capture(t, map[string]any{
			"tag": "withdrawRequest", "callback": "https://mint.example/w/cb",
			"minWithdrawable": 21000, "maxWithdrawable": 21000,
			"mintPubkey": part2.mintPubkey, "sig": part2.cs1,
		})
		lookup, _ := lnurlcash.NoteLookupOf(part2.a.Ck1)
		info, err := client.FetchNoteInfoByHash(background, base+"/w", lookup)
		if err != nil {
			t.Fatal(err)
		}
		if q := seen.all()[0].Query(); q.Get("p") != part2.a.Cp1 || q.Has("k1") {
			t.Errorf("lookup sent %v", q)
		}
		if info.MaxWithdrawableMsat != 21000 {
			t.Errorf("worth %d", info.MaxWithdrawableMsat)
		}
		if _, err := client.FetchNoteInfoByHash(background, base+"/w", part2.a.Ck1); !errors.Is(err, lnurlcash.ErrRequestRefused) {
			t.Errorf("looking up by a ck1 = %v, want refused", err)
		}
		if len(seen.all()) != 1 {
			t.Error("the refused lookup reached the service")
		}
	})

	t.Run("mutations", func(t *testing.T) {
		base, seen := capture(t, map[string]any{"status": "OK", "sig": part2.cs1, "sig2": part2.cs1})
		rotated, err := client.RotateNoteWithHash(background, base+"/w/cb", part2.a.Ck1, part2.b.Cp1)
		if err != nil {
			t.Fatal(err)
		}
		if rotated.Signature != part2.cs1 {
			t.Errorf("rotate kept %q, want the cs1", rotated.Signature)
		}
		if _, err := client.SplitNoteWithHash(background, base+"/w/cb", []string{part2.a.Ck1}, 5000, part2.b.Cp1, hash); err != nil {
			t.Fatal(err)
		}
		if _, err := client.MergeNotesWithHash(background, base+"/w/cb", []string{secret(0x11), part2.a.Ck1}, part2.c.Cp1); err != nil {
			t.Fatal(err)
		}
		requests := seen.all()
		if q := requests[0].Query(); q.Get("k1") != part2.a.Ck1 || q.Get("p1") != part2.b.Cp1 {
			t.Errorf("rotate sent %v", q)
		}
		if q := requests[1].Query(); q.Get("p1") != part2.b.Cp1 || q.Get("h2") != hash || q.Get("amount") != "5000" {
			t.Errorf("split sent %v", q)
		}
		if q := requests[2].Query(); len(q["k1"]) != 2 || q.Get("p1") != part2.c.Cp1 {
			t.Errorf("merge sent %v", q)
		}
	})

	t.Run("mint", func(t *testing.T) {
		base, seen := capture(t, map[string]any{"pr": "lnbc210n1pjqrstuvwxyz"})
		if _, err := client.RequestMintInvoiceWithHash(background, base+"/p/cb", 21000, part2.a.Cp1); err != nil {
			t.Fatal(err)
		}
		if q := seen.all()[0].Query(); q.Get("comment") != part2.a.Cp1 || q.Has("h") {
			t.Errorf("mint sent %v", q)
		}
		if _, err := client.RequestMintInvoiceWithHash(background, base+"/p/cb", 21000, part2.a.Ck1); !errors.Is(err, lnurlcash.ErrRequestRefused) {
			t.Errorf("minting to a ck1 = %v, want refused", err)
		}
		if len(seen.all()) != 1 {
			t.Error("the refused mint reached the service")
		}
	})
}

// FuzzPart2Decoders holds the decoders to never panicking, and to accepting a
// string only if it is the one encoding of what it decodes to. The seed corpus
// is every string part2.json carries, so plain `go test` runs those.
func FuzzPart2Decoders(f *testing.F) {
	for _, seed := range []string{"", "cp1", "ck1qqqqqq", "CP1QQQQQQQQ", "cx1" + strings.Repeat("q", 110)} {
		f.Add(seed)
	}
	var vectors part2Vectors
	if raw, err := os.ReadFile(filepath.Join(vectorsDir(f), "part2.json")); err == nil && json.Unmarshal(raw, &vectors) == nil {
		for _, branch := range vectors.Branches {
			f.Add(branch.Cx1)
			for _, note := range branch.Notes {
				f.Add(note.Cp1)
				f.Add(note.Ck1)
			}
		}
		for _, certificate := range vectors.Certificates {
			f.Add(certificate.Cs1)
		}
		for _, invalid := range vectors.Invalid {
			f.Add(invalid.Value)
		}
	}

	f.Fuzz(func(t *testing.T, value string) {
		canonical := strings.ToLower(strings.TrimSpace(value))
		if key, err := lnurlcash.DecodeCp1(value); err == nil && lnurlcash.EncodeCp1(key) != canonical {
			t.Errorf("cp1 %q decodes to %x, which encodes differently", value, key)
		}
		if signature, err := lnurlcash.DecodeCk1(value); err == nil && lnurlcash.EncodeCk1(signature) != canonical {
			t.Errorf("ck1 %q decodes to %x, which encodes differently", value, signature)
		}
		if signature, err := lnurlcash.DecodeCs1(value); err == nil && lnurlcash.EncodeCs1(signature) != canonical {
			t.Errorf("cs1 %q decodes to %x, which encodes differently", value, signature)
		}
		if branch, err := lnurlcash.DecodeCx1(value); err == nil && lnurlcash.EncodeCx1(branch.PubkeyXOnly, branch.ChainCode) != canonical {
			t.Errorf("cx1 %q decodes to %+v, which encodes differently", value, branch)
		}
		// and everything that reads a k1 or a signature through them
		_, _ = lnurlcash.NoteIDOf(value)
		_, _ = lnurlcash.NoteLookupOf(value)
		_ = lnurlcash.VerifyNoteSignature(value, 1, value, value)
		_ = lnurlcash.BuildNoteInfoURLByHash("https://mint.example/w", value)
	})
}
