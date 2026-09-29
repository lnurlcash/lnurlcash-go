package lnurlcash_test

// Key-path note behaviour the vectors do not state on their own: which
// parameter each call puts a spend or an output in, which older ck1s are still
// read, and what is refused before anything is sent. Every key and signature
// here is one of part2.json's, whose first branch is at mint.example, or is
// made from one of its keys.

import (
	"context"
	"crypto/sha256"
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

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	lnurlcash "github.com/lnurlcash/lnurlcash-go"
)

type part2Sample struct {
	a, b, c    part2Note
	domain     string
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
		domain:     vectors.Branches[0].Domain,
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

func TestNoteIDOfFilesEveryNoteByItsQ(t *testing.T) {
	part2 := loadPart2(t)
	k1 := secret(0x11)
	hash, _ := lnurlcash.HashK1(k1)
	q, _ := lnurlcash.BearerNoteID(hash)
	cw1, _ := lnurlcash.BearerCw1(k1)

	// a bearer preimage and its cw1 are one spend of one note, filed by hex(Q)
	for _, spend := range []string{k1, strings.ToUpper(k1), cw1} {
		if id, err := lnurlcash.NoteIDOf(spend); err != nil || id != q {
			t.Errorf("%.12s... is filed under %s (%v), want hex(Q) %s", spend, id, err, q)
		}
	}
	// looked up by its short form, which every mint reads, or by its cp1
	if lookup, err := lnurlcash.NoteLookupOf(k1); err != nil || lookup != hash {
		t.Errorf("a bearer preimage is looked up by %s (%v), want its h", lookup, err)
	}
	if lookup, err := lnurlcash.NoteLookupOf(cw1); err != nil || lookup != lnurlcash.EncodeCp1(hex32(t, q)) {
		t.Errorf("a bearer cw1 is looked up by %s (%v), want its cp1", lookup, err)
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
	for _, note := range []string{
		"https://" + part2.domain + "/w?k1=" + part2.a.Ck1 + "&amount=21000&sig=" + part2.cs1,
		"lnurlw://" + strings.ToUpper(part2.domain) + "/w?k1=" + part2.a.Ck1,
	} {
		if got := lnurlcash.ResolveNoteInput(note); got == "" {
			t.Errorf("%s did not resolve", note)
		}
	}
	// signed for one mint, it is no note at another
	if got := lnurlcash.ResolveNoteInput("https://elsewhere.example/w?k1=" + part2.a.Ck1); got != "" {
		t.Errorf("a ck1 for %s resolved at another mint: %q", part2.domain, got)
	}
	// a cp1 is the note's public name, not what spends it
	if got := lnurlcash.ResolveNoteInput("https://" + part2.domain + "/w?k1=" + part2.a.Cp1 + "&amount=21000"); got != "" {
		t.Errorf("a cp1 in k1 resolved to %q", got)
	}
}

func TestLooksEveryNoteUpByP(t *testing.T) {
	part2 := loadPart2(t)
	hash, _ := lnurlcash.HashK1(secret(0x11))
	const link = "https://mint.example/w?k1=" + "22" + "&amount=5&sig=ab"

	byKey := queryOf(t, lnurlcash.BuildNoteInfoURLByHash(link, part2.a.Cp1))
	if byKey.Get("p") != part2.a.Cp1 || byKey.Has("h") {
		t.Errorf("a cp1 lookup sent %v, want p alone", byKey)
	}
	// a bearer note's h is the cp1 slot's short form, and goes in the same place
	byHash := queryOf(t, lnurlcash.BuildNoteInfoURLByHash(link, hash))
	if byHash.Get("p") != hash || byHash.Has("h") {
		t.Errorf("a hash lookup sent %v, want p alone", byHash)
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

func TestEveryMutationOutputGoesAsP1OrP2(t *testing.T) {
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
	// a bearer note's h is the cp1 slot's short form: p1 all the same
	rotate, _ = lnurlcash.RotateRequestWithHash(callback, part2.a.Ck1, hash)
	if q := queryOf(t, rotate.URL); q.Get("p1") != hash || q.Has("h") {
		t.Errorf("rotate into a hash sent %v", q)
	}

	split, _ := lnurlcash.SplitRequestWithHash(callback, []string{part2.a.Ck1}, 5000, part2.b.Cp1, hash)
	if q := queryOf(t, split.URL); q.Get("p1") != part2.b.Cp1 || q.Get("p2") != hash || q.Has("h") || q.Has("h2") {
		t.Errorf("split into a key and a hash sent %v", q)
	}
	split, _ = lnurlcash.SplitRequestWithHash(callback, []string{part2.a.Ck1}, 5000, hash, part2.b.Cp1)
	if q := queryOf(t, split.URL); q.Get("p1") != hash || q.Get("p2") != part2.b.Cp1 || q.Has("h") || q.Has("h2") {
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
	// a cp1 whose key is no curve point is a note nobody could ever spend
	offCurve := lnurlcash.EncodeCp1([32]byte{31: 5})
	if _, err := lnurlcash.MintInvoiceRequestWithHash(pay, 21000, offCurve); !errors.Is(err, lnurlcash.ErrRequestRefused) {
		t.Errorf("minting to an off-curve cp1 = %v, want refused before anything was paid", err)
	}
}

// legacyCk1 is the pre-Schnorr spelling of a note's ck1: a 65-byte
// r || s || recovery id ECDSA signature over the Lightning-signed "LNURLcash".
// Nothing produces one anymore, but notes minted under it must stay readable
// until they are rotated.
func legacyCk1(t *testing.T, secretKeyHex string) string {
	t.Helper()
	var key secp256k1.ModNScalar
	key.SetByteSlice(hexBytes(t, secretKeyHex, 32))
	inner := sha256.Sum256([]byte("Lightning Signed Message:LNURLcash"))
	digest := sha256.Sum256(inner[:])
	compact := ecdsa.SignCompact(secp256k1.NewPrivateKey(&key), digest[:], true)
	payload := append(append([]byte(nil), compact[1:]...), compact[0]-27-4)
	words, err := bech32.ConvertBits(payload, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := bech32.EncodeM("ck", words)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// rawMessageCk1 is part2.json's first note (index 0 of mint.example) as
// lnurlcash-conformance 0.12.0 spelled it: the same key, but a BIP-340
// signature over the raw 9-byte "LNURLcash" rather than the spend sighash.
const rawMessageCk1 = "ck12e7xv2ca3njkjwuun6zm4u4v3ven69hfc33nmaxcemns7g9y7qeklrf8ych23gfjn0zt4k5g6ghfehepjte5ws7gcxqthg8965zfwazua5564jxx4fjwn3a78j2t55y24l03s7ldw2kmn672wrg5xq790yz4088e"

// digestMessageCk1 is the same note as lnurlcash-conformance 0.13 spelled it,
// the form current until spends moved onto the sighash: a BIP-340 signature
// over sha256("LNURLcash"), with all-zero auxiliary input.
func digestMessageCk1(t *testing.T, secretKeyHex string) string {
	t.Helper()
	private, _ := btcec.PrivKeyFromBytes(hexBytes(t, secretKeyHex, 32))
	digest := sha256.Sum256([]byte("LNURLcash"))
	signature, err := schnorr.Sign(private, digest[:], schnorr.CustomNonce([32]byte{}))
	if err != nil {
		t.Fatal(err)
	}
	var payload [96]byte
	copy(payload[:32], schnorr.SerializePubKey(private.PubKey()))
	copy(payload[32:], signature.Serialize())
	return lnurlcash.EncodeCk1(payload)
}

func TestOneKeyReproducesOneCk1PerMint(t *testing.T) {
	part2 := loadPart2(t)
	key := hex32(t, part2.a.NoteSecretKey)
	a, err := lnurlcash.SignNoteOwnership(key, part2.domain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := lnurlcash.SignNoteOwnership(key, "https://"+strings.ToUpper(part2.domain)+":3338/w")
	if err != nil {
		t.Fatal(err)
	}
	if a != b || lnurlcash.EncodeCk1(a) != part2.a.Ck1 {
		t.Errorf("signing twice gave %s and %s, want %s both times", lnurlcash.EncodeCk1(a), lnurlcash.EncodeCk1(b), part2.a.Ck1)
	}
	elsewhere, err := lnurlcash.SignNoteOwnership(key, "elsewhere.example")
	if err != nil || elsewhere == a {
		t.Errorf("one ck1 serves two mints (%v)", err)
	}
	if _, err := lnurlcash.SignNoteOwnership(key, ""); err == nil {
		t.Error("signed a ck1 bound to no mint")
	}
}

func TestALegacyCk1StaysReadableForRotation(t *testing.T) {
	part2 := loadPart2(t)
	legacy := legacyCk1(t, part2.a.NoteSecretKey)
	decoded, err := lnurlcash.DecodeCk1(legacy)
	if err != nil || !decoded.IsLegacy || len(decoded.Bytes()) != 65 {
		t.Fatalf("a legacy ck1 decodes to %+v (%v)", decoded, err)
	}
	if !lnurlcash.IsCk1(legacy) {
		t.Error("IsCk1 refused a legacy ck1")
	}
	if id, err := lnurlcash.NoteIDOf(legacy); err != nil || id != part2.a.NotePubkey {
		t.Errorf("a legacy ck1 is filed under %s (%v), want %s", id, err, part2.a.NotePubkey)
	}
	if lookup, err := lnurlcash.NoteLookupOf(legacy); err != nil || lookup != part2.a.Cp1 {
		t.Errorf("a legacy ck1 is looked up by %s (%v), want its cp1", lookup, err)
	}
	// it names no mint, so it reads the same at any, and says it is old
	for _, domain := range []string{part2.domain, "elsewhere.example"} {
		verified, err := lnurlcash.VerifySpend(legacy, domain)
		if err != nil || hex.EncodeToString(verified.OutputKey[:]) != part2.a.NotePubkey || !verified.Legacy {
			t.Errorf("at %s: %+v (%v), want the note, legacy", domain, verified, err)
		}
	}
}

// Both fixed-message ck1s were current once, and notes carrying them are
// still out there: read them, and say they are old so a wallet rotates them.
func TestFixedMessageCk1sStayReadableForRotation(t *testing.T) {
	part2 := loadPart2(t)
	for name, ck1 := range map[string]string{
		"raw message":    rawMessageCk1,
		"sha256 message": digestMessageCk1(t, part2.a.NoteSecretKey),
	} {
		if ck1 == part2.a.Ck1 {
			t.Fatalf("%s: the old spelling is the current one", name)
		}
		decoded, err := lnurlcash.DecodeCk1(ck1)
		if err != nil || decoded.IsLegacy {
			t.Fatalf("%s: decodes to %+v (%v)", name, decoded, err)
		}
		if id, err := lnurlcash.NoteIDOf(ck1); err != nil || id != part2.a.NotePubkey {
			t.Errorf("%s: filed under %s (%v), want %s", name, id, err, part2.a.NotePubkey)
		}
		owner, err := lnurlcash.RecoverNoteOwnershipPubkey(decoded.Bytes(), part2.domain)
		if err != nil || hex.EncodeToString(owner.PubkeyXOnly[:]) != part2.a.NotePubkey || !owner.Legacy {
			t.Errorf("%s: verifies as %+v (%v), want the note, legacy", name, owner, err)
		}
		// and its signature is not simply accepted for any message: moved onto
		// another key, it verifies under no scheme
		other, _ := lnurlcash.DecodeCk1(part2.b.Ck1)
		moved := decoded.Current
		copy(moved[:32], other.Current[:32])
		if _, err := lnurlcash.RecoverNoteOwnershipPubkey(moved[:], part2.domain); err == nil {
			t.Errorf("%s: the signature verified under another key", name)
		}
	}
	// the current ck1 is not mistaken for an old one
	if owner, err := lnurlcash.RecoverNoteOwnershipPubkey(mustCk1(t, part2.a.Ck1), part2.domain); err != nil || owner.Legacy {
		t.Errorf("the current ck1 = %+v (%v), want current", owner, err)
	}
}

func mustCk1(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := lnurlcash.DecodeCk1(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.Bytes()
}

func TestAnEchoedCk1IsComparedByTheNoteItNames(t *testing.T) {
	part2 := loadPart2(t)
	queried := "https://" + part2.domain + "/w?k1=" + part2.a.Ck1
	answer := func(k1 string) []byte {
		body, _ := json.Marshal(map[string]any{
			"tag": "withdrawRequest", "callback": "https://mint.example/w/cb", "k1": k1,
			"maxWithdrawable": 21000, "mintPubkey": part2.mintPubkey,
		})
		return body
	}
	for _, spelling := range []string{legacyCk1(t, part2.a.NoteSecretKey), rawMessageCk1, digestMessageCk1(t, part2.a.NoteSecretKey)} {
		if _, err := lnurlcash.ParseNoteInfo(answer(spelling), queried, lnurlcash.Policy{}); err != nil {
			t.Errorf("another spelling of the same note was refused: %v", err)
		}
	}
	var protocol *lnurlcash.ProtocolError
	if _, err := lnurlcash.ParseNoteInfo(answer(part2.b.Ck1), queried, lnurlcash.Policy{}); !errors.As(err, &protocol) {
		t.Errorf("a different note's ck1 was accepted as the echo: %v", err)
	}
	// the right key under a signature that opens nothing is not the note
	forged := mustCk1(t, part2.a.Ck1)
	forged[40] ^= 0xff
	var payload [96]byte
	copy(payload[:], forged)
	if _, err := lnurlcash.ParseNoteInfo(answer(lnurlcash.EncodeCk1(payload)), queried, lnurlcash.Policy{}); !errors.As(err, &protocol) {
		t.Errorf("a ck1 naming the note under a broken signature was accepted as the echo: %v", err)
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
		if _, err := lnurlcash.SignNoteOwnership(key, part2.domain); err == nil {
			t.Errorf("signed with %x", key)
		}
		if _, err := lnurlcash.CashNodeToCx1(lnurlcash.CashNode{PrivateKey: key}); err == nil {
			t.Errorf("made a cx1 from %x", key)
		}
	}

	current, _ := lnurlcash.DecodeCk1(part2.a.Ck1)
	if _, err := lnurlcash.RecoverNoteOwnershipPubkey(current.Current[:95], part2.domain); err == nil {
		t.Error("verified a truncated ck1")
	}
	for _, at := range []int{10, 40, 90} {
		corrupted := current.Current
		corrupted[at] ^= 0xff
		if owner, err := lnurlcash.RecoverNoteOwnershipPubkey(corrupted[:], part2.domain); err == nil && hex.EncodeToString(owner.PubkeyXOnly[:]) == part2.a.NotePubkey {
			t.Errorf("a ck1 corrupted at byte %d still verifies as the note", at)
		}
	}
	legacy, _ := lnurlcash.DecodeCk1(legacyCk1(t, part2.a.NoteSecretKey))
	badRecovery := legacy.Legacy
	badRecovery[64] = 4
	if _, err := lnurlcash.RecoverNoteOwnershipPubkey(badRecovery[:], part2.domain); err == nil {
		t.Error("recovered with a recovery id of 4")
	}
}

func TestTellsTheFiveEncodingsApart(t *testing.T) {
	part2 := loadPart2(t)
	cw1, _ := lnurlcash.BearerCw1(secret(0x11))
	for _, c := range []struct {
		value string
		want  [5]bool
	}{
		{part2.a.Cp1, [5]bool{true, false, false, false, false}},
		{part2.a.Ck1, [5]bool{false, true, false, false, false}},
		{cw1, [5]bool{false, false, true, false, false}},
		{part2.cs1, [5]bool{false, false, false, true, false}},
		{part2.cx1, [5]bool{false, false, false, false, true}},
		// a bearer preimage or h is never mistaken for any of them
		{secret(0x11), [5]bool{}},
	} {
		got := [5]bool{lnurlcash.IsCp1(c.value), lnurlcash.IsCk1(c.value), lnurlcash.IsCw1(c.value), lnurlcash.IsCs1WithAmount(c.value), lnurlcash.IsCx1(c.value)}
		if got != c.want {
			t.Errorf("%.12s...: cp1/ck1/cw1/cs1/cx1 = %v, want %v", c.value, got, c.want)
		}
	}
}

func TestAmountBearingCs1Boundaries(t *testing.T) {
	var signature [65]byte
	for _, amount := range []int64{0, 1, 99, 100, 21_000, 1<<63 - 1} {
		encoded, err := lnurlcash.EncodeCs1WithAmount(amount, signature)
		if err != nil {
			t.Fatalf("encode %d msat: %v", amount, err)
		}
		decoded, err := lnurlcash.DecodeCs1WithAmount(encoded)
		if err != nil || decoded.AmountMsat != amount || decoded.Signature != signature {
			t.Errorf("round trip %d msat = %+v (%v)", amount, decoded, err)
		}
	}
	if _, err := lnurlcash.EncodeCs1WithAmount(-1, signature); err == nil {
		t.Error("encoded a negative amount")
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
		{"ck", part2.a.Ck1, func(v string) error { _, err := lnurlcash.DecodeCk1(v); return err }},
		{"cx", part2.cx1, func(v string) error { _, err := lnurlcash.DecodeCx1(v); return err }},
		{"cw", mustBearerCw1(t), func(v string) error { _, err := lnurlcash.DecodeCw1(v); return err }},
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

func mustBearerCw1(t *testing.T) string {
	t.Helper()
	cw1, err := lnurlcash.BearerCw1(secret(0x11))
	if err != nil {
		t.Fatal(err)
	}
	return cw1
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
		if q := requests[1].Query(); q.Get("p1") != part2.b.Cp1 || q.Get("p2") != hash || q.Get("amount") != "5000" {
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

// ---- what an output named by cp1 is owed ----

// LUD-25 has a mint certify every note (a SHOULD). This package insists for an
// output the caller named by cp1: a mint that mints there and answers without
// a cs1 has issued a note nobody can check offline, which is the reason to
// name it so, and no Policy waives it. The mutation landed all the same: the
// error is about verifiability, and the note exists at the caller's key.
func TestAnUncertifiedCp1OutputIsUnverifiableWhateverThePolicy(t *testing.T) {
	part2 := loadPart2(t)
	hash, _ := lnurlcash.HashK1(secret(0x11))
	base, _ := capture(t, map[string]any{"status": "OK"})
	callback := base + "/w/cb"

	for name, policy := range map[string]lnurlcash.Policy{
		"the zero Policy":        {},
		"AllowMissingMintPubkey": {AllowMissingMintPubkey: true},
		"RequireSignatures":      {RequireSignatures: true},
	} {
		client := lnurlcash.NewClient()
		client.Policy = policy
		for call, mutate := range map[string]func() (lnurlcash.Mutation, error){
			"rotate": func() (lnurlcash.Mutation, error) {
				return client.RotateNoteWithHash(ctx(t), callback, part2.a.Ck1, part2.b.Cp1)
			},
			"split": func() (lnurlcash.Mutation, error) {
				return client.SplitNoteWithHash(ctx(t), callback, []string{part2.a.Ck1}, 5000, part2.b.Cp1, hash)
			},
			"merge": func() (lnurlcash.Mutation, error) {
				return client.MergeNotesWithHash(ctx(t), callback, []string{secret(0x11), part2.a.Ck1}, part2.c.Cp1)
			},
		} {
			_, err := mutate()
			if !lnurlcash.IsUnverifiable(err) {
				t.Errorf("%s, %s: %v, want unverifiable", name, call, err)
			}
			// the caller named the output, so nothing of this package's rides out
			if carried := lnurlcash.NewSecrets(err); len(carried) != 0 {
				t.Errorf("%s, %s: carried %d secrets it never had", name, call, len(carried))
			}
		}
	}

	// The tolerant policy admits an uncertified output named by a bearer h.
	if _, err := lnurlcash.NewClient().RotateNoteWithHash(ctx(t), callback, part2.a.Ck1, hash); err != nil {
		t.Errorf("an unsigned plain output was refused: %v", err)
	}

	// Read off the URL, so a request rebuilt from a persisted one - LUD-25's
	// byte-identical retry after a restart - is held to the same rule.
	rotate, err := lnurlcash.RotateRequestWithHash(callback, part2.a.Ck1, part2.b.Cp1)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := lnurlcash.Request{URL: rotate.URL}
	if _, err := lnurlcash.ParseMutation([]byte(`{"status":"OK"}`), rebuilt, lnurlcash.MutationRotate, lnurlcash.Policy{}); !lnurlcash.IsUnverifiable(err) {
		t.Errorf("a rebuilt request lost the rule: %v", err)
	}
	certified := []byte(`{"status":"OK","sig":"` + part2.cs1 + `"}`)
	if mutation, err := lnurlcash.ParseMutation(certified, rebuilt, lnurlcash.MutationRotate, lnurlcash.Policy{}); err != nil || mutation.Signature != part2.cs1 {
		t.Errorf("a certified cp1 output = %q (%v), want its cs1", mutation.Signature, err)
	}
}

// A split's change is a note like any other. When it is a cp1 it is owed its
// cs1 in sig2 exactly as the first output is owed one in sig, and a split that
// certifies only the output the caller asked about has left the rest of the
// value unverifiable.
func TestACp1ChangeWithoutItsCertificateIsUnverifiable(t *testing.T) {
	part2 := loadPart2(t)
	hash, _ := lnurlcash.HashK1(secret(0x11))
	client := lnurlcash.NewClient()

	firstOnly, _ := capture(t, map[string]any{"status": "OK", "sig": part2.cs1})
	_, err := client.SplitNoteWithHash(ctx(t), firstOnly+"/w/cb", []string{part2.a.Ck1}, 5000, hash, part2.b.Cp1)
	if !lnurlcash.IsUnverifiable(err) {
		t.Fatalf("a cp1 change with no sig2 = %v, want unverifiable", err)
	}
	if !strings.Contains(err.Error(), "change") {
		t.Errorf("the error does not name the change: %v", err)
	}

	// The other way round the change is the hash, and a plain change is owed
	// nothing.
	split, err := client.SplitNoteWithHash(ctx(t), firstOnly+"/w/cb", []string{part2.a.Ck1}, 5000, part2.b.Cp1, hash)
	if err != nil || split.Signature != part2.cs1 || split.ChangeSignature != "" {
		t.Errorf("a cp1 output with a plain change = %+v (%v)", split, err)
	}

	// and a split to two keys that certifies both is whole
	both, _ := capture(t, map[string]any{"status": "OK", "sig": part2.cs1, "sig2": part2.cs1})
	if _, err := client.SplitNoteWithHash(ctx(t), both+"/w/cb", []string{part2.a.Ck1}, 5000, part2.b.Cp1, part2.c.Cp1); err != nil {
		t.Errorf("a split certifying both keys was refused: %v", err)
	}
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
		if decoded, err := lnurlcash.DecodeCk1(value); err == nil && !decoded.IsLegacy && lnurlcash.EncodeCk1(decoded.Current) != canonical {
			t.Errorf("ck1 %q decodes to %x, which encodes differently", value, decoded.Current)
		}
		if signature, err := lnurlcash.DecodeCs1(value); err == nil && lnurlcash.EncodeCs1(signature) != canonical {
			t.Errorf("cs1 %q decodes to %x, which encodes differently", value, signature)
		}
		if certificate, err := lnurlcash.DecodeCs1WithAmount(value); err == nil {
			encoded, encodeErr := lnurlcash.EncodeCs1WithAmount(certificate.AmountMsat, certificate.Signature)
			if encodeErr != nil || encoded != canonical {
				t.Errorf("amount-bearing cs1 %q encodes differently (%v)", value, encodeErr)
			}
		}
		if branch, err := lnurlcash.DecodeCx1(value); err == nil && lnurlcash.EncodeCx1(branch.PubkeyXOnly, branch.ChainCode) != canonical {
			t.Errorf("cx1 %q decodes to %+v, which encodes differently", value, branch)
		}
		if spend, err := lnurlcash.DecodeCw1(value); err == nil {
			if encoded, encodeErr := lnurlcash.EncodeCw1(spend); encodeErr != nil || encoded != canonical {
				t.Errorf("cw1 %q decodes to %+v, which encodes differently (%v)", value, spend, encodeErr)
			}
		}
		// and everything that reads a k1 or a signature through them
		_, _ = lnurlcash.NoteIDOf(value)
		_, _ = lnurlcash.NoteLookupOf(value)
		_, _ = lnurlcash.VerifySpend(value, "mint.example")
		_ = lnurlcash.VerifyNoteSignature(value, value, 1, value, value)
		_ = lnurlcash.BuildNoteInfoURLByHash("https://mint.example/w", value)
	})
}
