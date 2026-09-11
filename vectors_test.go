package lnurlcash_test

// Every assertion here comes from lnurlcash-conformance, the same files the
// TypeScript, Python, Rust and Kotlin implementations are held to. Nothing in
// this file states what the protocol is - the vectors do.

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	lnurlcash "github.com/lnurlcash/lnurlcash-go"
)

func vectorsDir(t testing.TB) string {
	t.Helper()
	if configured := os.Getenv("LNURLCASH_CONFORMANCE"); configured != "" {
		return filepath.Join(configured, "vectors")
	}
	return filepath.Join("..", "lnurlcash-conformance", "vectors")
}

func loadVectors(t *testing.T, name string) map[string]json.RawMessage {
	t.Helper()
	path := filepath.Join(vectorsDir(t), name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("conformance vectors not found at %s - check out lnurlcash-conformance alongside this repo, or set LNURLCASH_CONFORMANCE", path)
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("%s is not valid JSON: %v", path, err)
	}
	return parsed
}

func unmarshalInto(t *testing.T, raw json.RawMessage, target any) {
	t.Helper()
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("could not read vector: %v", err)
	}
}

type feeVector struct {
	BaseFeeMsat int64 `json:"baseFeeMsat"`
	FeePpm      int64 `json:"feePpm"`
}

func (f feeVector) fee() lnurlcash.MintFee {
	return lnurlcash.MintFee{BaseFeeMsat: f.BaseFeeMsat, FeePpm: f.FeePpm}
}

func TestSignatureVectors(t *testing.T) {
	vectors := loadVectors(t, "signature.json")
	var cases []struct {
		Name       string `json:"name"`
		K1         string `json:"k1"`
		AmountMsat int64  `json:"amountMsat"`
		Signature  string `json:"signature"`
		MintPubkey string `json:"mintPubkey"`
		Valid      bool   `json:"valid"`
		Message    string `json:"message"`
		Digest     string `json:"digest"`
	}
	unmarshalInto(t, vectors["cases"], &cases)
	if len(cases) < 6 {
		t.Fatalf("only %d signature cases - too few to be meaningful", len(cases))
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			got := lnurlcash.VerifyNoteSignature(c.K1, c.AmountMsat, c.Signature, c.MintPubkey)
			if got != c.Valid {
				t.Errorf("verify = %v, want %v", got, c.Valid)
			}
			if c.Message != "" {
				message, err := lnurlcash.NoteSignatureMessage(c.K1, c.AmountMsat)
				if err != nil || message != c.Message {
					t.Errorf("message = %q (%v), want %q", message, err, c.Message)
				}
			}
		})
	}
}

func TestBech32Vectors(t *testing.T) {
	vectors := loadVectors(t, "bech32.json")
	var encode []struct {
		URL   string `json:"url"`
		Lnurl string `json:"lnurl"`
	}
	unmarshalInto(t, vectors["encode"], &encode)
	for _, c := range encode {
		encoded, err := lnurlcash.ToBech32Lnurl(c.URL)
		if err != nil || encoded != c.Lnurl {
			t.Errorf("encode(%q) = %q (%v), want %q", c.URL, encoded, err, c.Lnurl)
		}
		if decoded := lnurlcash.FromBech32Lnurl(c.Lnurl); decoded != c.URL {
			t.Errorf("decode(%q) = %q, want %q", c.Lnurl, decoded, c.URL)
		}
	}

	var invalid []struct {
		Input string `json:"input"`
		Why   string `json:"why"`
	}
	unmarshalInto(t, vectors["decodeInvalid"], &invalid)
	for _, c := range invalid {
		if decoded := lnurlcash.FromBech32Lnurl(c.Input); decoded != "" {
			t.Errorf("decode(%q) = %q, want none (%s)", c.Input, decoded, c.Why)
		}
	}

	var insensitive struct {
		Lower string `json:"lower"`
		Upper string `json:"upper"`
		URL   string `json:"url"`
	}
	unmarshalInto(t, vectors["caseInsensitive"], &insensitive)
	for _, encoded := range []string{insensitive.Lower, insensitive.Upper} {
		if decoded := lnurlcash.FromBech32Lnurl(encoded); decoded != insensitive.URL {
			t.Errorf("decode(%q) = %q, want %q", encoded, decoded, insensitive.URL)
		}
	}
}

func TestURLAdmissionVectors(t *testing.T) {
	vectors := loadVectors(t, "url-admission.json")
	var allowed []string
	unmarshalInto(t, vectors["allowed"], &allowed)
	for _, u := range allowed {
		if !lnurlcash.IsAllowedServiceURL(u) {
			t.Errorf("should allow %q", u)
		}
	}
	var rejected []struct {
		URL string `json:"url"`
		Why string `json:"why"`
	}
	unmarshalInto(t, vectors["rejected"], &rejected)
	for _, c := range rejected {
		if lnurlcash.IsAllowedServiceURL(c.URL) {
			t.Errorf("should reject %q (%s)", c.URL, c.Why)
		}
	}
}

func TestInputResolutionVectors(t *testing.T) {
	vectors := loadVectors(t, "input-resolution.json")
	type resolution struct {
		Input  string  `json:"input"`
		Expect *string `json:"expect"`
		Why    string  `json:"why"`
	}
	expected := func(e *string) string {
		if e == nil {
			return ""
		}
		return *e
	}

	for key, resolve := range map[string]func(string) string{
		"lnurl": lnurlcash.ResolveLnurlInput,
		"mint":  lnurlcash.ResolveMintInput,
		"note":  lnurlcash.ResolveNoteInput,
	} {
		var cases []resolution
		unmarshalInto(t, vectors[key], &cases)
		for _, c := range cases {
			if got := resolve(c.Input); got != expected(c.Expect) {
				t.Errorf("%s resolve(%q) = %q, want %q", key, c.Input, got, expected(c.Expect))
			}
		}
	}

	var mirrors []struct {
		PayURL string  `json:"payUrl"`
		Expect *string `json:"expect"`
	}
	unmarshalInto(t, vectors["mintAddressUrl"], &mirrors)
	for _, c := range mirrors {
		if got := lnurlcash.MintAddressURL(c.PayURL); got != expected(c.Expect) {
			t.Errorf("mirror(%q) = %q, want %q", c.PayURL, got, expected(c.Expect))
		}
	}

	var usernames []struct {
		PayURL string  `json:"payUrl"`
		Expect *string `json:"expect"`
	}
	unmarshalInto(t, vectors["lightningAddressUsername"], &usernames)
	for _, c := range usernames {
		if got := lnurlcash.LightningAddressUsername(c.PayURL); got != expected(c.Expect) {
			t.Errorf("username(%q) = %q, want %q", c.PayURL, got, expected(c.Expect))
		}
	}
}

func TestNoteURLVectors(t *testing.T) {
	vectors := loadVectors(t, "note-url.json")

	var parse []struct {
		URL                string  `json:"url"`
		K1                 *string `json:"k1"`
		DeclaredAmountMsat *int64  `json:"declaredAmountMsat"`
		Signature          *string `json:"signature"`
	}
	unmarshalInto(t, vectors["parse"], &parse)
	for _, c := range parse {
		want := ""
		if c.K1 != nil {
			want = *c.K1
		}
		if got := lnurlcash.NoteK1(c.URL); got != want {
			t.Errorf("k1(%q) = %q, want %q", c.URL, got, want)
		}
		amount, ok := lnurlcash.NoteDeclaredAmountMsat(c.URL)
		if c.DeclaredAmountMsat == nil && ok {
			t.Errorf("amount(%q) = %d, want none", c.URL, amount)
		}
		if c.DeclaredAmountMsat != nil && (!ok || amount != *c.DeclaredAmountMsat) {
			t.Errorf("amount(%q) = %d/%v, want %d", c.URL, amount, ok, *c.DeclaredAmountMsat)
		}
		wantSig := ""
		if c.Signature != nil {
			wantSig = *c.Signature
		}
		if got := lnurlcash.NoteSignature(c.URL); got != wantSig {
			t.Errorf("signature(%q) = %q, want %q", c.URL, got, wantSig)
		}
	}

	var build []struct {
		WithdrawLink string `json:"withdrawLink"`
		K1           string `json:"k1"`
		AmountMsat   *int64 `json:"amountMsat"`
		Expect       string `json:"expect"`
	}
	unmarshalInto(t, vectors["build"], &build)
	for _, c := range build {
		amount := int64(-1)
		if c.AmountMsat != nil {
			amount = *c.AmountMsat
		}
		if got := lnurlcash.BuildNoteURL(c.WithdrawLink, c.K1, amount); got != c.Expect {
			t.Errorf("build(%q) = %q, want %q", c.WithdrawLink, got, c.Expect)
		}
	}

	var withNew []struct {
		URL        string  `json:"url"`
		K1         string  `json:"k1"`
		AmountMsat int64   `json:"amountMsat"`
		Signature  *string `json:"signature"`
		Expect     string  `json:"expect"`
	}
	unmarshalInto(t, vectors["withNewK1"], &withNew)
	for _, c := range withNew {
		signature := ""
		if c.Signature != nil {
			signature = *c.Signature
		}
		if got := lnurlcash.WithNewK1(c.URL, c.K1, c.AmountMsat, signature); got != c.Expect {
			t.Errorf("withNewK1 = %q, want %q", got, c.Expect)
		}
	}

	var without []struct {
		URL        string  `json:"url"`
		AmountMsat int64   `json:"amountMsat"`
		Signature  *string `json:"signature"`
		Expect     string  `json:"expect"`
	}
	unmarshalInto(t, vectors["withoutK1"], &without)
	for _, c := range without {
		signature := ""
		if c.Signature != nil {
			signature = *c.Signature
		}
		if got := lnurlcash.WithoutK1(c.URL, c.AmountMsat, signature); got != c.Expect {
			t.Errorf("withoutK1 = %q, want %q", got, c.Expect)
		}
	}
}

func TestFeeVectors(t *testing.T) {
	vectors := loadVectors(t, "fees.json")

	var parse []struct {
		Metadata string     `json:"metadata"`
		Expect   *feeVector `json:"expect"`
	}
	unmarshalInto(t, vectors["parse"], &parse)
	for _, c := range parse {
		fee, ok := lnurlcash.ParseMintFee(c.Metadata)
		if c.Expect == nil {
			if ok {
				t.Errorf("parse(%q) = %+v, want none", c.Metadata, fee)
			}
			continue
		}
		if !ok || fee != c.Expect.fee() {
			t.Errorf("parse(%q) = %+v/%v, want %+v", c.Metadata, fee, ok, c.Expect.fee())
		}
	}

	var apply []struct {
		GrossMsat int64     `json:"grossMsat"`
		Fee       feeVector `json:"fee"`
		Expect    int64     `json:"expect"`
	}
	unmarshalInto(t, vectors["apply"], &apply)
	for _, c := range apply {
		if got := lnurlcash.ApplyMintFee(c.GrossMsat, c.Fee.fee()); got != c.Expect {
			t.Errorf("apply(%d, %+v) = %d, want %d", c.GrossMsat, c.Fee.fee(), got, c.Expect)
		}
	}

	var grossUp []struct {
		NetMsat int64     `json:"netMsat"`
		Fee     feeVector `json:"fee"`
		Expect  int64     `json:"expect"`
	}
	unmarshalInto(t, vectors["grossUp"], &grossUp)
	for _, c := range grossUp {
		if got := lnurlcash.GrossUpForMintFee(c.NetMsat, c.Fee.fee()); got != c.Expect {
			t.Errorf("grossUp(%d, %+v) = %d, want %d", c.NetMsat, c.Fee.fee(), got, c.Expect)
		}
	}

	var roundTrip struct {
		Fees           []feeVector `json:"fees"`
		NetAmountsMsat []int64     `json:"netAmountsMsat"`
	}
	unmarshalInto(t, vectors["grossUpRoundTrip"], &roundTrip)
	for _, raw := range roundTrip.Fees {
		fee := raw.fee()
		for _, net := range roundTrip.NetAmountsMsat {
			gross := lnurlcash.GrossUpForMintFee(net, fee)
			if got := lnurlcash.ApplyMintFee(gross, fee); got != net {
				t.Errorf("round trip %d through %+v nets %d", net, fee, got)
			}
			if got := lnurlcash.ApplyMintFee(gross-1, fee); got >= net {
				t.Errorf("round trip %d through %+v: %d is not the minimum", net, fee, gross)
			}
		}
	}

	var percent []struct {
		Ppm    int64  `json:"ppm"`
		Expect string `json:"expect"`
	}
	unmarshalInto(t, vectors["formatPercent"], &percent)
	for _, c := range percent {
		if got := lnurlcash.FormatFeePercent(c.Ppm); got != c.Expect {
			t.Errorf("format(%d) = %q, want %q", c.Ppm, got, c.Expect)
		}
	}
}

func TestBolt11Vectors(t *testing.T) {
	vectors := loadVectors(t, "bolt11.json")

	var amounts []struct {
		PR     string `json:"pr"`
		Expect *int64 `json:"expect"`
	}
	unmarshalInto(t, vectors["decodeAmountMsat"], &amounts)
	for _, c := range amounts {
		amount, ok := lnurlcash.DecodeBolt11AmountMsat(c.PR)
		if c.Expect == nil {
			if ok {
				t.Errorf("decode(%q) = %d, want none", c.PR, amount)
			}
			continue
		}
		if !ok || amount != *c.Expect {
			t.Errorf("decode(%q) = %d/%v, want %d", c.PR, amount, ok, *c.Expect)
		}
	}

	var shapes []struct {
		PR     string `json:"pr"`
		Expect bool   `json:"expect"`
	}
	unmarshalInto(t, vectors["isInvoice"], &shapes)
	for _, c := range shapes {
		if got := lnurlcash.IsBolt11Invoice(c.PR); got != c.Expect {
			t.Errorf("isInvoice(%q) = %v, want %v", c.PR, got, c.Expect)
		}
	}

	var same []struct {
		A      string `json:"a"`
		B      string `json:"b"`
		Expect bool   `json:"expect"`
	}
	unmarshalInto(t, vectors["sameInvoice"], &same)
	for _, c := range same {
		if got := lnurlcash.SameInvoice(c.A, c.B); got != c.Expect {
			t.Errorf("same(%q, %q) = %v, want %v", c.A, c.B, got, c.Expect)
		}
	}

	var preimages []struct {
		Value  string `json:"value"`
		Expect bool   `json:"expect"`
	}
	unmarshalInto(t, vectors["isPreimage"], &preimages)
	for _, c := range preimages {
		if got := lnurlcash.IsPreimage(c.Value); got != c.Expect {
			t.Errorf("isPreimage(%q) = %v, want %v", c.Value, got, c.Expect)
		}
	}
}

func asProtocol(err error, target **lnurlcash.ProtocolError) bool {
	return errors.As(err, target)
}

// TestPayRequestVectors binds LUD-25 minting to pay-request.json.
//
// This is the suite that would have caught the package sitting on the deleted
// preimage-keyed model for a month: nothing here states an opinion of its own,
// so a draft change lands as a red test rather than as a silent divergence
// discovered by a wallet that could not mint.
func TestPayRequestVectors(t *testing.T) {
	vectors := loadVectors(t, "pay-request.json")

	var accepted []struct {
		Name           string          `json:"name"`
		Body           json.RawMessage `json:"body"`
		WithdrawLink   string          `json:"withdrawLink"`
		CommentAllowed *int64          `json:"commentAllowed"`
		MintFee        *feeVector      `json:"mintFee"`
	}
	unmarshalInto(t, vectors["accepted"], &accepted)
	for _, testCase := range accepted {
		parsed, err := lnurlcash.ParsePayRequest(testCase.Body)
		if err != nil {
			t.Fatalf("%s: expected a parse, got %v", testCase.Name, err)
		}
		if parsed.WithdrawLink != testCase.WithdrawLink {
			t.Errorf("%s: withdrawLink = %q, want %q", testCase.Name, parsed.WithdrawLink, testCase.WithdrawLink)
		}
		wantComment := testCase.CommentAllowed != nil
		if parsed.HasCommentAllowed != wantComment {
			t.Errorf("%s: commentAllowed present = %v, want %v", testCase.Name, parsed.HasCommentAllowed, wantComment)
		}
		if wantComment && parsed.CommentAllowed != *testCase.CommentAllowed {
			t.Errorf("%s: commentAllowed = %d, want %d", testCase.Name, parsed.CommentAllowed, *testCase.CommentAllowed)
		}
		if parsed.HasMintFee != (testCase.MintFee != nil) {
			t.Errorf("%s: mint fee present = %v", testCase.Name, parsed.HasMintFee)
		}
		if testCase.MintFee != nil && parsed.MintFee != testCase.MintFee.fee() {
			t.Errorf("%s: mint fee = %+v, want %+v", testCase.Name, parsed.MintFee, testCase.MintFee.fee())
		}
		// A payRequest is only a mint if it can carry the commitment, and a
		// mint is only a mint if it advertises where the note will live.
		if parsed.NamesMintOutput() != (parsed.WithdrawLink != "") {
			t.Errorf("%s: minting capability must track withdrawLink", testCase.Name)
		}
	}

	var rejected []struct {
		Name string          `json:"name"`
		Body json.RawMessage `json:"body"`
	}
	unmarshalInto(t, vectors["rejected"], &rejected)
	for _, testCase := range rejected {
		if _, err := lnurlcash.ParsePayRequest(testCase.Body); err == nil {
			t.Errorf("%s: must not parse", testCase.Name)
		}
	}

	// The mint callback names the note before the invoice exists.
	const callback = "https://mint.example/p/cb"
	var mintCallback struct {
		Accepted []struct {
			Name                      string `json:"name"`
			AmountMsat                int64  `json:"amountMsat"`
			Comment                   string `json:"comment"`
			NoteID                    string `json:"noteId"`
			PaymentPreimageIsBearerK1 bool   `json:"paymentPreimageIsBearerK1"`
		} `json:"accepted"`
		Rejected []struct {
			Name       string  `json:"name"`
			AmountMsat int64   `json:"amountMsat"`
			Comment    *string `json:"comment"`
		} `json:"rejected"`
	}
	unmarshalInto(t, vectors["mintCallback"], &mintCallback)
	for _, testCase := range mintCallback.Accepted {
		request, err := lnurlcash.MintInvoiceRequestWithHash(callback, testCase.AmountMsat, testCase.Comment)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		// LUD-25 carries the commitment as a mandatory LUD-12 comment; h
		// repeats it for the additive ForgeSworn profile.
		if !strings.Contains(request.URL, "comment="+testCase.Comment) {
			t.Errorf("%s: the commitment must ride as a comment - got %s", testCase.Name, request.URL)
		}
		if !strings.Contains(request.URL, "h="+testCase.Comment) {
			t.Errorf("%s: h must repeat the commitment", testCase.Name)
		}
		if testCase.NoteID != testCase.Comment {
			t.Errorf("%s: the note is keyed by the commitment", testCase.Name)
		}
		if testCase.PaymentPreimageIsBearerK1 {
			t.Errorf("%s: the preimage is settlement proof, never the note", testCase.Name)
		}
	}
	for _, testCase := range mintCallback.Rejected {
		// A null comment is the unnamed mint the draft forbids: this package
		// cannot express one, because the minting builder requires the
		// commitment. A malformed one is refused before anything is sent.
		if testCase.Comment == nil {
			if _, err := lnurlcash.MintInvoiceRequest(callback, testCase.AmountMsat, ""); !errors.Is(err, lnurlcash.ErrRequestRefused) {
				t.Errorf("%s: an unnamed mint must be impossible to build", testCase.Name)
			}
			continue
		}
		if _, err := lnurlcash.MintInvoiceRequestWithHash(callback, testCase.AmountMsat, *testCase.Comment); !errors.Is(err, lnurlcash.ErrRequestRefused) {
			t.Errorf("%s: a malformed commitment must be refused before it is sent", testCase.Name)
		}
	}

	var invoice struct {
		Accepted []struct {
			Name          string          `json:"name"`
			RequestedMsat int64           `json:"requestedMsat"`
			Body          json.RawMessage `json:"body"`
			Disposable    bool            `json:"disposable"`
			Verify        string          `json:"verify"`
		} `json:"accepted"`
		Rejected []struct {
			Name          string          `json:"name"`
			RequestedMsat int64           `json:"requestedMsat"`
			Body          json.RawMessage `json:"body"`
		} `json:"rejected"`
	}
	unmarshalInto(t, vectors["invoice"], &invoice)
	for _, testCase := range invoice.Accepted {
		parsed, err := lnurlcash.ParseInvoice(testCase.Body, testCase.RequestedMsat)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		if parsed.Disposable != testCase.Disposable {
			t.Errorf("%s: disposable = %v, want %v", testCase.Name, parsed.Disposable, testCase.Disposable)
		}
		if parsed.VerifyURL != testCase.Verify {
			t.Errorf("%s: verify = %q, want %q", testCase.Name, parsed.VerifyURL, testCase.Verify)
		}
	}
	for _, testCase := range invoice.Rejected {
		if _, err := lnurlcash.ParseInvoice(testCase.Body, testCase.RequestedMsat); err == nil {
			t.Errorf("%s: must not parse", testCase.Name)
		}
	}

	var verify struct {
		Accepted []struct {
			Name     string          `json:"name"`
			Body     json.RawMessage `json:"body"`
			Settled  bool            `json:"settled"`
			Preimage string          `json:"preimage"`
		} `json:"accepted"`
		Rejected []struct {
			Name string          `json:"name"`
			Body json.RawMessage `json:"body"`
		} `json:"rejected"`
	}
	unmarshalInto(t, vectors["verify"], &verify)
	for _, testCase := range verify.Accepted {
		parsed, err := lnurlcash.ParseVerify(testCase.Body)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		if parsed.Settled != testCase.Settled {
			t.Errorf("%s: settled = %v, want %v", testCase.Name, parsed.Settled, testCase.Settled)
		}
		if parsed.Preimage != testCase.Preimage {
			t.Errorf("%s: preimage = %q, want %q", testCase.Name, parsed.Preimage, testCase.Preimage)
		}
	}
	for _, testCase := range verify.Rejected {
		if _, err := lnurlcash.ParseVerify(testCase.Body); err == nil {
			t.Errorf("%s: must not parse", testCase.Name)
		}
	}
}

// ---- derivation ----
//
// The two schemes a wallet may mint under. cash-derivation.json is the one
// LUD-25 specifies and the one a new wallet uses; derivation.json is the
// pre-spec HMAC scheme, kept because notes minted under it are still money.
//
// A disagreement with either file is a wallet that cannot restore what another
// implementation of the same seed phrase minted, which is the whole reason
// these vectors exist rather than each library testing itself.

func TestCashDerivationVectors(t *testing.T) {
	vectors := loadVectors(t, "cash-derivation.json")

	var scheme struct {
		Purpose                 string `json:"purpose"`
		HardenedByMagnitudeOnly bool   `json:"hardenedByMagnitudeOnly"`
	}
	unmarshalInto(t, vectors["scheme"], &scheme)
	if scheme.Purpose != "m/139'" {
		t.Fatalf("the vector describes %q, not the scheme this package implements", scheme.Purpose)
	}
	// The one thing an implementation can silently get wrong: d1..d4 are raw
	// uint32, hardened only where they happen to land at or above 2^31.
	if !scheme.HardenedByMagnitudeOnly {
		t.Fatal("the vector no longer pins hardened-by-magnitude-only")
	}

	// BIP-32's own published vector 1, so a failure here says CKDpriv is wrong
	// rather than the LUD-25 path above it. The chain alternates hardened and
	// unhardened, which is exactly the pair of legs the domain levels land on.
	var steps []struct {
		Index *uint32 `json:"index"`
		Node  string  `json:"node"`
	}
	unmarshalInto(t, vectors["bip32Vector1"], &steps)
	node, err := lnurlcash.CashNodeFromHex(steps[0].Node)
	if err != nil {
		t.Fatalf("BIP-32 vector 1 master: %v", err)
	}
	for _, step := range steps[1:] {
		if node, err = lnurlcash.DeriveCashChild(node, *step.Index); err != nil {
			t.Fatalf("BIP-32 vector 1 at %d: %v", *step.Index, err)
		}
		if got := lnurlcash.CashNodeToHex(node); got != step.Node {
			t.Errorf("BIP-32 vector 1 at %d: %s, want %s", *step.Index, got, step.Node)
		}
	}

	var cases []struct {
		Name          string   `json:"name"`
		SeedHex       string   `json:"seedHex"`
		Host          string   `json:"host"`
		Index         uint32   `json:"index"`
		CashRoot      string   `json:"cashRoot"`
		DomainIndices []uint32 `json:"domainIndices"`
		DomainNode    string   `json:"domainNode"`
		K1            string   `json:"k1"`
		NoteID        string   `json:"noteId"`
	}
	unmarshalInto(t, vectors["cases"], &cases)
	for _, testCase := range cases {
		seed, err := hex.DecodeString(testCase.SeedHex)
		if err != nil {
			t.Fatalf("%s: seedHex: %v", testCase.Name, err)
		}
		root, err := lnurlcash.DeriveCashRoot(seed)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		if got := lnurlcash.CashNodeToHex(root); got != testCase.CashRoot {
			t.Errorf("%s: root = %s, want %s", testCase.Name, got, testCase.CashRoot)
		}

		indices, err := lnurlcash.CashDomainIndices(root, testCase.Host)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		for i, want := range testCase.DomainIndices {
			if indices[i] != want {
				t.Errorf("%s: d%d = %d, want %d", testCase.Name, i+1, indices[i], want)
			}
		}

		domainNode, err := lnurlcash.DeriveCashDomainNode(root, testCase.Host)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		if got := lnurlcash.CashNodeToHex(domainNode); got != testCase.DomainNode {
			t.Errorf("%s: domain node = %s, want %s", testCase.Name, got, testCase.DomainNode)
		}

		secret, err := lnurlcash.DeriveCashSecret(root, testCase.Host, testCase.Index)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		if secret != testCase.K1 {
			t.Errorf("%s: k1 = %s, want %s", testCase.Name, secret, testCase.K1)
		}
		// The hardware-signer path: given only this mint's subtree, with no
		// seed and no elliptic curve, every note index still resolves.
		fromNode, err := lnurlcash.CashSecretAt(domainNode, testCase.Index)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		if fromNode != testCase.K1 {
			t.Errorf("%s: from the domain node alone = %s, want %s", testCase.Name, fromNode, testCase.K1)
		}
		id, err := lnurlcash.HashK1(secret)
		if err != nil {
			t.Fatalf("%s: %v", testCase.Name, err)
		}
		if id != testCase.NoteID {
			t.Errorf("%s: noteId = %s, want %s", testCase.Name, id, testCase.NoteID)
		}
	}
}

func TestLegacyDerivationVectors(t *testing.T) {
	vectors := loadVectors(t, "derivation.json")

	var scheme struct {
		RootKey string `json:"rootKey"`
	}
	unmarshalInto(t, vectors["scheme"], &scheme)
	if scheme.RootKey != "lnurlcash-note-v1" {
		t.Fatalf("the vector describes %q, not the legacy scheme", scheme.RootKey)
	}

	var cases []struct {
		Name    string `json:"name"`
		SeedHex string `json:"seedHex"`
		Host    string `json:"host"`
		Index   uint32 `json:"index"`
		K1      string `json:"k1"`
		NoteID  string `json:"noteId"`
	}
	unmarshalInto(t, vectors["cases"], &cases)
	for _, testCase := range cases {
		seed, err := hex.DecodeString(testCase.SeedHex)
		if err != nil {
			t.Fatalf("%s: seedHex: %v", testCase.Name, err)
		}
		root := lnurlcash.DeriveNoteRoot(seed)
		if got := lnurlcash.DeriveNoteSecret(root, testCase.Host, testCase.Index); got != testCase.K1 {
			t.Errorf("%s: k1 = %s, want %s", testCase.Name, got, testCase.K1)
		}
	}
}

// ---- LUD-25 Part 2 ----
//
// part2.json: notes keyed by a public key and spent by a recoverable
// signature. Every field of every branch, note and certificate is graded, and
// each value from the side that would actually compute it: note keys from the
// cx1 alone, as a watching mint does; secret keys from the address node, as
// the holder does; each ck1 by signing again, since RFC6979 must reproduce it
// byte for byte; and each ck1 and cs1 by recovering the key inside it.
//
// Both files are decoded strictly. A field these tests do not know is a field
// nobody is grading, so a vector that gains one fails here until it is.

func loadVectorsStrict(t *testing.T, name string, target any) {
	t.Helper()
	path := filepath.Join(vectorsDir(t), name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("conformance vectors not found at %s - check out lnurlcash-conformance v0.10.0 or later alongside this repo, or set LNURLCASH_CONFORMANCE", path)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("%s: %v - grade the new field before letting this pass", path, err)
	}
}

type part2Note struct {
	Index              uint32 `json:"index"`
	NotePubkey         string `json:"notePubkey"`
	Cp1                string `json:"cp1"`
	NoteSecretKey      string `json:"noteSecretKey"`
	OwnershipSignature string `json:"ownershipSignature"`
	Ck1                string `json:"ck1"`
}

type part2Vectors struct {
	Version     int    `json:"version"`
	Spec        string `json:"spec"`
	Description string `json:"description"`
	Conventions struct {
		AddressBranch      string `json:"addressBranch"`
		HashingKey         string `json:"hashingKey"`
		SpecTextSays       string `json:"specTextSays"`
		NoteTweak          string `json:"noteTweak"`
		IndexWidth         string `json:"indexWidth"`
		OwnershipMessage   string `json:"ownershipMessage"`
		OwnershipDigest    string `json:"ownershipDigest"`
		SignatureLayout    string `json:"signatureLayout"`
		CertificateMessage string `json:"certificateMessage"`
	} `json:"conventions"`
	Mint struct {
		PrivateKey string `json:"privateKey"`
		MintPubkey string `json:"mintPubkey"`
	} `json:"mint"`
	Branches []struct {
		Mnemonic      string      `json:"mnemonic"`
		SeedHex       string      `json:"seedHex"`
		Host          string      `json:"host"`
		CashRoot      string      `json:"cashRoot"`
		DomainIndices []uint32    `json:"domainIndices"`
		AddressNode   string      `json:"addressNode"`
		BranchPubkey  string      `json:"branchPubkey"`
		BranchParity  string      `json:"branchParity"`
		ChainCode     string      `json:"chainCode"`
		Cx1           string      `json:"cx1"`
		Notes         []part2Note `json:"notes"`
	} `json:"branches"`
	Certificates []struct {
		NotePubkey string `json:"notePubkey"`
		AmountMsat int64  `json:"amountMsat"`
		Message    string `json:"message"`
		Digest     string `json:"digest"`
		Signature  string `json:"signature"`
		Cs1        string `json:"cs1"`
	} `json:"certificates"`
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

func hexBytes(t *testing.T, value string, length int) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != length {
		t.Fatalf("vector value %q is not %d bytes of hex", value, length)
	}
	return raw
}

func hex32(t *testing.T, value string) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], hexBytes(t, value, 32))
	return out
}

func hex65(t *testing.T, value string) [65]byte {
	t.Helper()
	var out [65]byte
	copy(out[:], hexBytes(t, value, 65))
	return out
}

// publicKeyOf is the compressed public key of a 32-byte secret key, worked out
// here rather than by the package, so the package's own keys have something
// independent to be checked against.
func publicKeyOf(t *testing.T, secretKey [32]byte) []byte {
	t.Helper()
	var scalar secp256k1.ModNScalar
	if scalar.SetBytes(&secretKey) != 0 || scalar.IsZero() {
		t.Fatalf("vector secret key is not a scalar in [1, n)")
	}
	return secp256k1.NewPrivateKey(&scalar).PubKey().SerializeCompressed()
}

// recoverCompressed recovers the compressed key behind an r || s || recovery
// id signature over digest, independently of the package.
func recoverCompressed(t *testing.T, signature [65]byte, digest []byte) string {
	t.Helper()
	compact := append([]byte{27 + 4 + signature[64]}, signature[:64]...)
	pubkey, _, err := ecdsa.RecoverCompact(compact, digest)
	if err != nil {
		t.Fatalf("signature does not recover: %v", err)
	}
	return hex.EncodeToString(pubkey.SerializeCompressed())
}

// requireLayout checks the conventions' "r || s || recovery id (0..3),
// low-S" against a signature's own bytes.
func requireLayout(t *testing.T, signature [65]byte) {
	t.Helper()
	if signature[64] > 3 {
		t.Errorf("recovery id %d, want 0 to 3 in the last byte", signature[64])
	}
	var s secp256k1.ModNScalar
	if s.SetByteSlice(signature[32:64]) || s.IsOverHalfOrder() {
		t.Errorf("s is not low: the signer did not normalise it")
	}
}

func bip39Seed(t *testing.T, mnemonic string) []byte {
	t.Helper()
	// BIP39 with no passphrase. The vector mnemonics are ASCII, so NFKD is the
	// identity and needs no normaliser.
	seed, err := pbkdf2.Key(sha512.New, mnemonic, []byte("mnemonic"), 2048, 64)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	return seed
}

// gradeNote grades one note on a branch, from both halves of it: the holder's
// address node and the watcher's cx1.
func gradeNote(t *testing.T, node lnurlcash.CashNode, watched lnurlcash.Cx1, note part2Note) {
	t.Helper()

	// the watcher, holding only the cx1
	pubkey, err := lnurlcash.DeriveNotePubkey(watched.PubkeyXOnly, watched.ChainCode, note.Index)
	if err != nil {
		t.Fatalf("note pubkey: %v", err)
	}
	if got := hex.EncodeToString(pubkey[:]); got != note.NotePubkey {
		t.Errorf("note pubkey from the cx1 = %s, want %s", got, note.NotePubkey)
	}

	// the holder, holding the node
	secretKey, err := lnurlcash.DeriveNoteSecretKey(node.PrivateKey, node.ChainCode, note.Index)
	if err != nil {
		t.Fatalf("note secret key: %v", err)
	}
	if got := hex.EncodeToString(secretKey[:]); got != note.NoteSecretKey {
		t.Errorf("note secret key = %s, want %s", got, note.NoteSecretKey)
	}
	// and the two halves meet: the holder's key is the one the watcher derived
	if got := hex.EncodeToString(publicKeyOf(t, secretKey)[1:]); got != note.NotePubkey {
		t.Errorf("the secret key's own public key = %s, want %s", got, note.NotePubkey)
	}

	if got := lnurlcash.EncodeCp1(pubkey); got != note.Cp1 {
		t.Errorf("cp1 = %s, want %s", got, note.Cp1)
	}
	if decoded, err := lnurlcash.DecodeCp1(note.Cp1); err != nil || decoded != pubkey {
		t.Errorf("cp1 does not decode to the note pubkey: %v", err)
	}

	// RFC6979: signing again reproduces the ck1 byte for byte
	signature, err := lnurlcash.SignNoteOwnership(secretKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if note.OwnershipSignature != "" {
		if got := hex.EncodeToString(signature[:]); got != note.OwnershipSignature {
			t.Errorf("ownership signature = %s, want %s", got, note.OwnershipSignature)
		}
		requireLayout(t, hex65(t, note.OwnershipSignature))
	}
	if got := lnurlcash.EncodeCk1(signature); got != note.Ck1 {
		t.Errorf("ck1 = %s, want %s", got, note.Ck1)
	}

	// the service's side: the ck1 it is handed recovers to the note it files
	fromVector, err := lnurlcash.DecodeCk1(note.Ck1)
	if err != nil {
		t.Fatalf("ck1 does not decode: %v", err)
	}
	if note.OwnershipSignature != "" && fromVector != hex65(t, note.OwnershipSignature) {
		t.Errorf("ck1 decodes to %x, want %s", fromVector, note.OwnershipSignature)
	}
	recovered, err := lnurlcash.RecoverNoteOwnershipPubkey(fromVector)
	if err != nil || hex.EncodeToString(recovered[:]) != note.NotePubkey {
		t.Errorf("ck1 recovers to %x (%v), want %s", recovered, err, note.NotePubkey)
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

func TestPart2Vectors(t *testing.T) {
	var vectors part2Vectors
	loadVectorsStrict(t, "part2.json", &vectors)
	if vectors.Version != 1 {
		t.Fatalf("part2.json is format version %d; these tests read version 1", vectors.Version)
	}

	// What this package implements. A vector describing anything else is a
	// different scheme, and every value below would fail for that reason alone.
	conventions := vectors.Conventions
	if conventions.AddressBranch != "m/139'/1'/d1/d2/d3/d4" || conventions.HashingKey != "m/139'/1'/0" {
		t.Fatalf("the vectors describe %s under %s, not the reference wallet's address path", conventions.AddressBranch, conventions.HashingKey)
	}
	if conventions.OwnershipMessage != "LNURLcash" || conventions.CertificateMessage != "LNURLcash:<amount_msat>:<hex(pk)>" {
		t.Fatalf("the vectors sign %q and certify %q", conventions.OwnershipMessage, conventions.CertificateMessage)
	}
	inner := sha256.Sum256([]byte("Lightning Signed Message:" + conventions.OwnershipMessage))
	ownershipDigest := sha256.Sum256(inner[:])
	if got := hex.EncodeToString(ownershipDigest[:]); got != conventions.OwnershipDigest {
		t.Errorf("ownership digest = %s, want %s", got, conventions.OwnershipDigest)
	}
	// The package signs under that digest if, and only if, it reproduces every
	// ck1 below and recovers every one of them to its note.

	mintPubkey := vectors.Mint.MintPubkey
	if got := hex.EncodeToString(publicKeyOf(t, hex32(t, vectors.Mint.PrivateKey))); got != mintPubkey {
		t.Fatalf("mint private key is the key of %s, not %s", got, mintPubkey)
	}

	if len(vectors.Branches) < 8 {
		t.Fatalf("only %d branches - too few to be meaningful", len(vectors.Branches))
	}
	parities := map[string]bool{}
	indices := map[uint32]bool{}
	notesByPubkey := map[string]part2Note{}
	for _, branch := range vectors.Branches {
		parities[branch.BranchParity] = true
		t.Run(fmt.Sprintf("%s under %s", branch.Host, branch.SeedHex[:8]), func(t *testing.T) {
			seed := bip39Seed(t, branch.Mnemonic)
			if got := hex.EncodeToString(seed); got != branch.SeedHex {
				t.Fatalf("seed = %s, want %s", got, branch.SeedHex)
			}
			root, err := lnurlcash.DeriveCashRoot(seed)
			if err != nil {
				t.Fatal(err)
			}
			if got := lnurlcash.CashNodeToHex(root); got != branch.CashRoot {
				t.Errorf("cash root = %s, want %s", got, branch.CashRoot)
			}

			// d1..d4 hang off m/139'/1', keyed by m/139'/1'/0
			addressRoot, err := lnurlcash.DeriveCashChild(root, 1+0x80000000)
			if err != nil {
				t.Fatal(err)
			}
			domain, err := lnurlcash.CashDomainIndices(addressRoot, branch.Host)
			if err != nil {
				t.Fatal(err)
			}
			if len(branch.DomainIndices) != len(domain) {
				t.Fatalf("%d domain indices, want %d", len(branch.DomainIndices), len(domain))
			}
			for i, want := range branch.DomainIndices {
				if domain[i] != want {
					t.Errorf("d%d = %d, want %d", i+1, domain[i], want)
				}
			}

			node, err := lnurlcash.DeriveCashAddressNode(root, branch.Host)
			if err != nil {
				t.Fatal(err)
			}
			if got := lnurlcash.CashNodeToHex(node); got != branch.AddressNode {
				t.Fatalf("address node = %s, want %s", got, branch.AddressNode)
			}
			// the spec text's path is the Part 1 ladder's node; never this one
			if part1, err := lnurlcash.DeriveCashDomainNode(root, branch.Host); err != nil || part1 == node {
				t.Errorf("the address branch shares a node with the Part 1 ladder")
			}

			cx, err := lnurlcash.CashNodeToCx1(node)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(cx.PubkeyXOnly[:]); got != branch.BranchPubkey {
				t.Errorf("branch pubkey = %s, want %s", got, branch.BranchPubkey)
			}
			if got := hex.EncodeToString(cx.ChainCode[:]); got != branch.ChainCode {
				t.Errorf("chain code = %s, want %s", got, branch.ChainCode)
			}
			parity := "even"
			if publicKeyOf(t, node.PrivateKey)[0] == 0x03 {
				parity = "odd"
			}
			if parity != branch.BranchParity {
				t.Errorf("branch parity = %s, want %s", parity, branch.BranchParity)
			}
			if got := lnurlcash.EncodeCx1(cx.PubkeyXOnly, cx.ChainCode); got != branch.Cx1 {
				t.Errorf("cx1 = %s, want %s", got, branch.Cx1)
			}
			watched, err := lnurlcash.DecodeCx1(branch.Cx1)
			if err != nil || watched != cx {
				t.Fatalf("cx1 does not decode to the branch: %v", err)
			}

			for _, note := range branch.Notes {
				indices[note.Index] = true
				notesByPubkey[note.NotePubkey] = note
				t.Run(fmt.Sprintf("index %d", note.Index), func(t *testing.T) {
					gradeNote(t, node, watched, note)
				})
			}
		})
	}
	// An odd branch is the one a wallet that forgets to negate gets wrong.
	if !parities["even"] || !parities["odd"] {
		t.Errorf("the branches cover parities %v; both even and odd are needed", parities)
	}
	// i is a plain uint32, never hardened: both sides of 2^31, and the top.
	for _, index := range []uint32{0x7fffffff, 0x80000000, 0xffffffff} {
		if !indices[index] {
			t.Errorf("no note at index %d", index)
		}
	}

	if len(vectors.Certificates) == 0 {
		t.Fatal("no certificates")
	}
	for _, certificate := range vectors.Certificates {
		t.Run(fmt.Sprintf("certificate for %d msat", certificate.AmountMsat), func(t *testing.T) {
			if got := lnurlcash.NoteSignatureMessageForHash(certificate.NotePubkey, certificate.AmountMsat); got != certificate.Message {
				t.Errorf("message = %q, want %q", got, certificate.Message)
			}
			digest := lnurlcash.NoteSignatureDigestForHash(certificate.NotePubkey, certificate.AmountMsat)
			if got := hex.EncodeToString(digest); got != certificate.Digest {
				t.Errorf("digest = %s, want %s", got, certificate.Digest)
			}

			signature := hex65(t, certificate.Signature)
			requireLayout(t, signature)
			if got := lnurlcash.EncodeCs1(signature); got != certificate.Cs1 {
				t.Errorf("cs1 = %s, want %s", got, certificate.Cs1)
			}
			decoded, err := lnurlcash.DecodeCs1(certificate.Cs1)
			if err != nil || decoded != signature {
				t.Fatalf("cs1 does not decode to the signature: %v", err)
			}
			// the cs1 recovers to the mint's key, over the vector's own digest
			if got := recoverCompressed(t, decoded, hexBytes(t, certificate.Digest, 32)); got != mintPubkey {
				t.Errorf("cs1 recovers to %s, want the mint's %s", got, mintPubkey)
			}
			for _, spelling := range []string{certificate.Signature, certificate.Cs1} {
				if !lnurlcash.VerifyNoteSignatureHash(certificate.NotePubkey, certificate.AmountMsat, spelling, mintPubkey) {
					t.Errorf("does not verify over the note pubkey as %.8s...", spelling)
				}
			}

			// the recipient's check: a ck1 and its cs1, offline, nothing else
			note, ok := notesByPubkey[certificate.NotePubkey]
			if !ok {
				t.Fatalf("certifies %s, which no branch holds", certificate.NotePubkey)
			}
			if got, err := lnurlcash.NoteSignatureMessage(note.Ck1, certificate.AmountMsat); err != nil || got != certificate.Message {
				t.Errorf("message from the ck1 = %q (%v), want %q", got, err, certificate.Message)
			}
			if got, err := lnurlcash.NoteSignatureDigest(note.Ck1, certificate.AmountMsat); err != nil || hex.EncodeToString(got) != certificate.Digest {
				t.Errorf("digest from the ck1 = %x (%v), want %s", got, err, certificate.Digest)
			}
			if !lnurlcash.VerifyNoteSignature(note.Ck1, certificate.AmountMsat, certificate.Cs1, mintPubkey) {
				t.Error("a ck1 and its cs1 do not verify")
			}
			if lnurlcash.VerifyNoteSignature(note.Ck1, certificate.AmountMsat+1, certificate.Cs1, mintPubkey) {
				t.Error("verifies for an amount nobody certified")
			}
		})
	}

	// The four decoders, and the checks, by the vectors' own type names.
	decoders := map[string]func(string) (string, error){
		"cp1": func(v string) (string, error) { b, err := lnurlcash.DecodeCp1(v); return hex.EncodeToString(b[:]), err },
		"ck1": func(v string) (string, error) { b, err := lnurlcash.DecodeCk1(v); return hex.EncodeToString(b[:]), err },
		"cs1": func(v string) (string, error) { b, err := lnurlcash.DecodeCs1(v); return hex.EncodeToString(b[:]), err },
		"cx1": func(v string) (string, error) {
			c, err := lnurlcash.DecodeCx1(v)
			return hex.EncodeToString(c.PubkeyXOnly[:]) + hex.EncodeToString(c.ChainCode[:]), err
		},
	}
	checks := map[string]func(string) bool{
		"cp1": lnurlcash.IsCp1, "ck1": lnurlcash.IsCk1, "cs1": lnurlcash.IsCs1, "cx1": lnurlcash.IsCx1,
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

// TestNostrSeedVectors grades nostr-seed.json: an extension, not LUD-25. A
// Part 2 address branch rooted in a Nostr identity key, the same file
// heartwood-esp32 and lnurlcash-kit grade against, so all three derive one
// branch from one key.
func TestNostrSeedVectors(t *testing.T) {
	var vectors struct {
		Version     int    `json:"version"`
		Spec        string `json:"spec"`
		Extension   bool   `json:"extension"`
		Description string `json:"description"`
		Label       string `json:"label"`
		Cases       []struct {
			Identity       string      `json:"identity"`
			IdentityPubkey string      `json:"identityPubkey"`
			Host           string      `json:"host"`
			Seed           string      `json:"seed"`
			AddressNode    string      `json:"addressNode"`
			Cx1            string      `json:"cx1"`
			Notes          []part2Note `json:"notes"`
		} `json:"cases"`
	}
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

	for _, testCase := range vectors.Cases {
		t.Run(fmt.Sprintf("%s under %s", testCase.Host, testCase.IdentityPubkey[:8]), func(t *testing.T) {
			identity := hex32(t, testCase.Identity)
			if got := hex.EncodeToString(publicKeyOf(t, identity)[1:]); got != testCase.IdentityPubkey {
				t.Errorf("identity pubkey = %s, want %s", got, testCase.IdentityPubkey)
			}
			seed := lnurlcash.DeriveNostrCashSeed(identity)
			if got := hex.EncodeToString(seed[:]); got != testCase.Seed {
				t.Errorf("seed = %s, want %s", got, testCase.Seed)
			}

			node, err := lnurlcash.DeriveNostrAddressNode(identity, testCase.Host)
			if err != nil {
				t.Fatal(err)
			}
			if got := lnurlcash.CashNodeToHex(node); got != testCase.AddressNode {
				t.Fatalf("address node = %s, want %s", got, testCase.AddressNode)
			}
			// and it is the ordinary address path from that seed, unchanged
			root, err := lnurlcash.DeriveCashRoot(seed[:])
			if err != nil {
				t.Fatal(err)
			}
			if ordinary, err := lnurlcash.DeriveCashAddressNode(root, testCase.Host); err != nil || ordinary != node {
				t.Errorf("not the address path from the seed: %v", err)
			}

			cx, err := lnurlcash.CashNodeToCx1(node)
			if err != nil {
				t.Fatal(err)
			}
			if got := lnurlcash.EncodeCx1(cx.PubkeyXOnly, cx.ChainCode); got != testCase.Cx1 {
				t.Errorf("cx1 = %s, want %s", got, testCase.Cx1)
			}
			watched, err := lnurlcash.DecodeCx1(testCase.Cx1)
			if err != nil || watched != cx {
				t.Fatalf("cx1 does not decode to the branch: %v", err)
			}
			for _, note := range testCase.Notes {
				t.Run(fmt.Sprintf("index %d", note.Index), func(t *testing.T) {
					gradeNote(t, node, watched, note)
				})
			}
		})
	}
}

// ---- responses.json ----
//
// How a mutating callback's answer is classified, driven through the Client
// against a local server that answers exactly as each case says. `op` picks the
// call, and `output` and `change` the kind of note it mints: a hash unless the
// case says cp1, because only a cp1 is owed a certificate. Each case with only
// hash outputs is driven a second time through the call that draws its own
// secrets, so the vectors grade which outcomes carry those secrets out as well
// as how each is classified. Retries are off, so one case is one request: the
// replay has tests of its own.

type responseCase struct {
	Name            string          `json:"name"`
	Op              string          `json:"op"`
	Output          string          `json:"output"`
	Change          string          `json:"change"`
	HTTP            int             `json:"http"`
	Body            json.RawMessage `json:"body"`
	BodyRaw         *string         `json:"bodyRaw"`
	TransportError  bool            `json:"transportError"`
	Timeout         bool            `json:"timeout"`
	Expect          string          `json:"expect"`
	Why             string          `json:"why"`
	Signature       string          `json:"signature"`
	ChangeSignature string          `json:"changeSignature"`
}

// respond serves one case's answer and returns the callback to send it to.
func respond(t *testing.T, c responseCase) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case c.TransportError:
			// the request arrived; the answer never leaves
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
		case c.Timeout:
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		default:
			status := c.HTTP
			if status == 0 {
				status = http.StatusOK
			}
			body := []byte(c.Body)
			if c.BodyRaw != nil {
				body = []byte(*c.BodyRaw)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL + "/w/cb"
}

// outcomeOf names an answer in responses.json's own words.
func outcomeOf(err error) string {
	var service *lnurlcash.ServiceError
	switch {
	case err == nil:
		return "ok"
	case lnurlcash.IsUnverifiable(err):
		return "unverifiable"
	case errors.Is(err, lnurlcash.ErrNotePending):
		return "pending"
	case lnurlcash.IsSpent(err):
		return "spent"
	case lnurlcash.IsUnknownNote(err):
		return "unknown"
	case lnurlcash.IsAmbiguous(err):
		return "ambiguous"
	case errors.As(err, &service):
		return "error"
	}
	return fmt.Sprintf("unclassified (%T: %v)", err, err)
}

func gradeResponse(t *testing.T, c responseCase, mutation lnurlcash.Mutation, err error) {
	t.Helper()
	if got := outcomeOf(err); got != c.Expect {
		t.Fatalf("classified as %s, want %s (%s)", got, c.Expect, c.Why)
	}
	if err != nil {
		return
	}
	if mutation.Signature != c.Signature || mutation.ChangeSignature != c.ChangeSignature {
		t.Errorf("signatures = %q, %q; want %q, %q", mutation.Signature, mutation.ChangeSignature, c.Signature, c.ChangeSignature)
	}
	if c.Op == "melt" {
		var proof struct {
			PR     string `json:"pr"`
			Verify string `json:"verify"`
		}
		_ = json.Unmarshal(c.Body, &proof)
		if mutation.PR != proof.PR || mutation.VerifyURL != proof.Verify {
			t.Errorf("melt proof = %q, %q; want %q, %q", mutation.PR, mutation.VerifyURL, proof.PR, proof.Verify)
		}
	}
}

func TestResponseVectors(t *testing.T) {
	var vectors struct {
		Version     int               `json:"version"`
		Spec        string            `json:"spec"`
		Description string            `json:"description"`
		Outcomes    map[string]string `json:"outcomes"`
		Cases       []responseCase    `json:"cases"`
	}
	loadVectorsStrict(t, "responses.json", &vectors)
	if vectors.Version != 1 {
		t.Fatalf("responses.json is format version %d; these tests read version 1", vectors.Version)
	}

	// Every outcome this test tells apart, and whether it carries the fresh
	// secrets out: the ones that can describe a mutation that landed. A new
	// outcome is a new thing a wallet must do, and fails here until graded.
	carries := map[string]bool{
		"ok": false, "unverifiable": true, "pending": false, "spent": true,
		"unknown": true, "error": false, "ambiguous": true,
	}
	for outcome := range vectors.Outcomes {
		if _, graded := carries[outcome]; !graded {
			t.Errorf("outcome %q is not graded here", outcome)
		}
	}

	var cp1Outputs, cp1Changes int
	for _, c := range vectors.Cases {
		for _, kind := range []string{c.Output, c.Change} {
			if kind != "" && kind != "cp1" {
				t.Fatalf("%s: an output of kind %q, which this test cannot mint", c.Name, kind)
			}
		}
		if c.Output == "cp1" {
			cp1Outputs++
		}
		if c.Change == "cp1" {
			cp1Changes++
		}
	}
	if cp1Outputs == 0 || cp1Changes == 0 {
		t.Fatal("responses.json names no cp1 output or change - it predates lnurlcash-conformance v0.10.0")
	}

	k1 := strings.Repeat("a", 64)
	output, change := strings.Repeat("b", 64), strings.Repeat("c", 64)
	var key [32]byte
	for i := range key {
		key[i] = 0x0b
	}
	cp1 := lnurlcash.EncodeCp1(key)

	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if _, graded := carries[c.Expect]; !graded {
				t.Fatalf("expects %q, which this test does not grade", c.Expect)
			}
			callback := respond(t, c)
			client := lnurlcash.NewClient()
			client.MutationRetries = -1
			if c.Timeout {
				client.Timeout = 100 * time.Millisecond
			}
			first, second := output, change
			if c.Output == "cp1" {
				first = cp1
			}
			if c.Change == "cp1" {
				second = cp1
			}

			var mutation lnurlcash.Mutation
			var err error
			switch c.Op {
			case "melt":
				mutation, err = client.MeltNote(ctx(t), callback, k1, "lnbc210n1pjq")
			case "split":
				mutation, err = client.SplitNoteWithHash(ctx(t), callback, []string{k1}, 5000, first, second)
			case "mutation":
				mutation, err = client.RotateNoteWithHash(ctx(t), callback, k1, first)
			default:
				t.Fatalf("op %q is not a call this test drives", c.Op)
			}
			gradeResponse(t, c, mutation, err)
			// the caller named every output, so nothing of this package's rides out
			if carried := lnurlcash.NewSecrets(err); len(carried) != 0 {
				t.Errorf("carried %d secrets it never had", len(carried))
			}

			if c.Op == "melt" || c.Output == "cp1" || c.Change == "cp1" {
				return
			}
			// the same answer, to a call that drew its own secrets
			var drawn []string
			client.Secrets = func() (string, error) {
				drawn = append(drawn, secret(byte(0x40+len(drawn))))
				return drawn[len(drawn)-1], nil
			}
			if c.Op == "split" {
				notes, splitErr := client.SplitNote(ctx(t), callback, []string{k1}, 5000)
				mutation = lnurlcash.Mutation{Signature: notes.Signature, ChangeSignature: notes.ChangeSignature}
				err = splitErr
			} else {
				note, rotateErr := client.RotateNote(ctx(t), callback, k1)
				mutation = lnurlcash.Mutation{Signature: note.Signature}
				err = rotateErr
			}
			gradeResponse(t, c, mutation, err)
			carried := lnurlcash.NewSecrets(err)
			if !carries[c.Expect] {
				if len(carried) != 0 {
					t.Errorf("a %s outcome carried %d secrets", c.Expect, len(carried))
				}
				return
			}
			if strings.Join(carried, ",") != strings.Join(drawn, ",") {
				t.Errorf("a %s outcome carried %d secrets, want the %d drawn, in output order", c.Expect, len(carried), len(drawn))
			}
		})
	}
}

// ---- withdraw-info.json ----
//
// The informational GET, driven through the Client against a local server that
// answers with each case's body, byte for byte as the vector spells it. The
// queried URL is the vector's own, moved onto that server, so the request the
// Client actually sends is graded as well as how it reads the answer.

type withdrawInfoCase struct {
	Name            string          `json:"name"`
	Body            json.RawMessage `json:"body"`
	MaxWithdrawable *int64          `json:"maxWithdrawable"`
	Why             string          `json:"why"`
}

func TestWithdrawInfoVectors(t *testing.T) {
	var vectors struct {
		Version                  int                `json:"version"`
		Spec                     string             `json:"spec"`
		Description              string             `json:"description"`
		QueriedURL               string             `json:"queriedUrl"`
		RequestMustNotSend       []string           `json:"requestMustNotSend"`
		RequestMustSendUnchanged []string           `json:"requestMustSendUnchanged"`
		Accepted                 []withdrawInfoCase `json:"accepted"`
		Rejected                 []withdrawInfoCase `json:"rejected"`
	}
	loadVectorsStrict(t, "withdraw-info.json", &vectors)
	if vectors.Version != 1 {
		t.Fatalf("withdraw-info.json is format version %d; these tests read version 1", vectors.Version)
	}
	queried, err := url.Parse(vectors.QueriedURL)
	if err != nil {
		t.Fatalf("queriedUrl does not parse: %v", err)
	}

	fetch := func(t *testing.T, c withdrawInfoCase) (lnurlcash.WithdrawInfo, error) {
		t.Helper()
		sent := make(chan url.Values, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case sent <- r.URL.Query():
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(c.Body)
		}))
		t.Cleanup(server.Close)
		info, err := lnurlcash.NewClient().FetchNoteInfo(ctx(t), server.URL+queried.RequestURI())

		var query url.Values
		select {
		case query = <-sent:
		default:
			t.Fatal("no request reached the service")
		}
		for _, key := range vectors.RequestMustNotSend {
			if query.Has(key) {
				t.Errorf("sent %s, which the service must never see", key)
			}
		}
		for _, key := range vectors.RequestMustSendUnchanged {
			if got, want := query[key], queried.Query()[key]; strings.Join(got, "&") != strings.Join(want, "&") {
				t.Errorf("sent %s=%q, want it unchanged as %q", key, got, want)
			}
		}
		return info, err
	}

	for _, c := range vectors.Accepted {
		t.Run("accepted/"+c.Name, func(t *testing.T) {
			if c.MaxWithdrawable == nil {
				t.Fatal("an accepted case states no maxWithdrawable to grade")
			}
			info, err := fetch(t, c)
			if err != nil {
				t.Fatalf("refused: %v (%s)", err, c.Why)
			}
			if info.MaxWithdrawableMsat != *c.MaxWithdrawable {
				t.Errorf("worth %d msat, want %d", info.MaxWithdrawableMsat, *c.MaxWithdrawable)
			}
		})
	}
	for _, c := range vectors.Rejected {
		t.Run("rejected/"+c.Name, func(t *testing.T) {
			if c.MaxWithdrawable != nil {
				t.Fatal("a rejected case states a maxWithdrawable, which nothing can grade")
			}
			info, err := fetch(t, c)
			var protocol *lnurlcash.ProtocolError
			if !asProtocol(err, &protocol) {
				t.Fatalf("got %v and a note worth %d msat, want a ProtocolError (%s)", err, info.MaxWithdrawableMsat, c.Why)
			}
		})
	}
}
