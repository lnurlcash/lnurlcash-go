package lnurlcash_test

// Every assertion here comes from lnurlcash-conformance, the same files the
// TypeScript, Python, Rust and Kotlin implementations are held to. Nothing in
// this file states what the protocol is - the vectors do.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lnurlcash "github.com/lnurlcash/lnurlcash-go"
)

func vectorsDir(t *testing.T) string {
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
