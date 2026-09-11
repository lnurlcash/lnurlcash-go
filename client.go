package lnurlcash

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client performs the GETs. It is deliberately thin: everything about the
// protocol lives in the Request/Parse pairs above, and this only classifies a
// failure by whether the request could have been processed.
//
// A caller with its own HTTP stack should use those directly and skip this.
type Client struct {
	// HTTP performs the requests.
	//
	// A replacement MUST NOT retry. See NewClient for why, at length: it is the
	// sharpest edge in this package, and it is not obvious.
	HTTP *http.Client

	// Timeout bounds every request. Without one a hung service blocks forever.
	Timeout time.Duration

	// Offline refuses to make any request at all. For a caller that wants
	// certainty nothing reaches the network, rather than trusting that it
	// happens not to.
	Offline bool

	// Secrets supplies replacement note secrets. Nil means the OS CSPRNG.
	Secrets SecretSource

	// Policy is what this client insists a service does. The zero value
	// requires the offline verification LUD-25 makes mandatory.
	Policy Policy

	// MutationRetries is how many times to re-send a rotate, split or merge
	// whose outcome the transport lost.
	//
	// LUD-25 requires a service to answer a byte-identical retry with the
	// original success ("Retrying a mutation"), so re-sending resolves the
	// ambiguity rather than compounding it: a conforming service replays, and
	// one that refuses leaves the caller exactly where an un-retried failure
	// would have.
	//
	// Never applied to a melt, which carries pr, is paid out asynchronously and
	// has no replay guarantee at all. Zero means the DEFAULT of one attempt
	// beyond the first; use a negative number to turn retrying off entirely,
	// so the zero value of a bare Client behaves like NewClient.
	MutationRetries int
}

// mutationRetries resolves the field's zero value to the default.
func (c *Client) mutationRetries() int {
	if c.MutationRetries < 0 {
		return 0
	}
	if c.MutationRetries == 0 {
		return 1
	}
	return c.MutationRetries
}

// NewClient returns a Client that retries a mutation deliberately, and whose
// HTTP transport will not do it behind the client's back.
//
// This is the most important thing in this file, and it is worth saying why in
// full.
//
// Every LNURLcash mutation - rotate, split, merge, melt - is an HTTP GET. HTTP
// considers GET idempotent, so a transport may resend one when a connection
// fails mid-flight. An LNURLcash mutation is emphatically not idempotent: the
// first attempt burns the input note.
//
// For most of this draft's life that was fatal. A service applied a rotate, the
// connection dropped, a retrying transport sent it again, and the second
// attempt got "invalid or already spent k1" - a definitive rejection. The
// caller concluded nothing had happened and discarded the fresh secret, which
// was the only copy of the note the service had just minted. The money was
// gone, and every layer had behaved reasonably.
//
// Go's net/http does exactly that resend, under a condition that is easy to
// miss: it retries an idempotent request when it was sent on a REUSED
// connection. A client with no Transport of its own uses
// http.DefaultTransport, whose connection pool is shared process-wide - so
// whether a mutation was silently retried depended on whether some unrelated
// code happened to talk to the same host first.
//
// LUD-25 closed the hole at the other end: a service MUST now answer a
// byte-identical rotate, split or merge with the success it already returned,
// signature and all. So this client re-sends one whose answer was lost, on
// purpose and bounded, and a lost answer usually resolves into a completed
// mutation. See MutationRetries.
//
// Keep-alives stay disabled all the same. A deliberate retry this package
// counts is a different thing from an invisible one it does not, a service that
// has not caught up still answers the second attempt as already spent, and the
// cost - a fresh connection per request, for a wallet making a handful of them
// - is not worth weighing against leaving that to chance with somebody's
// money.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				Proxy:             http.ProxyFromEnvironment,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Timeout: 30 * time.Second,
	}
}

func (c *Client) secret() (string, error) {
	if c.Secrets != nil {
		return c.Secrets()
	}
	return GenerateNoteSecret()
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	// Never http.DefaultClient: its transport pools connections process-wide,
	// which is the condition under which net/http silently retries a mutation.
	// A zero-value Client gets the same safe transport NewClient builds.
	return NewClient().HTTP
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 30 * time.Second
}

// do performs one request, classifying every failure by whether the service
// could have processed it.
func (c *Client) do(ctx context.Context, request Request) ([]byte, error) {
	attach := func(err error) error {
		var ambiguous *AmbiguousError
		if asAmbiguous(err, &ambiguous) {
			ambiguous.NewSecrets = request.NewSecrets
		}
		return err
	}

	if c.Offline {
		return nil, fmt.Errorf("%w: offline mode is on - no request was made", ErrRequestRefused)
	}
	if !IsAllowedServiceURL(request.URL) {
		return nil, fmt.Errorf(
			"%w: refusing to fetch that URL - only https, or http to a loopback or .onion host, is allowed",
			ErrRequestRefused,
		)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, request.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestRefused, err)
	}
	response, err := c.httpClient().Do(httpRequest)
	if err != nil {
		// Transport failures are ambiguous for a mutating request: the request
		// may well have arrived, and only the answer was lost.
		return nil, attach(&AmbiguousError{
			Detail: "failed to reach the service, or its answer was lost - the request may still have been processed",
			Cause:  err,
		})
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, attach(&AmbiguousError{
			Detail: "the service's response could not be read",
			Cause:  err,
		})
	}
	return body, nil
}

// FetchNoteInfo performs the informational GET. It never burns the note.
func (c *Client) FetchNoteInfo(ctx context.Context, noteURL string) (WithdrawInfo, error) {
	request, err := NoteInfoRequest(noteURL)
	if err != nil {
		return WithdrawInfo{}, err
	}
	body, err := c.do(ctx, request)
	if err != nil {
		return WithdrawInfo{}, err
	}
	return ParseNoteInfo(body, noteURL, c.Policy)
}

// FetchNoteInfoByHash performs the informational GET by hash rather than by
// secret, so the service learns which note is being asked about but never what
// spends it. h is a hash, or a Part 2 note's cp1; NoteLookupOf gives the right
// one for either kind of k1.
//
// The form to use for any lookup not immediately followed by a mutation -
// checking a balance, and above all walking a derivation during a restore.
// A rejection proves nothing: see BuildNoteInfoURLByHash.
func (c *Client) FetchNoteInfoByHash(ctx context.Context, withdrawLink, h string) (WithdrawInfo, error) {
	lookup := BuildNoteInfoURLByHash(withdrawLink, h)
	if lookup == "" {
		return WithdrawInfo{}, fmt.Errorf("%w: a note lookup is 32 bytes of hex or a cp1, on a withdraw link that parses", ErrRequestRefused)
	}
	body, err := c.do(ctx, Request{URL: lookup})
	if err != nil {
		return WithdrawInfo{}, err
	}
	return ParseNoteInfoByHash(body, c.Policy)
}

// FetchMintAddress performs the experimental mint-address GET.
func (c *Client) FetchMintAddress(ctx context.Context, rawURL string) (MintAddress, error) {
	request, err := MintAddressRequest(rawURL)
	if err != nil {
		return MintAddress{}, err
	}
	body, err := c.do(ctx, request)
	if err != nil {
		return MintAddress{}, err
	}
	return ParseMintAddress(body)
}

// mutate performs one mutating GET, re-sending it while the transport keeps
// losing the answer.
//
// LUD-25's "Retrying a mutation" is what makes this safe and what makes it
// useful: a service MUST answer a byte-identical rotate, split or merge with
// the success it returned the first time, rather than with the already-spent
// refusal its burned inputs would otherwise earn.
//
// The same Request goes out each time rather than a rebuilt one, because the
// replay is matched on the k1 set, h, h2 and amount. Regenerating a secret
// between attempts would make the retry a DIFFERENT mutation, and against a
// service that had already applied the first, a second real burn.
//
// Only ambiguity is retried. A definitive refusal is the service's considered
// answer and asking again cannot improve it. A melt is never retried at all.
func (c *Client) mutate(ctx context.Context, request Request, err error, kind MutationKind) (Mutation, error) {
	if err != nil {
		return Mutation{}, err
	}
	attempts := c.mutationRetries()
	if kind == MutationMelt {
		attempts = 0
	}
	var lost error
	for attempt := 0; attempt <= attempts; attempt++ {
		body, err := c.do(ctx, request)
		if err == nil {
			var mutation Mutation
			mutation, err = ParseMutation(body, request.NewSecrets, kind, c.Policy)
			if err == nil {
				return mutation, nil
			}
		}
		if !IsAmbiguous(err) {
			return Mutation{}, err
		}
		lost = err
	}
	return Mutation{}, lost
}

// MeltNote burns a note; the service pays pr of exactly its value.
//
// Success means the payment is IN FLIGHT, not that the note is spent.
func (c *Client) MeltNote(ctx context.Context, callback, k1, pr string) (Mutation, error) {
	request, err := MeltRequest(callback, k1, pr)
	return c.mutate(ctx, request, err, MutationMelt)
}

// RotatedNote is a note this wallet now holds, whose secret the service has
// never seen.
type RotatedNote struct {
	K1        string
	Signature string
}

// SplitNotes are the two notes a split produced.
type SplitNotes struct {
	K1              string
	Change          string
	Signature       string
	ChangeSignature string
}

// RotateNote burns k1 and mints a fresh secret of the same value, which this
// wallet generates and the service never sees.
//
// On an ambiguous failure the fresh secret rides the error - see NewSecrets.
func (c *Client) RotateNote(ctx context.Context, callback, k1 string) (RotatedNote, error) {
	fresh, err := c.secret()
	if err != nil {
		return RotatedNote{}, err
	}
	request, err := RotateRequest(callback, k1, fresh)
	mutation, err := c.mutate(ctx, request, err, MutationRotate)
	if err != nil {
		return RotatedNote{}, err
	}
	return RotatedNote{K1: fresh, Signature: mutation.Signature}, nil
}

// SplitNote burns one or many notes, minting one worth amountMsat and one
// carrying the remainder.
func (c *Client) SplitNote(ctx context.Context, callback string, k1s []string, amountMsat int64) (SplitNotes, error) {
	fresh, err := c.secret()
	if err != nil {
		return SplitNotes{}, err
	}
	change, err := c.secret()
	if err != nil {
		return SplitNotes{}, err
	}
	request, err := SplitRequest(callback, k1s, amountMsat, fresh, change)
	mutation, err := c.mutate(ctx, request, err, MutationSplit)
	if err != nil {
		return SplitNotes{}, err
	}
	return SplitNotes{
		K1:              fresh,
		Change:          change,
		Signature:       mutation.Signature,
		ChangeSignature: mutation.ChangeSignature,
	}, nil
}

// MergeNotes burns all the given notes and mints one worth their sum.
func (c *Client) MergeNotes(ctx context.Context, callback string, k1s []string) (RotatedNote, error) {
	fresh, err := c.secret()
	if err != nil {
		return RotatedNote{}, err
	}
	request, err := MergeRequest(callback, k1s, fresh)
	mutation, err := c.mutate(ctx, request, err, MutationMerge)
	if err != nil {
		return RotatedNote{}, err
	}
	return RotatedNote{K1: fresh, Signature: mutation.Signature}, nil
}

// The hash-parameterised mutations: the caller supplies each output rather than
// having this client draw a secret for it. What a hardware wallet drives, where
// the secret never enters this process - and the only way to mint to a Part 2
// key, which the caller derives (DeriveNotePubkey) and passes as a cp1.
//
// A k1 may be a Part 1 secret or a Part 2 ck1, and outputs may be hashes or
// cp1s, mixed freely. Retried exactly as RotateNote is. There are no NewSecrets
// on any error: the caller already holds whatever the outputs belong to, and
// must have persisted it - with the index it came from - before calling.

// RotateNoteWithHash burns k1 and mints a note of the same value to h.
func (c *Client) RotateNoteWithHash(ctx context.Context, callback, k1, h string) (Mutation, error) {
	request, err := RotateRequestWithHash(callback, k1, h)
	return c.mutate(ctx, request, err, MutationRotate)
}

// SplitNoteWithHash burns k1s, minting amountMsat to h and the remainder to h2.
func (c *Client) SplitNoteWithHash(ctx context.Context, callback string, k1s []string, amountMsat int64, h, h2 string) (Mutation, error) {
	request, err := SplitRequestWithHash(callback, k1s, amountMsat, h, h2)
	return c.mutate(ctx, request, err, MutationSplit)
}

// MergeNotesWithHash burns k1s and mints one note worth their sum to h.
func (c *Client) MergeNotesWithHash(ctx context.Context, callback string, k1s []string, h string) (Mutation, error) {
	request, err := MergeRequestWithHash(callback, k1s, h)
	return c.mutate(ctx, request, err, MutationMerge)
}

// FetchPayRequest reads a mint's payRequest.
func (c *Client) FetchPayRequest(ctx context.Context, rawURL string) (PayRequest, error) {
	request, err := PayRequestRequest(rawURL)
	if err != nil {
		return PayRequest{}, err
	}
	body, err := c.do(ctx, request)
	if err != nil {
		return PayRequest{}, err
	}
	return ParsePayRequest(body)
}

// RequestInvoice asks for a plain LUD-06 invoice. It mints nothing: it names no
// output.
func (c *Client) RequestInvoice(ctx context.Context, payCallback string, amountMsat int64) (Invoice, error) {
	request, err := InvoiceRequest(payCallback, amountMsat)
	if err != nil {
		return Invoice{}, err
	}
	body, err := c.do(ctx, request)
	if err != nil {
		return Invoice{}, err
	}
	return ParseInvoice(body, amountMsat)
}

// RequestMintInvoice asks for an invoice that mints a note the caller already
// holds the secret to.
//
// Persist mintSecret before paying the invoice this returns. The service only
// ever learns its hash, so it cannot help reconstruct it, and a paid invoice
// whose secret was lost is a note nobody can spend.
func (c *Client) RequestMintInvoice(ctx context.Context, payCallback string, amountMsat int64, mintSecret string) (Invoice, error) {
	request, err := MintInvoiceRequest(payCallback, amountMsat, mintSecret)
	if err != nil {
		return Invoice{}, err
	}
	body, err := c.do(ctx, request)
	if err != nil {
		return Invoice{}, err
	}
	return ParseInvoice(body, amountMsat)
}

// RequestMintInvoiceWithHash asks for an invoice that mints to an output the
// caller names: a hash, or a Part 2 cp1, which goes as the comment alone. See
// MintInvoiceRequestWithHash.
func (c *Client) RequestMintInvoiceWithHash(ctx context.Context, payCallback string, amountMsat int64, h string) (Invoice, error) {
	request, err := MintInvoiceRequestWithHash(payCallback, amountMsat, h)
	if err != nil {
		return Invoice{}, err
	}
	body, err := c.do(ctx, request)
	if err != nil {
		return Invoice{}, err
	}
	return ParseInvoice(body, amountMsat)
}

// FetchInvoiceStatus polls a LUD-21 verify URL.
func (c *Client) FetchInvoiceStatus(ctx context.Context, verifyURL string) (InvoiceStatus, error) {
	request, err := VerifyRequest(verifyURL)
	if err != nil {
		return InvoiceStatus{}, err
	}
	body, err := c.do(ctx, request)
	if err != nil {
		return InvoiceStatus{}, err
	}
	return ParseVerify(body)
}

// NoteFate is what a probe learned about a note whose fate was uncertain.
type NoteFate string

const (
	// NoteLive means the request never landed, so the fresh secrets minted
	// nothing and can be discarded.
	NoteLive NoteFate = "live"
	// NoteGone means the burn landed, and the carried secrets are the only money
	// left.
	NoteGone NoteFate = "gone"
	// NoteFateUnknown means the probe itself failed. No information either way -
	// keep everything.
	NoteFateUnknown NoteFate = "unknown"
)

// ProbeBurnedNote answers, after an ambiguous mutation, whether the burn
// actually happened.
func (c *Client) ProbeBurnedNote(ctx context.Context, noteURL string) NoteFate {
	_, err := c.FetchNoteInfo(ctx, noteURL)
	switch {
	case err == nil:
		return NoteLive
	case IsSpent(err), IsUnknownNote(err):
		return NoteGone
	default:
		return NoteFateUnknown
	}
}

// SettledNote is a note resolved against what the service says it is worth.
type SettledNote struct {
	K1         string
	AmountMsat int64
	Signature  string
	Callback   string
}

// SettleNote resolves what a split's change or a merge's output is ACTUALLY
// worth, then rotates it before further use.
//
// Neither response carries an amount - the spec's only source of truth is an
// informational GET - and a fee-charging service may have deducted from a
// split's change or refunded into a merge's result. That GET puts k1 on the
// wire, so a rotate follows, best-effort.
//
// "Best-effort" covers a rotate the service definitively refused on policy
// grounds: nothing was burned, so the exposed k1 and its signature are still
// the note. It cannot cover a rotate that MAY HAVE APPLIED. This used to
// discard the error entirely and return nil, so a caller could not even ask:
// when the request had landed, that k1 was burned and the fresh secret
// carried on the error was the only copy of the note the service had just
// minted.
func (c *Client) SettleNote(ctx context.Context, baseURL, k1 string, expectedAmountMsat int64, signature string) (SettledNote, error) {
	noteURL := WithNewK1(baseURL, k1, expectedAmountMsat, signature)
	if noteURL == "" {
		return SettledNote{}, fmt.Errorf("%w: that note URL does not parse", ErrRequestRefused)
	}
	info, err := c.FetchNoteInfo(ctx, noteURL)
	if err != nil {
		return SettledNote{}, err
	}
	rotated, err := c.RotateNote(ctx, info.Callback, k1)
	if err != nil {
		// NewSecrets is non-empty for exactly the errors that could be
		// describing a mutation the service applied - ambiguous, unverifiable,
		// or a spent/unknown refusal, which is also what an already-applied
		// mutation looks like asked a second time - and empty for a refusal
		// that burned nothing. Only the latter may be reported as a settled
		// note.
		if IsAmbiguous(err) || len(NewSecrets(err)) > 0 {
			return SettledNote{}, err
		}
		return SettledNote{
			K1:         k1,
			AmountMsat: info.MaxWithdrawableMsat,
			Signature:  signature,
			Callback:   info.Callback,
		}, nil
	}
	return SettledNote{
		K1:         rotated.K1,
		AmountMsat: info.MaxWithdrawableMsat,
		Signature:  rotated.Signature,
		Callback:   info.Callback,
	}, nil
}
