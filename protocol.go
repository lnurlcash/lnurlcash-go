package lnurlcash

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The protocol itself, with no I/O in it.
//
// Every operation is a Request - a URL to GET, plus the fresh secrets that must
// survive if the answer is lost - paired with a Parse* function for what comes
// back. A caller with its own HTTP stack needs nothing else; Client is a thin
// loop over exactly these.

// Request is one GET, and the secrets whose loss would destroy money.
type Request struct {
	URL string
	// NewSecrets are the fresh wallet-generated secrets this request disclosed
	// the hashes of. If the outcome turns out to be unknown they may be the only
	// copies of notes the service has already minted, so persist them before
	// performing the GET.
	NewSecrets []string
}

// Policy is what this package insists a service does, rather than merely hopes
// it does.
//
// LUD-25 makes offline verification mandatory: a service MUST publish
// mintPubkey and MUST sign every note a rotate, split or merge mints. A wallet
// that quietly accepted unsigned notes would be handing its holder something
// nobody downstream can check, which is the exact gap offline verification
// exists to close - so the zero value insists.
//
// Set RequireSignatures false only to talk to a service that predates the
// requirement, and only knowing the cost.
type Policy struct {
	// AllowUnsignedNotes turns the requirement off. Named for what it permits
	// rather than what it demands, so the zero-value Policy is the strict one
	// and a caller has to say the dangerous thing out loud.
	AllowUnsignedNotes bool
}

// RequireSignatures reports whether this policy insists on verifiable notes.
func (p Policy) RequireSignatures() bool { return !p.AllowUnsignedNotes }

// MutationKind says which mutation a response is being read as, which decides
// what it must carry. A melt mints nothing, so it has no signature to return
// and none is required; a split mints two notes and owes one over each.
type MutationKind int

const (
	MutationMelt MutationKind = iota
	MutationRotate
	MutationSplit
	MutationMerge
)

// IsCompressedPubkey reports whether value is a compressed secp256k1 point: 33
// bytes hex, the leading byte naming which of the two y values the x
// coordinate stands for.
//
// Checked at the response rather than at the first signature check, because a
// mintPubkey that is not one verifies nothing - and the same fault found later
// looks like a forged note instead of a broken mint.
func IsCompressedPubkey(value string) bool {
	key := strings.ToLower(strings.TrimSpace(value))
	if len(key) != 66 || (!strings.HasPrefix(key, "02") && !strings.HasPrefix(key, "03")) {
		return false
	}
	for _, r := range key {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

// WithdrawInfo is the informational GET's answer.
type WithdrawInfo struct {
	Callback string
	K1       string
	// MaxWithdrawableMsat is the ONLY authoritative statement of what a note is
	// worth. The amount in a note URL is an unverified claim.
	MaxWithdrawableMsat int64
	MinWithdrawableMsat int64
	DefaultDescription  string
	// MintPubkey is the key this service's note signatures verify against.
	//
	// LUD-25 makes offline verification mandatory, so a conforming service
	// always publishes it here. Only ever empty when the caller passed a Policy
	// with RequireSignatures false.
	MintPubkey string
}

// MintAddress is the experimental withdraw-side discovery response.
type MintAddress struct {
	Callback            string
	PayLink             string
	MaxWithdrawableMsat int64
	MinWithdrawableMsat int64
	// The wire field is mintPubkey, but at this endpoint it is never a note's
	// signing key - always the service's own node identity.
	NodePubkey string
	NodeAlias  string
	NodeURI    string
	NodeColor  string
	// The wire field is nodeCapacity, msat like every other amount here -
	// suffixed so a caller cannot read it as sats. Zero on all three means
	// the service advertised nothing, the same as an empty NodeAlias.
	NodeCapacityMsat int64
	NodeNumChannels  int64
	NodeNumPeers     int64
	// Every address the service's node announces, each already
	// "node_key@host:port". NodeURI is the first of them; a node behind Tor
	// as well as clearnet has more, and a caller that can only reach the
	// other one needs the whole list. Nil, never an empty slice, when the
	// service announces nothing.
	NodeURIs []string
	// The day the service plans to close, ISO-8601 ("2026-12-31"). Advance
	// warning while there is still time to spend, deliberately not the same
	// thing as a mint that has already stopped minting. Nothing enforces it
	// and nothing verifies it, so it is a prompt to move notes, never a
	// deadline to compute against. Empty when the service published none, or
	// published something that is not a real calendar day.
	SunsetDate string
	// What the service says it owes, msat: every note it has issued and not
	// burned. A pointer, unlike every other number here, because zero is a
	// real answer - "owes nothing" and "will not say" are different things to
	// know about a custodian, and the zero value cannot tell them apart.
	OutstandingNotesMsat *int64
}

// PayRequest is a LUD-06 payRequest, extended per LUD-25.
type PayRequest struct {
	Callback        string
	MinSendableMsat int64
	MaxSendableMsat int64
	Metadata        string
	// WithdrawLink is present when paying this mints a bearer note. It is the
	// raw LUD-17 withdraw endpoint, in either the plain or the lnurlw://
	// spelling: the draft says "as described in LUD-17", and LUD-17 describes
	// both, so a wallet accepts either unchanged.
	WithdrawLink string
	MintPubkey   string
	// MintFee is valid only when HasMintFee is true. Absent means the service
	// advertised none, which the spec reads as fee-free rather than unknown.
	MintFee    MintFee
	HasMintFee bool
	// CommentAllowed is LUD-12's field and LUD-25's minting capability, valid
	// only when HasCommentAllowed is true. A mint must allow the 64 characters
	// a hex-encoded SHA-256 commitment needs.
	CommentAllowed    int64
	HasCommentAllowed bool
	// MintToHash is an additive ForgeSworn extension: the service also accepts
	// the same commitment as an h parameter. Never a substitute for the
	// mandatory comment, and anything that is not exactly true reads as false.
	MintToHash bool
}

// MintCommentLength is the exact comment capacity minting needs: 32 bytes as
// lowercase hex.
const MintCommentLength = 64

// NamesMintOutput reports whether this service can mint a current-draft LUD-25
// note.
//
// MintToHash alone cannot stand in for it: that extension is additive and
// predates the comment spelling, and a service without the comment capacity has
// nowhere to put the commitment.
func (p PayRequest) NamesMintOutput() bool {
	return p.HasCommentAllowed && p.CommentAllowed >= MintCommentLength
}

// Invoice is a payRequest callback's answer.
type Invoice struct {
	PR        string
	VerifyURL string
	// Disposable follows LUD-11: absent on the wire MUST be read as true.
	Disposable bool
}

// InvoiceStatus is a LUD-21 verify answer.
type InvoiceStatus struct {
	Settled bool
	// Preimage, for LNURLcash, IS the bearer note's spend secret. Rotate at once.
	Preimage string
	PR       string
}

// Mutation is a mutating callback's answer.
type Mutation struct {
	Signature       string
	ChangeSignature string
	// PR and VerifyURL form the optional LUD-25 melt proof.
	PR        string
	VerifyURL string
}

func withParams(rawURL string, params [][2]string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	// append, never replace: a merge repeats the k1 parameter, and a callback may
	// already carry parameters of its own
	pairs := parseOrdered(parsed.RawQuery)
	pairs = append(pairs, params...)
	parsed.RawQuery = encodePairs(pairs)
	return parsed.String(), nil
}

func decode(body []byte) (map[string]any, error) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, &AmbiguousError{Detail: "the service returned an unreadable response", Cause: err}
	}
	return parsed, nil
}

// rejectError turns a service's ERROR into a definitive failure. The reason is
// carried through exactly as sent, empty included.
func rejectError(body map[string]any) error {
	if status, _ := body["status"].(string); status == "ERROR" {
		reason, _ := body["reason"].(string)
		return &ServiceError{Reason: reason}
	}
	return nil
}

func str(body map[string]any, key string) string {
	value, _ := body[key].(string)
	return value
}

// Non-empty strings only, and nil rather than an empty slice for a list that
// had none: a caller testing len() and one testing != nil have to reach the
// same conclusion about a service that announced nothing.
func strList(body map[string]any, key string) []string {
	raw, ok := body[key].([]any)
	if !ok {
		return nil
	}
	var entries []string
	for _, item := range raw {
		if text, ok := item.(string); ok && text != "" {
			entries = append(entries, text)
		}
	}
	return entries
}

// A calendar day, YYYY-MM-DD, and nothing else. A timestamp, a
// locale-formatted date or a typo is dropped rather than passed on, because
// the one thing a wallet does with this is put it in front of a holder and a
// wrong date there is worse than no date. time.Parse with a strict layout
// rejects 2026-02-31 rather than rolling it forward to March, which is what
// makes it the right tool here.
func isoDate(body map[string]any, key string) string {
	raw, ok := body[key].(string)
	if !ok {
		return ""
	}
	parsed, err := time.Parse(time.DateOnly, raw)
	if err != nil || parsed.Format(time.DateOnly) != raw {
		return ""
	}
	return raw
}

func msat(body map[string]any, key string) (int64, bool) {
	switch value := body[key].(type) {
	case float64:
		return int64(value), true
	case json.Number:
		parsed, err := value.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

// ---- the informational GET ----

// NoteInfoRequest builds the LUD-03 informational GET. It never burns, rotates
// or alters the note.
//
// sig is stripped before the request: it is only meaningful to a holder
// inspecting the note locally, since the service already knows what it signed.
// k1 and amount are left as they are.
func NoteInfoRequest(noteURL string) (Request, error) {
	parsed, err := url.Parse(noteURL)
	if err != nil {
		return Request{}, fmt.Errorf("%w: that note URL does not parse", ErrRequestRefused)
	}
	pairs := parseOrdered(parsed.RawQuery)
	kept := pairs[:0]
	for _, pair := range pairs {
		if pair[0] != "sig" {
			kept = append(kept, pair)
		}
	}
	parsed.RawQuery = encodePairs(kept)
	return Request{URL: parsed.String()}, nil
}

// ParseNoteInfo reads an informational GET's answer.
func ParseNoteInfo(body []byte, queriedURL string, policy Policy) (WithdrawInfo, error) {
	parsed, err := decode(body)
	if err != nil {
		return WithdrawInfo{}, err
	}
	if err := rejectError(parsed); err != nil {
		var service *ServiceError
		_ = asService(err, &service)
		return WithdrawInfo{}, classifyNoteError(service.Reason)
	}
	invalid := &ProtocolError{Detail: "not a withdrawRequest (unexpected response)"}
	if str(parsed, "tag") != "withdrawRequest" {
		return WithdrawInfo{}, invalid
	}
	callback, k1 := str(parsed, "callback"), str(parsed, "k1")
	maximum, ok := msat(parsed, "maxWithdrawable")
	if callback == "" || k1 == "" || !ok || maximum < 0 {
		return WithdrawInfo{}, invalid
	}
	minimum := int64(0)
	if _, present := parsed["minWithdrawable"]; present && parsed["minWithdrawable"] != nil {
		minimum, ok = msat(parsed, "minWithdrawable")
		if !ok || minimum < 0 || minimum > maximum {
			return WithdrawInfo{}, invalid
		}
	}
	// Spec MUST: the response's k1 is the bearer secret itself, never a derived
	// or opaque id. A service returning something else for the k1 it was queried
	// with is non-compliant - or the note was rotated by somebody else, which
	// matters more.
	if queried := NoteK1(queriedURL); queried != "" && !sameNote(k1, queried) {
		return WithdrawInfo{}, &ProtocolError{
			Detail: "the service echoed back a different k1 than was queried - the note may have been redeemed elsewhere, or the service isn't spec-compliant",
		}
	}
	mintPubkey := str(parsed, "mintPubkey")
	// Separate from the shape check above, and separately worded: this response
	// IS a withdrawRequest, it just describes a note nobody can check offline.
	// Saying "not a withdrawRequest" would send a caller after the wrong fault.
	if policy.RequireSignatures() && !IsCompressedPubkey(mintPubkey) {
		detail := "this service published a mintPubkey that is not a 33-byte compressed secp256k1 key"
		if mintPubkey == "" {
			detail = "this service publishes no mintPubkey, so its notes cannot be verified offline (LUD-25 requires one)"
		}
		return WithdrawInfo{}, &ProtocolError{Detail: detail}
	}
	return WithdrawInfo{
		Callback:            callback,
		K1:                  strings.ToLower(k1),
		MaxWithdrawableMsat: maximum,
		MinWithdrawableMsat: minimum,
		DefaultDescription:  str(parsed, "defaultDescription"),
		MintPubkey:          strings.ToLower(strings.TrimSpace(mintPubkey)),
	}, nil
}

// sameNote reports whether two k1s name one note. A Part 1 secret has one
// spelling, but a Part 2 note has as many valid ck1s as a signer has nonces -
// and anyone can flip a signature to its high-S twin - so a service echoing a
// different ck1 that recovers to the same key has named the same note, not a
// different one.
func sameNote(a, b string) bool {
	if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) {
		return true
	}
	idA, errA := NoteIDOf(a)
	idB, errB := NoteIDOf(b)
	return errA == nil && errB == nil && idA == idB
}

// ParseNoteInfoByHash reads the same response, for a lookup that named the
// note by its hash - or, for a Part 2 note, by its cp1.
//
// Differs from ParseNoteInfo in exactly two places, both because there was no
// secret in the request: k1 is not required in the response, and there is no
// echo to check against. Everything else - the shape, and the mandatory
// mintPubkey - is enforced identically, because a note nobody can verify
// offline is no more acceptable when it was looked up privately.
//
// K1 on the returned value is empty: a conforming service has nothing to echo
// when the request never named a secret, and the caller already holds it.
func ParseNoteInfoByHash(body []byte, policy Policy) (WithdrawInfo, error) {
	parsed, err := decode(body)
	if err != nil {
		return WithdrawInfo{}, err
	}
	if err := rejectError(parsed); err != nil {
		var service *ServiceError
		_ = asService(err, &service)
		return WithdrawInfo{}, classifyNoteError(service.Reason)
	}
	invalid := &ProtocolError{Detail: "not a withdrawRequest (unexpected response)"}
	if str(parsed, "tag") != "withdrawRequest" {
		return WithdrawInfo{}, invalid
	}
	callback := str(parsed, "callback")
	maximum, ok := msat(parsed, "maxWithdrawable")
	if callback == "" || !ok || maximum < 0 {
		return WithdrawInfo{}, invalid
	}
	minimum := int64(0)
	if _, present := parsed["minWithdrawable"]; present && parsed["minWithdrawable"] != nil {
		minimum, ok = msat(parsed, "minWithdrawable")
		if !ok || minimum < 0 || minimum > maximum {
			return WithdrawInfo{}, invalid
		}
	}
	mintPubkey := str(parsed, "mintPubkey")
	if policy.RequireSignatures() && !IsCompressedPubkey(mintPubkey) {
		detail := "this service published a mintPubkey that is not a 33-byte compressed secp256k1 key"
		if mintPubkey == "" {
			detail = "this service publishes no mintPubkey, so its notes cannot be verified offline (LUD-25 requires one)"
		}
		return WithdrawInfo{}, &ProtocolError{Detail: detail}
	}
	return WithdrawInfo{
		Callback:            callback,
		MaxWithdrawableMsat: maximum,
		MinWithdrawableMsat: minimum,
		DefaultDescription:  str(parsed, "defaultDescription"),
		MintPubkey:          strings.ToLower(strings.TrimSpace(mintPubkey)),
	}, nil
}

// MintAddressRequest builds the experimental mint-address GET. Best-effort
// discovery: most services will not have it, and a rejection means "no extra
// information", not a failure.
func MintAddressRequest(rawURL string) (Request, error) {
	return Request{URL: rawURL}, nil
}

// ParseMintAddress reads a mint-address answer.
func ParseMintAddress(body []byte) (MintAddress, error) {
	parsed, err := decode(body)
	if err != nil {
		return MintAddress{}, err
	}
	if err := rejectError(parsed); err != nil {
		return MintAddress{}, err
	}
	invalid := &ProtocolError{Detail: "not a mint address response (unexpected shape)"}
	if str(parsed, "tag") != "withdrawRequest" {
		return MintAddress{}, invalid
	}
	maximum, ok := msat(parsed, "maxWithdrawable")
	if str(parsed, "callback") == "" || str(parsed, "payLink") == "" || !ok {
		return MintAddress{}, invalid
	}
	minimum, _ := msat(parsed, "minWithdrawable")
	capacity, _ := msat(parsed, "nodeCapacity")
	channels, _ := msat(parsed, "nodeNumChannels")
	peers, _ := msat(parsed, "nodeNumPeers")
	var outstanding *int64
	if owed, ok := msat(parsed, "outstandingNotesMsat"); ok {
		outstanding = &owed
	}
	return MintAddress{
		Callback:             str(parsed, "callback"),
		PayLink:              str(parsed, "payLink"),
		MaxWithdrawableMsat:  maximum,
		MinWithdrawableMsat:  minimum,
		NodePubkey:           str(parsed, "mintPubkey"),
		NodeAlias:            str(parsed, "nodeAlias"),
		NodeURI:              str(parsed, "nodeUri"),
		NodeColor:            str(parsed, "nodeColor"),
		NodeCapacityMsat:     capacity,
		NodeNumChannels:      channels,
		NodeNumPeers:         peers,
		NodeURIs:             strList(parsed, "nodeUris"),
		SunsetDate:           isoDate(parsed, "sunsetDate"),
		OutstandingNotesMsat: outstanding,
	}, nil
}

// ---- the mutating callback ----

func callbackURL(callback string, params [][2]string) (string, error) {
	if !IsAllowedServiceURL(callback) {
		return "", fmt.Errorf("%w: the service provided an invalid callback URL", ErrRequestRefused)
	}
	hasK1 := false
	for _, pair := range params {
		if pair[0] == "k1" {
			hasK1 = true
			break
		}
	}
	if !hasK1 {
		// Nothing to operate on. Worth refusing here rather than letting it become
		// a callback with no k1, whose meaning is entirely up to the service -
		// and which, read generously, could burn something the caller never named.
		return "", fmt.Errorf("%w: at least one k1 is required - there is no note to operate on", ErrRequestRefused)
	}
	return withParams(callback, params)
}

// MeltRequest burns a single note; the service pays pr of exactly its value.
// Merge several notes first to melt them together - LUD-25 dropped multi-k1
// melt.
//
// A confirmation means the payment is IN FLIGHT, not that the note is spent.
// The service pays asynchronously and only finalises the burn once the payment
// settles, restoring the note if it fails - so a melt failure is never reported
// through this call, only observed as the note becoming spendable again.
func MeltRequest(callback, k1, pr string) (Request, error) {
	built, err := callbackURL(callback, [][2]string{{"k1", k1}, {"pr", strings.TrimSpace(pr)}})
	if err != nil {
		return Request{}, err
	}
	return Request{URL: built}, nil
}

// outputParam names a mutation's output. An output is a hash, or a Part 2 cp1
// key. LUD-25 renamed the callback's h and h2 to p1 and p2; a hash keeps the
// old names, which every mint accepts, and a key goes as p1 or p2, which only a
// Part 2 mint takes anyway. Decided per value, never by a version flag - the
// same rule as lnurl-wallet - and the value goes out exactly as given, so a
// retried request stays byte-identical.
//
// A k1 needs no such treatment: a Part 1 secret and a Part 2 ck1 both go as
// k1, and the service tells them apart by shape.
func outputParam(value string, which int) [2]string {
	if IsCp1(strings.ToLower(strings.TrimSpace(value))) {
		return [2]string{"p" + strconv.Itoa(which), value}
	}
	if which == 2 {
		return [2]string{"h2", value}
	}
	return [2]string{"h", value}
}

// RotateRequestWithHash builds a rotate for a hash the caller already holds -
// what a hardware wallet drives, where the secret never enters this process.
//
// k1 may be a Part 2 ck1, and h a Part 2 cp1, which goes as p1: a rotate into
// a key the wallet derived and the service only ever learns the public half of.
func RotateRequestWithHash(callback, k1, h string) (Request, error) {
	built, err := callbackURL(callback, [][2]string{{"k1", k1}, outputParam(h, 1)})
	if err != nil {
		return Request{}, err
	}
	return Request{URL: built}, nil
}

// SplitRequestWithHash builds a split for hashes the caller already holds.
// Either output may be a cp1, and the two need not be the same kind.
func SplitRequestWithHash(callback string, k1s []string, amountMsat int64, h, h2 string) (Request, error) {
	params := make([][2]string, 0, len(k1s)+3)
	for _, k1 := range k1s {
		params = append(params, [2]string{"k1", k1})
	}
	params = append(params,
		[2]string{"amount", strconv.FormatInt(amountMsat, 10)},
		outputParam(h, 1),
		outputParam(h2, 2),
	)
	built, err := callbackURL(callback, params)
	if err != nil {
		return Request{}, err
	}
	return Request{URL: built}, nil
}

// MergeRequestWithHash builds a merge for a hash the caller already holds. The
// inputs may mix Part 1 secrets and Part 2 ck1s, and the output may be a cp1.
func MergeRequestWithHash(callback string, k1s []string, h string) (Request, error) {
	params := make([][2]string, 0, len(k1s)+1)
	for _, k1 := range k1s {
		params = append(params, [2]string{"k1", k1})
	}
	params = append(params, outputParam(h, 1))
	built, err := callbackURL(callback, params)
	if err != nil {
		return Request{}, err
	}
	return Request{URL: built}, nil
}

// The generating variants.
//
// Per LUD-25 the wallet generates the replacement secret and discloses only its
// hash. The service never sees, generates or persists it, which is what closes
// the prior-holder exposure a service-generated replacement would otherwise
// reopen on every single rotate.
//
// The secrets are passed in rather than drawn here, so a hardware wallet can
// supply them from its own RNG and a test can be deterministic.

// RotateRequest builds a rotate that mints newSecret.
func RotateRequest(callback, k1, newSecret string) (Request, error) {
	h, err := HashK1(newSecret)
	if err != nil {
		return Request{}, err
	}
	request, err := RotateRequestWithHash(callback, k1, h)
	if err != nil {
		return Request{}, err
	}
	request.NewSecrets = []string{newSecret}
	return request, nil
}

// SplitRequest builds a split that mints newSecret and changeSecret.
func SplitRequest(callback string, k1s []string, amountMsat int64, newSecret, changeSecret string) (Request, error) {
	h, err := HashK1(newSecret)
	if err != nil {
		return Request{}, err
	}
	h2, err := HashK1(changeSecret)
	if err != nil {
		return Request{}, err
	}
	request, err := SplitRequestWithHash(callback, k1s, amountMsat, h, h2)
	if err != nil {
		return Request{}, err
	}
	request.NewSecrets = []string{newSecret, changeSecret}
	return request, nil
}

// MergeRequest builds a merge that mints newSecret.
func MergeRequest(callback string, k1s []string, newSecret string) (Request, error) {
	h, err := HashK1(newSecret)
	if err != nil {
		return Request{}, err
	}
	request, err := MergeRequestWithHash(callback, k1s, h)
	if err != nil {
		return Request{}, err
	}
	request.NewSecrets = []string{newSecret}
	return request, nil
}

// ParseMutation classifies a mutating callback's response.
//
// A 200 that does not confirm is an AmbiguousError, not a failure: the service
// may have applied the mutation and merely failed to say so. newSecrets are
// attached to any ambiguous outcome so nothing can lose them between the call
// and the check.
func ParseMutation(body []byte, newSecrets []string, kind MutationKind, policy Policy) (Mutation, error) {
	parsed, err := decode(body)
	if err != nil {
		var ambiguous *AmbiguousError
		if asAmbiguous(err, &ambiguous) {
			ambiguous.NewSecrets = newSecrets
		}
		return Mutation{}, err
	}
	if err := rejectError(parsed); err != nil {
		var service *ServiceError
		_ = asService(err, &service)
		refusal := classifyNoteError(service.Reason)
		// A spent-or-unknown refusal from a mutation is also what an
		// ALREADY-APPLIED mutation looks like at a service that will not replay
		// a retry, so the secrets go out with it rather than with the stack
		// frame. A policy refusal burned nothing and carries nothing.
		var classified *ServiceError
		if asService(refusal, &classified) && (classified.Spent || classified.Unknown) {
			classified.NewSecrets = newSecrets
		}
		return Mutation{}, refusal
	}
	if str(parsed, "status") != "OK" {
		return Mutation{}, &AmbiguousError{
			Detail:     "the service did not confirm the operation - it may still have been applied",
			NewSecrets: newSecrets,
		}
	}
	signature, changeSignature := str(parsed, "sig"), str(parsed, "sig2")
	// Every mutation the replay rule covers owes a signature over each note it
	// mints. The mutation has already landed by the time this is checked -
	// status was OK - so the refusal carries the caller's secrets out with it,
	// or enforcing the spec becomes the thing that loses the money.
	if policy.RequireSignatures() {
		what := ""
		switch {
		case kind == MutationMelt:
		case signature == "":
			what = map[MutationKind]string{
				MutationRotate: "rotate",
				MutationSplit:  "split",
				MutationMerge:  "merge",
			}[kind]
		case kind == MutationSplit && changeSignature == "":
			what = "split's change"
		}
		if what != "" {
			return Mutation{}, &UnverifiableError{
				Detail: fmt.Sprintf(
					"the service confirmed the %s but returned no signature, so the note it just minted cannot be verified offline. The note exists - keep the secret",
					what,
				),
				NewSecrets: newSecrets,
			}
		}
	}
	return Mutation{
		Signature:       signature,
		ChangeSignature: changeSignature,
		PR:              str(parsed, "pr"),
		VerifyURL:       str(parsed, "verify"),
	}, nil
}

// ---- minting ----

// PayRequestRequest builds the payRequest GET.
func PayRequestRequest(rawURL string) (Request, error) {
	return Request{URL: rawURL}, nil
}

// ParsePayRequest reads a payRequest.
func ParsePayRequest(body []byte) (PayRequest, error) {
	parsed, err := decode(body)
	if err != nil {
		return PayRequest{}, err
	}
	if err := rejectError(parsed); err != nil {
		return PayRequest{}, err
	}
	if str(parsed, "tag") != "payRequest" || str(parsed, "callback") == "" {
		return PayRequest{}, &ProtocolError{Detail: "not a payRequest (unexpected response)"}
	}
	metadata := str(parsed, "metadata")
	minSendable, _ := msat(parsed, "minSendable")
	maxSendable, _ := msat(parsed, "maxSendable")
	fee, hasFee := ParseMintFee(metadata)
	// A withdrawLink that is present but not a string is a broken mint, not a
	// mint without one. Reading it as absent would send the caller down the
	// well-known fallback and quietly mint against the wrong endpoint.
	if raw, present := parsed["withdrawLink"]; present {
		if _, ok := raw.(string); !ok {
			return PayRequest{}, &ProtocolError{Detail: "the mint's payRequest has an invalid withdrawLink"}
		}
	}
	withdrawLink := str(parsed, "withdrawLink")
	commentAllowed, hasCommentAllowed := msat(parsed, "commentAllowed")
	mintToHash, _ := parsed["mintToHash"].(bool)
	request := PayRequest{
		Callback:          str(parsed, "callback"),
		MinSendableMsat:   minSendable,
		MaxSendableMsat:   maxSendable,
		Metadata:          metadata,
		WithdrawLink:      withdrawLink,
		MintPubkey:        str(parsed, "mintPubkey"),
		MintFee:           fee,
		HasMintFee:        hasFee,
		CommentAllowed:    commentAllowed,
		HasCommentAllowed: hasCommentAllowed,
		MintToHash:        mintToHash,
	}
	// LUD-25: minting is comment-bound. A payRequest that advertises a
	// withdrawLink but no room for the 64-character commitment is offering
	// something it cannot deliver, and the failure would otherwise land after
	// the caller had already paid.
	if withdrawLink != "" && !request.NamesMintOutput() {
		return PayRequest{}, &ProtocolError{
			Detail: "this mint offers no room for the required output commitment - it cannot mint",
		}
	}
	return request, nil
}

// InvoiceRequest builds a plain LUD-06 callback GET for an amount.
//
// Correct for paying an ordinary Lightning address; it mints nothing, because
// it names no output. To mint, use MintInvoiceRequest.
func InvoiceRequest(payCallback string, amountMsat int64) (Request, error) {
	built, err := withParams(payCallback, [][2]string{{"amount", strconv.FormatInt(amountMsat, 10)}})
	if err != nil {
		return Request{}, fmt.Errorf("%w: that pay callback does not parse", ErrRequestRefused)
	}
	return Request{URL: built}, nil
}

// MintInvoiceRequestWithHash asks for a mint invoice, naming the note it will
// credit with h = sha256(secret).
//
// LUD-25 carries the commitment as a mandatory LUD-12 comment; h repeats the
// identical value for services that took the parameter form first. It is never
// an alternative to the comment.
//
// The service learns a hash and nothing else, so the payment preimage is
// settlement proof only - it can never redeem the note. That is the whole point
// of the current draft: a preimage propagates to every routing node that
// forwards the payment, and a note keyed by one is a note they can all spend.
//
// h may instead be a Part 2 cp1, minting to a key. That goes as the comment
// alone: h is a hash-only extension, and a mint may refuse a key under it. A
// cp1 is 61 characters, so it fits the same 64 a mint must allow.
func MintInvoiceRequestWithHash(payCallback string, amountMsat int64, h string) (Request, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	params := [][2]string{{"amount", strconv.FormatInt(amountMsat, 10)}, {"comment", h}}
	switch {
	case IsCp1(h):
		// the comment is the whole of it
	case IsPreimage(h):
		params = append(params, [2]string{"h", h})
	default:
		// Refused here rather than sent, so a wallet never pays for a quote the
		// service was always going to reject.
		return Request{}, fmt.Errorf("%w: an output must be 32 bytes of hex or a cp1 key - no invoice was requested", ErrRequestRefused)
	}
	built, err := withParams(payCallback, params)
	if err != nil {
		return Request{}, fmt.Errorf("%w: that pay callback does not parse", ErrRequestRefused)
	}
	return Request{URL: built}, nil
}

// MintInvoiceRequest is MintInvoiceRequestWithHash, generating the commitment
// from the secret the caller will hold the note by.
//
// The secret comes back on Request.NewSecrets. Persist it BEFORE paying the
// invoice this returns. Paying for a note and then losing its secret is the one
// way the comment-bound scheme is worse than the preimage one it replaced, and
// persisting first removes it entirely. Drawing the secret from the seed
// derivation rather than the CSPRNG makes the note recoverable from birth,
// without any rotate at all.
func MintInvoiceRequest(payCallback string, amountMsat int64, mintSecret string) (Request, error) {
	// Checked before hashing, so a malformed secret is ErrRequestRefused - the
	// caller's own input, nothing sent - rather than the ProtocolError HashK1
	// would raise, which in this package's taxonomy accuses the service of a
	// broken response it never sent.
	if !IsPreimage(mintSecret) {
		return Request{}, fmt.Errorf("%w: a note secret must be 32 bytes of hex - no invoice was requested", ErrRequestRefused)
	}
	h, err := HashK1(mintSecret)
	if err != nil {
		return Request{}, err
	}
	request, err := MintInvoiceRequestWithHash(payCallback, amountMsat, h)
	if err != nil {
		return Request{}, err
	}
	request.NewSecrets = []string{mintSecret}
	return request, nil
}

// ParseInvoice reads an invoice, refusing one for the wrong amount.
func ParseInvoice(body []byte, requestedMsat int64) (Invoice, error) {
	parsed, err := decode(body)
	if err != nil {
		return Invoice{}, err
	}
	if err := rejectError(parsed); err != nil {
		return Invoice{}, err
	}
	pr := str(parsed, "pr")
	if pr == "" {
		return Invoice{}, &ProtocolError{Detail: "the service did not return an invoice"}
	}
	// A service answering an amount request with an invoice for a DIFFERENT
	// amount is broken or hostile. An amountless invoice passes through: there is
	// nothing to check it against here.
	if invoiced, ok := DecodeBolt11AmountMsat(pr); ok && invoiced != requestedMsat {
		return Invoice{}, &ProtocolError{
			Detail: fmt.Sprintf("the service returned an invoice for %d msat, not the %d requested", invoiced, requestedMsat),
		}
	}
	disposable := true
	if value, ok := parsed["disposable"].(bool); ok && !value {
		disposable = false
	}
	return Invoice{PR: pr, VerifyURL: str(parsed, "verify"), Disposable: disposable}, nil
}

// VerifyRequest builds a LUD-21 verify GET, to learn whether a mint or melt has
// settled.
//
// Under current LUD-25 this is unconditionally safe to call and its answer
// unconditionally safe to disclose: minting is comment-bound, so the preimage a
// settled invoice reveals is settlement proof and never the note's credential.
// (It was not always so. An earlier draft keyed the note by the payment
// preimage, which made this endpoint hand out the money; that fallback is gone.)
func VerifyRequest(verifyURL string) (Request, error) {
	return Request{URL: verifyURL}, nil
}

// ParseVerify reads a LUD-21 verify answer.
func ParseVerify(body []byte) (InvoiceStatus, error) {
	parsed, err := decode(body)
	if err != nil {
		return InvoiceStatus{}, err
	}
	if err := rejectError(parsed); err != nil {
		return InvoiceStatus{}, err
	}
	settled, ok := parsed["settled"].(bool)
	pr := str(parsed, "pr")
	if !ok || pr == "" {
		return InvoiceStatus{}, &ProtocolError{Detail: "the service returned an unexpected verify response"}
	}
	return InvoiceStatus{Settled: settled, Preimage: str(parsed, "preimage"), PR: pr}, nil
}
