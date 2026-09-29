// Package lnurlcash implements LNURLcash (LUD-25 draft) bearer notes.
//
// A bearer note is an ordinary LUD-03 withdrawRequest link whose k1 IS the
// asset:
//
//	lnurlw://mint.example/w?k1=<spend>&amount=<msat>
//
// Whoever knows the k1 controls the sats behind it, like a banknote. The
// amount alongside it is only a claim by whoever encoded the note; the
// authoritative value is always MaxWithdrawable from an informational GET.
//
// Every note is a BIP-341 taproot output key Q, named cp1<Q>, and k1 is a
// spend of it (see spend.go): a ck1 signed by Q for this mint, a cw1 opening a
// leaf of Q's script tree, or a bearer note's 64-hex preimage, the short form
// of the cw1 for its OP_SHA256 <h> OP_EQUAL leaf.
//
// Every mutating operation is a GET on the callback from that withdrawRequest,
// each output named by a cp1 or a bearer note's hex h:
//
//	callback?k1=X&pr=<bolt11>                melt
//	callback?k1=X&p1=<cp1 or h>              rotate
//	callback?k1=X&amount=<msat>&p1=..&p2=..  split
//	callback?k1=X&k1=Y&p1=<cp1 or h>         merge
//
// Amounts are int64 milli-satoshis, everywhere, with no exceptions.
//
// Draft spec: https://github.com/lnurl/luds/pull/301
//
// Reference implementations, both by dni and both MIT:
// https://github.com/dni/lnurl-mint (the service) and
// https://github.com/dni/lnurl-wallet (the wallet).
package lnurlcash

import (
	"errors"
	"fmt"
	"strings"
)

// The error taxonomy is the safety-critical part of this package, so it is
// worth stating plainly what each one means for the money involved.
//
//	ErrRequestRefused   nothing was sent. The note is untouched.
//	ServiceError        the service processed the request and refused it.
//	                    Definitive.
//	AmbiguousError      the outcome is unknown. The request MAY have been
//	                    processed. Nothing may be assumed either way.
//	ProtocolError       a non-mutating response did not match the spec.
//	UnverifiableError   a MUTATION landed and an output came back without the
//	                    certificate it is owed. The note exists; it just
//	                    cannot be verified offline.
//
// Treating an ambiguous failure as a definitive one is how wallets lose money:
// a rotate that times out after the service burned the input has already
// minted the output, and the fresh secret in this process is the only copy of
// it in existence.
var (
	// ErrRequestRefused means the request never left: offline, a URL this
	// package will not fetch, or a callback that does not parse. Safe to treat
	// as a no-op.
	ErrRequestRefused = errors.New("request refused")

	// ErrNotePending is the exact {"status":"ERROR","reason":"pending"} case:
	// this k1 has a melt in flight, and every other operation on it is refused
	// until that resolves. Retry shortly - never read this as spent.
	ErrNotePending = errors.New("this note has another operation in progress - try again in a moment")
)

// ErrOutputInUse is LUD-25's {"status":"ERROR","reason":"already in use"}
// case: an output this request named, p1 or p2, is already outstanding or was
// burned before, so the service refused rather than credit value into a note
// somebody else may hold the spend for. Nothing was burned. Name a fresh
// output - the next index, for a key derived from a branch - and try again.
var ErrOutputInUse = errors.New("an output this request named is already in use - name a fresh one")

// ProtocolError is a non-mutating response that does not match the protocol.
type ProtocolError struct {
	Detail string
}

func (e *ProtocolError) Error() string { return e.Detail }

// ServiceError is a {"status":"ERROR"} answer: the service processed the
// request and declined it. Definitive - the operation did not happen.
type ServiceError struct {
	// Reason is carried through exactly as the service sent it, empty string
	// included. Substituting a friendly default before classification would be
	// read back as though the service had said it: "unknown service error"
	// matches the rule for an unknown note, and would report one on no
	// evidence at all.
	Reason string
	// Spent is true when the service is authoritative that the note is already
	// burned. A holder may lock it as spent without asking anything further.
	Spent bool
	// Unknown is true when the service does not recognise the k1 at all.
	// Distinct from Spent: nothing here proves the holder's copy was ever real.
	Unknown bool
	// OutputInUse is true for LUD-25's "already in use": an output the
	// request named is taken, and nothing was burned. errors.Is(err,
	// ErrOutputInUse) says the same.
	OutputInUse bool
	// NewSecrets are the fresh wallet-generated secrets a MUTATION disclosed
	// the hashes of, when this refusal is one that could describe a mutation
	// the service had already applied.
	//
	// At a service that has not implemented LUD-25's replay rule, a retried
	// rotate, split or merge is answered as an already-spent input - so a Spent
	// or Unknown refusal from a mutation is also what a mutation the service
	// DID apply looks like. Read these with NewSecrets before believing it.
	//
	// Nil on every other refusal, and on every non-mutating call.
	NewSecrets []string
}

// Is lets errors.Is match ErrOutputInUse against the refusal it describes.
func (e *ServiceError) Is(target error) bool {
	return target == ErrOutputInUse && e.OutputInUse
}

func (e *ServiceError) Error() string {
	switch {
	case e.Spent:
		return fmt.Sprintf("this note has already been spent (service says: %q)", e.Reason)
	case e.Unknown:
		return fmt.Sprintf("the service doesn't recognise this note (service says: %q)", e.Reason)
	case e.Reason == "":
		return "the service rejected the request"
	default:
		return e.Reason
	}
}

// AmbiguousError means the outcome is unknown. The failure happened in a
// window where the request may already have reached and been processed by the
// service: a timeout, a dropped connection, an unreadable response, or a 200
// that did not carry the expected confirmation.
type AmbiguousError struct {
	Detail string
	// NewSecrets are the fresh wallet-generated secrets whose hashes the
	// uncertain request disclosed. If the request did land, these are the only
	// copies of the notes the service minted - persist them before doing
	// anything else, then probe.
	//
	// Order matches the operation's result shape: [rotated] for a rotate,
	// [splitOff, change] for a split, [merged] for a merge.
	NewSecrets []string
	// Cause is the underlying transport failure, if there was one.
	Cause error
}

func (e *AmbiguousError) Error() string { return e.Detail }

func (e *AmbiguousError) Unwrap() error { return e.Cause }

// UnverifiableError means the service confirmed a rotate, split or merge with
// {"status":"OK"} but returned no certificate for an output it was owed one
// for. LUD-25 says a service SHOULD certify every note; this package insists
// for an output named by cp1, since offline verification is the reason to
// name it so - but the mutation LANDED. The note exists, at the key or hash
// the caller disclosed, and whatever is behind it is the only key to that
// value anywhere.
//
// So this is an error about the note's VERIFIABILITY, never about its
// existence, and it carries the secrets for the same reason AmbiguousError
// does: refusing without them would strand real money to make a point about
// conformance. Persist them, then decide whether to keep dealing with a mint
// that issues notes nobody can check.
//
// Raised for an output named by cp1 whatever the Policy says. One named by a
// bearer note's hex h raises it when Policy.RequireSignatures asked for a
// certificate and a mint with no signer omitted it.
type UnverifiableError struct {
	Detail string
	// NewSecrets, as AmbiguousError - and more important here, because the note
	// is known to exist. Empty from the *WithHash calls, where the caller
	// supplied every output and this package never saw what spends it.
	NewSecrets []string
}

func (e *UnverifiableError) Error() string { return e.Detail }

// IsUnverifiable reports whether a mutation landed without a signature it was
// owed. The note is real; only its offline verifiability is missing.
func IsUnverifiable(err error) bool {
	var unverifiable *UnverifiableError
	return errors.As(err, &unverifiable)
}

// IsAmbiguous reports whether the request could have been processed. The single
// most important question about any failure here.
func IsAmbiguous(err error) bool {
	var ambiguous *AmbiguousError
	return errors.As(err, &ambiguous)
}

// NewSecrets returns the fresh secrets carried out of any error that could
// describe a mutation the service applied: ambiguous, unverifiable, or a
// spent-or-unknown refusal. Persist them before doing anything else.
func NewSecrets(err error) []string {
	var ambiguous *AmbiguousError
	if errors.As(err, &ambiguous) {
		return ambiguous.NewSecrets
	}
	var unverifiable *UnverifiableError
	if errors.As(err, &unverifiable) {
		return unverifiable.NewSecrets
	}
	// A refusal on policy grounds burned nothing, so it carries nothing and a
	// caller may discard its staged records at once. Only spent and unknown can
	// be a description of something that DID happen.
	var service *ServiceError
	if errors.As(err, &service) && (service.Spent || service.Unknown) {
		return service.NewSecrets
	}
	return nil
}

// IsSpent reports whether the service was authoritative that the note is gone.
func IsSpent(err error) bool {
	var service *ServiceError
	return errors.As(err, &service) && service.Spent
}

// IsUnknownNote reports whether the service did not recognise the note.
func IsUnknownNote(err error) bool {
	var service *ServiceError
	return errors.As(err, &service) && service.Unknown
}

// classifyNoteError turns a service's reason text into a typed error.
//
// A service's wording for "this k1 is dead" varies by implementation and by
// endpoint. An informational GET can afford to distinguish "Note already
// spent." from "Unknown note.", while the mutating callback - an atomic,
// possibly multi-k1 request - can only say something like "Invalid or already
// spent k1.", since it cannot tell which case applies to which k1.
func classifyNoteError(reason string) error {
	lowered := strings.ToLower(reason)
	if lowered == "pending" {
		return ErrNotePending
	}
	// LUD-25 says exactly "already in use"; lnurl-mint says "Output already
	// in use.", so it is matched as a phrase, as lnurl-wallet does
	if strings.Contains(lowered, "already in use") {
		return &ServiceError{Reason: reason, OutputInUse: true}
	}
	if strings.Contains(lowered, "spent") {
		return &ServiceError{Reason: reason, Spent: true}
	}
	if strings.Contains(lowered, "unknown") || strings.Contains(lowered, "not found") {
		return &ServiceError{Reason: reason, Unknown: true}
	}
	return &ServiceError{Reason: reason}
}

func asService(err error, target **ServiceError) bool { return errors.As(err, target) }

func asAmbiguous(err error, target **AmbiguousError) bool { return errors.As(err, target) }
