package lnurlcash

import (
	"net/url"
	"strconv"
	"strings"
)

// NoteK1 returns the secret out of a note URL, normalised to lowercase hex.
//
// It is bytes, not text, so casing carries no meaning, and normalising keeps
// duplicate detection and the echo check on an informational GET from treating
// the same secret in two casings as two different notes.
func NoteK1(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Query().Get("k1"))
}

// NoteDeclaredAmountMsat returns what a note CLAIMS to carry, and whether it
// claimed anything at all.
//
// Only a claim by whoever encoded it - a service ignores it at the
// informational endpoint - so it is safe to display before contacting the
// service but must not be trusted without either a matching signature or a
// fresh online GET.
func NoteDeclaredAmountMsat(rawURL string) (int64, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0, false
	}
	raw := parsed.Query().Get("amount")
	if raw == "" {
		return 0, false
	}
	amount, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return amount, true
}

// NoteSignature returns a note's offline-verification signature, or "".
func NoteSignature(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("sig")
}

// ResolveNoteInput resolves input to a note URL, or "" if it is not one.
//
// Input only qualifies if it carries a well-formed k1: 32 bytes hex, or a Part 2
// ck1 that recovers to a key. Anything else would fail during hashing later, so
// it is refused at the door.
func ResolveNoteInput(value string) string {
	resolved := ResolveLnurlInput(value)
	if resolved == "" {
		return ""
	}
	k1 := NoteK1(resolved)
	if k1 == "" {
		return ""
	}
	if _, err := NoteIDOf(k1); err != nil {
		return ""
	}
	return resolved
}

// IsValidNoteInput reports whether input resolves to a note.
func IsValidNoteInput(value string) bool { return ResolveNoteInput(value) != "" }

// BuildNoteURL makes a note from a withdrawLink and a secret.
//
// Pass amountMsat < 0 when the real value is not known yet: the spec has a
// service ignore it here regardless, but some implementations validate it
// strictly, and a placeholder like 0 risks being rejected rather than ignored.
func BuildNoteURL(withdrawLink, k1 string, amountMsat int64) string {
	parsed, err := url.Parse(FromLud17(strings.TrimSpace(withdrawLink)))
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Del("k1")
	query.Del("amount")
	ordered := encodeOrdered(query, [][2]string{{"k1", strings.ToLower(strings.TrimSpace(k1))}}, amountMsat, "")
	parsed.RawQuery = ordered
	return parsed.String()
}

// BuildNoteInfoURLByHash builds the informational GET for a note named by its
// HASH rather than its secret.
//
// LUD-25's "Checking a note without exposing it": a service MAY accept
// ?h=<hex sha256 of k1> in place of ?k1=, on the informational GET only and
// never at the callback. It already stores every note under that hash, so this
// is a second way into a lookup it can do anyway - and the secret stays off
// the wire, which is what a restore walk needs, since a walk queries a whole
// gap window of indices the wallet has not minted into yet.
//
// k1, amount and sig are dropped: naming the note twice, once in a form that
// spends it, would defeat the point.
//
// A service that does not index by hash answers exactly as it answers for an
// unknown k1, which LUD-25 requires, so a rejection never distinguishes "not
// supported" from "no such note" - and a burned note is deliberately
// indistinguishable from one that never existed.
//
// h may also be a Part 2 cp1, sent as p, the name LUD-25 now uses. A hash keeps
// the older h, which every mint that ever took a hash lookup understands. Same
// rule as lnurl-wallet. NoteLookupOf gives the right one for either kind of k1.
//
// Returns "" if h is neither 32 bytes of hex nor a cp1, or the link does not
// parse.
func BuildNoteInfoURLByHash(withdrawLink, h string) string {
	value := strings.ToLower(strings.TrimSpace(h))
	key := "h"
	switch {
	case IsCp1(value):
		key = "p"
	case !IsPreimage(value):
		return ""
	}
	parsed, err := url.Parse(FromLud17(strings.TrimSpace(withdrawLink)))
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Del("k1")
	query.Del("amount")
	query.Del("sig")
	// -1, not 0: encodeOrdered writes any amount >= 0, and a lookup that
	// promises to drop amount must not add amount=0 back
	ordered := encodeOrdered(query, [][2]string{{key, value}}, -1, "")
	parsed.RawQuery = ordered
	return parsed.String()
}

// WithNewK1 returns the same note with its secret swapped out, after a rotate,
// split or merge.
//
// A signature only carries over when the response actually returned a fresh
// one: a mutation at a service without offline verification drops any stale
// sig, since it no longer matches the new secret.
func WithNewK1(rawURL, k1 string, amountMsat int64, signature string) string {
	return rewriteNote(rawURL, strings.ToLower(k1), amountMsat, signature, false)
}

// WithoutK1 is like WithNewK1 but removes k1 - for re-deriving a
// hardware-backed note's blank URL template after a mutation whose fresh secret
// now lives on the device rather than in this process.
func WithoutK1(rawURL string, amountMsat int64, signature string) string {
	return rewriteNote(rawURL, "", amountMsat, signature, true)
}

func rewriteNote(rawURL, k1 string, amountMsat int64, signature string, drop bool) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	// url.Values is a map, so it cannot preserve parameter order on its own -
	// and a note URL's shape is user-visible, quoted in bug reports and
	// compared by eye. Rebuild it in the order it arrived.
	pairs := parseOrdered(parsed.RawQuery)
	out := make([][2]string, 0, len(pairs)+3)
	sawK1, sawAmount, sawSig := false, false, false
	for _, pair := range pairs {
		switch pair[0] {
		case "k1":
			if drop {
				continue
			}
			out = append(out, [2]string{"k1", k1})
			sawK1 = true
		case "amount":
			out = append(out, [2]string{"amount", strconv.FormatInt(amountMsat, 10)})
			sawAmount = true
		case "sig":
			if signature != "" {
				out = append(out, [2]string{"sig", signature})
				sawSig = true
			}
		default:
			out = append(out, pair)
		}
	}
	if !drop && !sawK1 {
		out = append(out, [2]string{"k1", k1})
	}
	if !sawAmount {
		out = append(out, [2]string{"amount", strconv.FormatInt(amountMsat, 10)})
	}
	if signature != "" && !sawSig {
		out = append(out, [2]string{"sig", signature})
	}
	parsed.RawQuery = encodePairs(out)
	return parsed.String()
}

func parseOrdered(raw string) [][2]string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "&")
	pairs := make([][2]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, value, _ := strings.Cut(part, "=")
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			decodedKey = key
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			decodedValue = value
		}
		pairs = append(pairs, [2]string{decodedKey, decodedValue})
	}
	return pairs
}

func encodePairs(pairs [][2]string) string {
	var builder strings.Builder
	for i, pair := range pairs {
		if i > 0 {
			builder.WriteByte('&')
		}
		builder.WriteString(url.QueryEscape(pair[0]))
		builder.WriteByte('=')
		builder.WriteString(url.QueryEscape(pair[1]))
	}
	return builder.String()
}

func encodeOrdered(existing url.Values, prepend [][2]string, amountMsat int64, signature string) string {
	pairs := make([][2]string, 0, len(existing)+3)
	for key, values := range existing {
		for _, value := range values {
			pairs = append(pairs, [2]string{key, value})
		}
	}
	pairs = append(pairs, prepend...)
	if amountMsat >= 0 {
		pairs = append(pairs, [2]string{"amount", strconv.FormatInt(amountMsat, 10)})
	}
	if signature != "" {
		pairs = append(pairs, [2]string{"sig", signature})
	}
	return encodePairs(pairs)
}
