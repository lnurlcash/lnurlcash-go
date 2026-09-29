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
// fresh online GET. When there is no separate amount parameter, a current
// amount-bearing cs1 carries the same declaration in its prefix.
func NoteDeclaredAmountMsat(rawURL string) (int64, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0, false
	}
	raw := parsed.Query().Get("amount")
	if raw == "" {
		certificate, err := DecodeCs1WithAmount(parsed.Query().Get("sig"))
		if err != nil {
			return 0, false
		}
		return certificate.AmountMsat, true
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
// Input only qualifies if its k1 is a spend that opens its note at the URL's
// own domain (VerifySpend): a bearer preimage or cw1, or a ck1 signed for this
// mint. A ck1 signed for another mint could never be redeemed here, so it is
// refused at the door. A cw1 whose leaf this package cannot run passes on its
// structure alone; the mint judges the rest.
func ResolveNoteInput(value string) string {
	resolved := ResolveLnurlInput(value)
	if resolved == "" {
		return ""
	}
	k1 := NoteK1(resolved)
	if k1 == "" {
		return ""
	}
	if _, err := VerifySpend(k1, resolved); err != nil {
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
// public name rather than a spend of it.
//
// LUD-25's "Checking a note without exposing it": a service MUST accept
// ?p=<cp1> in place of ?k1=, or a bearer note's hex h as its short form, on
// the informational GET only and never at the callback. The spend stays off
// the wire, which is what a restore walk needs, since a walk queries a whole
// gap window of indices the wallet has not minted into yet.
//
// k1, amount and sig are dropped: naming the note twice, once in a form that
// spends it, would defeat the point.
//
// An unknown note is answered exactly as an unknown k1 is, and a burned note
// is deliberately indistinguishable from one that never existed.
//
// h is a cp1 or a bearer note's hex h, and goes as p either way. Mints from
// before LUD-25 settled on p also read h, but every current one reads p for
// both. NoteLookupOf gives the right value for any k1.
//
// Returns "" if h is neither 32 bytes of hex nor a cp1, or the link does not
// parse.
func BuildNoteInfoURLByHash(withdrawLink, h string) string {
	value := strings.ToLower(strings.TrimSpace(h))
	key := "p"
	if !IsCp1(value) && !IsPreimage(value) {
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
	amountIsImplied := signature != "" && IsCs1WithAmount(signature)
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
			if !amountIsImplied {
				out = append(out, [2]string{"amount", strconv.FormatInt(amountMsat, 10)})
				sawAmount = true
			}
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
	if !sawAmount && !amountIsImplied {
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
