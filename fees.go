package lnurlcash

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// MintFee is what a service withholds when minting (LUD-25, optional), and
// LUD-26's address fee.
//
// A service signals it with a "Mint fees: <base_fee_msat>,<fee_ppm>" token
// anywhere in its payRequest's text/plain metadata entry, so a wallet can warn
// the payer up front that the note they end up holding is worth less than the
// invoice they paid. The values are plain base-10 integers separated by commas,
// ending at whitespace or the end of the entry. A third value is LUD-26's
// address fee, what registering one Lightning Address costs. A service without
// the token is fee-free, not unknown.
type MintFee struct {
	BaseFeeMsat int64
	FeePpm      int64
	// AddressFeeMsat is LUD-26's third value: the fee per Lightning Address
	// registration. Valid only when HasAddressFee is true, which is false when
	// it is not advertised or does not parse; either way a wallet should
	// refuse to pay a registration invoice it was not told about.
	AddressFeeMsat int64
	HasAddressFee  bool
}

const mintFeeToken = "Mint fees:"

// Above 2^53 most languages lose integer precision, and a fee read wrong is
// worse than no fee: refuse it rather than estimate with a mangled value.
const maxSafeInteger = 1<<53 - 1

func feeValue(text string) (int64, bool) {
	if text == "" {
		return 0, false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value > maxSafeInteger {
		return 0, false
	}
	return value, true
}

// parseFeeToken reads the token's values: after "Mint fees:" and any spaces, up
// to the next whitespace. False when the first two do not parse, which LUD-25
// calls an unknown fee: a wallet relies on maxWithdrawable alone.
func parseFeeToken(text string) (MintFee, bool) {
	at := strings.Index(text, mintFeeToken)
	if at < 0 {
		return MintFee{}, false
	}
	rest := strings.TrimLeftFunc(text[at+len(mintFeeToken):], unicode.IsSpace)
	if end := strings.IndexFunc(rest, unicode.IsSpace); end >= 0 {
		rest = rest[:end]
	}
	parts := strings.Split(rest, ",")
	if len(parts) < 2 {
		return MintFee{}, false
	}
	base, ok1 := feeValue(parts[0])
	ppm, ok2 := feeValue(parts[1])
	if !ok1 || !ok2 {
		return MintFee{}, false
	}
	// A fee of 100% or more can never net anything. Refusing it here is also
	// what keeps GrossUpForMintFee's search bounded, so a service cannot
	// stall a caller simply by advertising one.
	if ppm >= 1_000_000 {
		return MintFee{}, false
	}
	fee := MintFee{BaseFeeMsat: base, FeePpm: ppm}
	if len(parts) > 2 {
		fee.AddressFeeMsat, fee.HasAddressFee = feeValue(parts[2])
	}
	return fee, true
}

// ParseMintFee reads the first parseable Mint fees token out of payRequest
// metadata's text/plain entries. Returns false when there is none, which the
// spec says to read as fee-free; when it does not parse, which is a fee the
// wallet does not know; and when every value is zero, so a caller never has to
// special-case a fee that withholds nothing.
func ParseMintFee(metadata string) (MintFee, bool) {
	var entries [][]json.RawMessage
	if err := json.Unmarshal([]byte(metadata), &entries); err != nil {
		return MintFee{}, false
	}
	for _, entry := range entries {
		if len(entry) < 2 {
			continue
		}
		var kind, text string
		if json.Unmarshal(entry[0], &kind) != nil || kind != "text/plain" {
			continue
		}
		if json.Unmarshal(entry[1], &text) != nil {
			continue
		}
		fee, ok := parseFeeToken(text)
		if !ok {
			continue
		}
		if fee.BaseFeeMsat == 0 && fee.FeePpm == 0 && (!fee.HasAddressFee || fee.AddressFeeMsat == 0) {
			return MintFee{}, false
		}
		return fee, true
	}
	return MintFee{}, false
}

// proportionalFee is floor(gross * ppm / 1_000_000), computed so it cannot
// overflow.
//
// The obvious gross * ppm is wrong at realistic amounts: 21M BTC is 2.1e15
// msat, and at 999_999 ppm the product is about 2.1e21 - past int64's 9.2e18.
// Splitting the multiplication keeps both halves small: the quotient half
// reaches at most 2.1e15, the remainder half at most 1e12.
//
// This is the single most likely thing for a port to get wrong, because a naive
// version passes every small test.
func proportionalFee(grossMsat, feePpm int64) int64 {
	return (grossMsat/1_000_000)*feePpm + ((grossMsat%1_000_000)*feePpm)/1_000_000
}

// ApplyMintFee returns what a service is expected to credit after withholding
// its advertised fee.
//
// Only ever an estimate to show before paying: the authoritative value is
// whatever the informational GET reports once the note is claimed.
func ApplyMintFee(grossMsat int64, fee MintFee) int64 {
	net := grossMsat - fee.BaseFeeMsat - proportionalFee(grossMsat, fee.FeePpm)
	if net < 0 {
		return 0
	}
	return net
}

// GrossUpForMintFee returns the SMALLEST invoice amount whose note nets
// netMsat after the fee.
//
// ApplyMintFee is non-decreasing in gross with per-msat steps of 0 or 1 (the
// proportional term grows by at most 1 per msat, since ppm is below
// 1_000_000), so the minimal such gross exists and binary search finds it
// exactly. The tempting alternative - estimate linearly, then walk one msat at
// a time - is both unbounded and wrong at the edge: at 999_999 ppm the walk is
// roughly a million steps, so any guard on it returns a non-minimal answer, and
// the service picks the fee.
func GrossUpForMintFee(netMsat int64, fee MintFee) int64 {
	if netMsat <= 0 {
		return 0
	}
	hi := netMsat + fee.BaseFeeMsat
	if hi < 1 {
		hi = 1
	}
	for ApplyMintFee(hi, fee) < netMsat {
		if hi > (1<<62)/2 {
			// unreachable with ppm < 1_000_000, but a library holding somebody's
			// money should saturate rather than overflow
			return hi
		}
		hi *= 2
	}
	lo := int64(0)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if ApplyMintFee(mid, fee) >= netMsat {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

// FormatFeePercent renders ppm as a percentage: /10_000 for a percent, then
// trim the trailing zeros (2000 ppm -> "0.2000" -> "0.2").
func FormatFeePercent(ppm int64) string {
	text := strconv.FormatFloat(float64(ppm)/10_000.0, 'f', 4, 64)
	trimmed := strings.TrimRight(strings.TrimRight(text, "0"), ".")
	if trimmed == "" {
		return "0"
	}
	return trimmed
}

// DescribeMintFee renders a fee for a human.
func DescribeMintFee(fee MintFee) string {
	parts := make([]string, 0, 2)
	if fee.BaseFeeMsat > 0 {
		parts = append(parts, fmt.Sprintf("%d sat flat", (fee.BaseFeeMsat+500)/1000))
	}
	if fee.FeePpm > 0 {
		parts = append(parts, FormatFeePercent(fee.FeePpm)+"% of the amount paid")
	}
	return strings.Join(parts, " + ")
}
