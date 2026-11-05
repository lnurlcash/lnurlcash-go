package lnurlcash_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	lnurlcash "github.com/lnurlcash/lnurlcash-go"
)

// CKDpub is checked against BIP-32's own published vector 1, wherever the chain
// takes a non-hardened step: the public derivation from the parent's key and
// chain code must land on the child CKDpriv reached.
func TestCKDpubAgreesWithCKDprivOnBIP32Vector1(t *testing.T) {
	vectors := loadVectors(t, "cash-derivation.json")
	var steps []struct {
		Index *uint32 `json:"index"`
		Node  string  `json:"node"`
	}
	unmarshalInto(t, vectors["bip32Vector1"], &steps)
	parent, err := lnurlcash.CashNodeFromHex(steps[0].Node)
	if err != nil {
		t.Fatal(err)
	}
	publicSteps := 0
	for _, step := range steps[1:] {
		child, err := lnurlcash.CashNodeFromHex(step.Node)
		if err != nil {
			t.Fatal(err)
		}
		if *step.Index < 0x80000000 {
			publicSteps++
			parentKey, err := lnurlcash.CashNodePublicKey(parent)
			if err != nil {
				t.Fatal(err)
			}
			wantKey, err := lnurlcash.CashNodePublicKey(child)
			if err != nil {
				t.Fatal(err)
			}
			gotKey, gotChain, err := lnurlcash.DeriveCashChildPub(parentKey, parent.ChainCode, *step.Index)
			if err != nil {
				t.Fatalf("CKDpub at %d: %v", *step.Index, err)
			}
			if gotKey != wantKey || gotChain != child.ChainCode {
				t.Errorf("CKDpub at %d = %x / %x, want %x / %x", *step.Index, gotKey, gotChain, wantKey, child.ChainCode)
			}
		} else if _, _, err := lnurlcash.DeriveCashChildPub([33]byte{2}, [32]byte{}, *step.Index); err == nil {
			t.Errorf("CKDpub took the hardened index %d", *step.Index)
		}
		parent = child
	}
	if publicSteps == 0 {
		t.Fatal("BIP-32 vector 1 has no non-hardened step to grade")
	}
}

func TestACx1IsSixtyFiveBytesAndTheOldShapeIsRefused(t *testing.T) {
	part2 := loadPart2(t)
	cx1, err := lnurlcash.DecodeCx1(part2.cx1)
	if err != nil {
		t.Fatal(err)
	}
	if len(part2.cx1) != 113 || cx1.PubkeyXOnly() != [32]byte(cx1.Pubkey[1:]) {
		t.Errorf("a cx1 is 113 characters (%d) and x(P) is its key without the prefix", len(part2.cx1))
	}
	if cx1.Pubkey[0] != 2 && cx1.Pubkey[0] != 3 {
		t.Errorf("the key prefix is %#x", cx1.Pubkey[0])
	}
	legacy := lnurlcash.EncodeLegacyCx1(lnurlcash.LegacyCx1{PubkeyXOnly: cx1.PubkeyXOnly(), ChainCode: cx1.ChainCode})
	if _, err := lnurlcash.DecodeCx1(legacy); err == nil {
		t.Error("the superseded 64-byte shape decoded as a cx1")
	}
	if decoded, err := lnurlcash.DecodeLegacyCx1(legacy); err != nil || decoded.PubkeyXOnly != cx1.PubkeyXOnly() {
		t.Errorf("the superseded shape no longer reads: %v", err)
	}
	if _, err := lnurlcash.DecodeLegacyCx1(part2.cx1); err == nil {
		t.Error("a 65-byte cx1 decoded as the superseded shape")
	}
	// the same x(P) at the other parity is a different cx1, which is why a
	// registration proof binds the whole string
	flipped := cx1
	flipped.Pubkey[0] ^= 1
	if lnurlcash.EncodeCx1(flipped) == part2.cx1 {
		t.Error("the parity byte does not change the cx1")
	}
	if _, err := lnurlcash.DecodeCx1(lnurlcash.EncodeCx1(flipped)); err != nil {
		t.Errorf("the other parity is still a point: %v", err)
	}
}

func TestACertificateWithARecoveryIDAboveThreeIsRefused(t *testing.T) {
	var signature [65]byte
	signature[64] = 4
	cs1, err := lnurlcash.EncodeCs1WithAmount(1000, signature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lnurlcash.DecodeCs1WithAmount(cs1); err == nil || lnurlcash.IsCs1WithAmount(cs1) {
		t.Error("an amount-bearing cs1 with a recovery id of 4 was accepted")
	}
}

func TestAnAddressFeeIsTheThirdMintFeesValue(t *testing.T) {
	for _, c := range []struct {
		text    string
		fee     lnurlcash.MintFee
		advised bool
	}{
		{"Mint fees: 1000,10,21000", lnurlcash.MintFee{BaseFeeMsat: 1000, FeePpm: 10, AddressFeeMsat: 21000, HasAddressFee: true}, true},
		{"Mint fees: 0,0,21000", lnurlcash.MintFee{AddressFeeMsat: 21000, HasAddressFee: true}, true},
		{"Mint fees: 1000,10", lnurlcash.MintFee{BaseFeeMsat: 1000, FeePpm: 10}, true},
		{"a mint. Mint fees:1000,10 and more", lnurlcash.MintFee{BaseFeeMsat: 1000, FeePpm: 10}, true},
		{"Mint fees: 1000,10,x", lnurlcash.MintFee{BaseFeeMsat: 1000, FeePpm: 10}, true},
		{"Mint fees: 1000,10,0", lnurlcash.MintFee{BaseFeeMsat: 1000, FeePpm: 10, HasAddressFee: true}, true},
		// a zero address fee alongside zero mint fees withholds nothing
		{"Mint fees: 0,0,0", lnurlcash.MintFee{}, false},
		{"Mint fees: 0,0", lnurlcash.MintFee{}, false},
		// the values end at whitespace, so spaces around a comma are not one list
		{"Mint fees: 1000 , 2000", lnurlcash.MintFee{}, false},
		{"Mint fees: 1000, 2000", lnurlcash.MintFee{}, false},
		{"Mint fees: 1000,2000 Address fee: 21000", lnurlcash.MintFee{BaseFeeMsat: 1000, FeePpm: 2000}, true},
		{"Mint fees: -1,2", lnurlcash.MintFee{}, false},
		{"Mint fees: 1000,1000000", lnurlcash.MintFee{}, false},
		// above 2^53 a fee cannot be read reliably, so it is not read
		{"Mint fees: 9007199254740992,1", lnurlcash.MintFee{}, false},
		{"Mint fees: 9007199254740991,1", lnurlcash.MintFee{BaseFeeMsat: 9007199254740991, FeePpm: 1}, true},
		{"Mint fees: 1,1,9007199254740992", lnurlcash.MintFee{BaseFeeMsat: 1, FeePpm: 1}, true},
	} {
		metadata := `[["text/plain","` + c.text + `"]]`
		fee, ok := lnurlcash.ParseMintFee(metadata)
		if ok != c.advised || (ok && fee != c.fee) {
			t.Errorf("%q = %+v/%v, want %+v/%v", c.text, fee, ok, c.fee, c.advised)
		}
	}
}

func TestACertificateReadsAnExactAlreadyInUseAsSpent(t *testing.T) {
	// LUD-25 (luds 92abbb3) answers a burned note exactly "already in use", at
	// the informational GET and the callback alike
	for _, reason := range []string{"already in use", "Already in use", " already in use "} {
		body := `{"status":"ERROR","reason":"` + reason + `"}`
		_, err := lnurlcash.ParseNoteInfo([]byte(body), "https://mint.example/w?k1=x", lnurlcash.Policy{})
		if !lnurlcash.IsSpent(err) || !lnurlcash.IsAlreadyInUse(err) || errors.Is(err, lnurlcash.ErrOutputInUse) {
			t.Errorf("%q at the info GET = %v", reason, err)
		}
	}
	// lnurl-mint's older wording names the output
	body := `{"status":"ERROR","reason":"Output already in use."}`
	_, err := lnurlcash.ParseNoteInfo([]byte(body), "https://mint.example/w?k1=x", lnurlcash.Policy{})
	if lnurlcash.IsSpent(err) || !lnurlcash.IsAlreadyInUse(err) || !errors.Is(err, lnurlcash.ErrOutputInUse) {
		t.Errorf("Output already in use. = %v", err)
	}
	if lnurlcash.IsAlreadyInUse(errors.New("already in use")) || lnurlcash.IsAlreadyInUse(nil) {
		t.Error("a plain error is not a service's answer")
	}
	// a refusal that carries the secrets of a mutation that may have applied
	mutation := lnurlcash.Request{URL: "https://mint.example/cb", NewSecrets: []string{"s"}}
	_, err = lnurlcash.ParseMutation([]byte(`{"status":"ERROR","reason":"already in use"}`), mutation, lnurlcash.MutationRotate, lnurlcash.Policy{})
	if got := lnurlcash.NewSecrets(err); len(got) != 1 || got[0] != "s" {
		t.Errorf("the spent reading dropped the fresh secrets: %v", got)
	}
}

func payeeAt(withdrawLink string) lnurlcash.PayRequest {
	return lnurlcash.PayRequest{
		Callback:        "https://mint.example/.well-known/lnurlp/bob/cb",
		MinSendableMsat: 1000,
		MaxSendableMsat: 100_000_000,
		Metadata:        "[]",
		WithdrawLink:    withdrawLink,
	}
}

func TestAnInternalTransferSendsTheWholeNoteToTheCallback(t *testing.T) {
	k1 := secret(0x11)
	for _, link := range []string{"https://mint.example/w", "lnurlw://MINT.example/w"} {
		request, err := lnurlcash.InternalTransferRequest(payeeAt(link), "https://mint.example:443/w?k1=x", k1, 21000)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		want := "https://mint.example/.well-known/lnurlp/bob/cb?amount=21000&k1=" + k1
		if request.URL != want || len(request.NewSecrets) != 0 {
			t.Errorf("%s: request = %+v, want %s", link, request, want)
		}
	}
}

func TestAnInternalTransferNeverLeavesTheNotesMint(t *testing.T) {
	k1 := secret(0x11)
	// no withdrawLink, or one at another mint: the spend would go to a SERVICE
	// that does not hold the note
	for _, payee := range []lnurlcash.PayRequest{payeeAt(""), payeeAt("https://other.example/w")} {
		if _, err := lnurlcash.InternalTransferRequest(payee, "mint.example", k1, 21000); !errors.Is(err, lnurlcash.ErrRequestRefused) {
			t.Errorf("%q: %v", payee.WithdrawLink, err)
		}
	}
	payee := payeeAt("https://mint.example/w")
	for _, amount := range []int64{999, 100_000_001} {
		if _, err := lnurlcash.InternalTransferRequest(payee, "mint.example", k1, amount); !errors.Is(err, lnurlcash.ErrRequestRefused) {
			t.Errorf("%d msat: %v", amount, err)
		}
	}
	if _, err := lnurlcash.InternalTransferRequest(payee, "mint.example", "not a spend", 21000); !errors.Is(err, lnurlcash.ErrRequestRefused) {
		t.Errorf("not a spend: %v", err)
	}
	if _, err := lnurlcash.InternalTransferRequest(payee, "", k1, 21000); !errors.Is(err, lnurlcash.ErrRequestRefused) {
		t.Errorf("no note domain: %v", err)
	}
}

func TestAnInternalTransferAnswerIsOKRefusedOrAmbiguous(t *testing.T) {
	if err := lnurlcash.ParseInternalTransfer([]byte(`{"status":"OK"}`)); err != nil {
		t.Errorf("OK: %v", err)
	}
	err := lnurlcash.ParseInternalTransfer([]byte(`{"status":"ERROR","reason":"already in use"}`))
	var service *lnurlcash.ServiceError
	if !errors.As(err, &service) || lnurlcash.IsAmbiguous(err) {
		t.Errorf("a refusal = %v, want a definitive service error", err)
	}
	for _, body := range []string{`{"tag":"payRequest"}`, `{"status":"PENDING"}`, `not json`} {
		if err := lnurlcash.ParseInternalTransfer([]byte(body)); !lnurlcash.IsAmbiguous(err) {
			t.Errorf("%s = %v, want ambiguous", body, err)
		}
	}
}

func TestAnAddressProofRefusesWhatIsNotARegistrationShape(t *testing.T) {
	part2 := loadPart2(t)
	// a cx1 is signed in its canonical lowercase spelling
	lower, err := lnurlcash.AddressProofMessage("register", "mint.example", "alice", part2.cx1)
	if err != nil {
		t.Fatal(err)
	}
	upper, err := lnurlcash.AddressProofMessage("register", "mint.example", "alice", strings.ToUpper(part2.cx1))
	if err != nil || upper != lower {
		t.Errorf("an upper-case cx1 signs %q (%v), want %q", upper, err, lower)
	}
	// an unregister proof binds no cx1 and names no other thing
	if message, err := lnurlcash.AddressProofMessage("unregister", "mint.example", "Alice", ""); err != nil || message != "LNURLcash:unregister:mint.example:alice" {
		t.Errorf("unregister = %q (%v)", message, err)
	}
	key, _ := hex.DecodeString(strings.Repeat("11", 32))
	var secretKey [32]byte
	copy(secretKey[:], key)
	if _, err := lnurlcash.SignAddressProof([32]byte{}, "unregister", "mint.example", "alice", ""); err == nil {
		t.Error("signed with a zero key")
	}
	if signature, err := lnurlcash.SignAddressProof(secretKey, "unregister", "mint.example", "alice", ""); err != nil || len(signature) != 64 {
		t.Errorf("signing failed: %v", err)
	}
}
