package lnurlcash_test

// Runs against the conformance repo's mock mint - a real HTTP server that can
// be told to misbehave. The happy paths matter, but the adversarial modes are
// the reason this suite exists: a package that only works against a
// well-behaved service has not been tested at all.

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	lnurlcash "github.com/lnurlcash/lnurlcash-go"
)

type mockMint struct {
	url     string
	pubkey  string
	command *exec.Cmd
}

func conformanceDir() string {
	if configured := os.Getenv("LNURLCASH_CONFORMANCE"); configured != "" {
		return configured
	}
	return filepath.Join("..", "lnurlcash-conformance")
}

var (
	listeningRe = regexp.MustCompile(`listening on (\S+)`)
	pubkeyRe    = regexp.MustCompile(`mint pubkey:\s+(\S+)`)
)

func startMint(t *testing.T, flags ...string) *mockMint {
	t.Helper()
	script := filepath.Join(conformanceDir(), "mock-mint", "index.mjs")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("mock mint not found at %s", script)
	}
	args := append([]string{script, "--port=0", "--testHooks=true"}, flags...)
	command := exec.Command("node", args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("could not pipe the mock mint's output: %v", err)
	}
	command.Stderr = command.Stdout
	if err := command.Start(); err != nil {
		t.Skipf("could not start node: %v", err)
	}

	mint := &mockMint{command: command}
	scanner := bufio.NewScanner(stdout)
	deadline := time.Now().Add(20 * time.Second)
	for scanner.Scan() && time.Now().Before(deadline) {
		line := scanner.Text()
		if match := listeningRe.FindStringSubmatch(line); match != nil {
			mint.url = match[1]
		}
		if match := pubkeyRe.FindStringSubmatch(line); match != nil {
			mint.pubkey = match[1]
		}
		if mint.url != "" && mint.pubkey != "" {
			break
		}
	}
	if mint.url == "" {
		_ = command.Process.Kill()
		t.Fatal("the mock mint did not start")
	}
	// keep draining, or the mint blocks once its pipe buffer fills
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	return mint
}

func (m *mockMint) hook(t *testing.T, path string) map[string]any {
	t.Helper()
	response, err := http.Get(m.url + path)
	if err != nil {
		t.Fatalf("test hook %s: %v", path, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("test hook %s returned %q", path, body)
	}
	return parsed
}

// credit brings a note into existence and returns the signature the mint
// issued for it.
func (m *mockMint) credit(t *testing.T, k1 string, amountMsat int64) string {
	t.Helper()
	body := m.hook(t, fmt.Sprintf("/_test/credit?k1=%s&amount=%d", k1, amountMsat))
	if body["status"] != "OK" {
		t.Fatalf("credit failed: %v", body)
	}
	signature, _ := body["sig"].(string)
	return signature
}

// noteState is what the SERVICE thinks of a note - the difference between what
// a mint says and what it did.
func (m *mockMint) noteState(t *testing.T, k1 string) string {
	t.Helper()
	body := m.hook(t, "/_test/state?k1="+k1)
	state, _ := body["state"].(string)
	return state
}

func (m *mockMint) settle(t *testing.T, paymentHash string) {
	t.Helper()
	body := m.hook(t, "/_test/settle?payment_hash="+paymentHash)
	if body["status"] != "OK" {
		t.Fatalf("settle failed: %v", body)
	}
}

func (m *mockMint) noteURL(k1 string) string { return m.url + "/w?k1=" + k1 }
func (m *mockMint) callback() string         { return m.url + "/w/cb" }
func (m *mockMint) payURL() string           { return m.url + "/.well-known/lnurlp/mint" }

func secret(seed byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed
	}
	return hex.EncodeToString(buf)
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

// ---- the informational GET ----

func TestReportsValueAndNeverBurns(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	k1 := secret(1)
	mint.credit(t, k1, 21000)

	info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(k1))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if info.MaxWithdrawableMsat != 21000 || info.K1 != k1 {
		t.Fatalf("got %+v", info)
	}
	if state := mint.noteState(t, k1); state != "outstanding" {
		t.Fatalf("the informational GET burned the note: %s", state)
	}
	if _, err := client.FetchNoteInfo(ctx(t), mint.noteURL(k1)); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
}

func TestMaxWithdrawableBeatsTheURLsOwnClaim(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	k1 := secret(2)
	mint.credit(t, k1, 21000)

	info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(k1)+"&amount=2100000")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if info.MaxWithdrawableMsat != 21000 {
		t.Fatalf("the URL's own claim won: %d", info.MaxWithdrawableMsat)
	}
}

func TestRefusesAServiceThatEchoesADifferentK1(t *testing.T) {
	mint := startMint(t, "--echoWrongK1=true")
	client := lnurlcash.NewClient()
	k1 := secret(3)
	mint.credit(t, k1, 21000)

	_, err := client.FetchNoteInfo(ctx(t), mint.noteURL(k1))
	var protocolErr *lnurlcash.ProtocolError
	if err == nil || !asProtocol(err, &protocolErr) {
		t.Fatalf("want a protocol error, got %v", err)
	}
}

func TestUnknownAndSpentAreDifferentAnswers(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	known := secret(4)
	mint.credit(t, known, 21000)

	if _, err := client.FetchNoteInfo(ctx(t), mint.noteURL(secret(5))); !lnurlcash.IsUnknownNote(err) {
		t.Fatalf("want unknown, got %v", err)
	}
	if _, err := client.RotateNote(ctx(t), mint.callback(), known); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := client.FetchNoteInfo(ctx(t), mint.noteURL(known)); !lnurlcash.IsSpent(err) {
		t.Fatalf("want spent, got %v", err)
	}
}

// ---- rotate, split, merge ----

func TestRotateBurnsTheOldSecretAndMintsOneTheServiceNeverSaw(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	k1 := secret(6)
	mint.credit(t, k1, 21000)

	rotated, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.K1 == k1 {
		t.Fatal("the secret did not change")
	}
	if state := mint.noteState(t, k1); state != "burned" {
		t.Fatalf("input state = %s", state)
	}
	if state := mint.noteState(t, rotated.K1); state != "outstanding" {
		t.Fatalf("output state = %s", state)
	}
	if !lnurlcash.VerifyNoteSignature(rotated.K1, 21000, rotated.Signature, mint.pubkey) {
		t.Fatal("the signature does not verify")
	}
	if lnurlcash.VerifyNoteSignature(rotated.K1, 21001, rotated.Signature, mint.pubkey) {
		t.Fatal("a signature verified for an amount the mint never signed")
	}
}

func TestAcceptsTheOtherRecoveryIDLayout(t *testing.T) {
	mint := startMint(t, "--signatureLayout=leading")
	client := lnurlcash.NewClient()
	k1 := secret(7)
	mint.credit(t, k1, 21000)

	rotated, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !lnurlcash.VerifyNoteSignature(rotated.K1, 21000, rotated.Signature, mint.pubkey) {
		t.Fatal("a recovery-id-leading signature did not verify")
	}
}

func TestIgnoresASecretTheServiceTriesToHandBack(t *testing.T) {
	mint := startMint(t, "--serverGeneratedSecrets=true")
	client := lnurlcash.NewClient()
	k1 := secret(8)
	mint.credit(t, k1, 21000)

	rotated, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// taking the mint's offered secret would hand it a permanent copy of the
	// note it just issued
	if rotated.K1 == strings.Repeat("a", 64) {
		t.Fatal("adopted the service's own secret")
	}
	if state := mint.noteState(t, rotated.K1); state != "outstanding" {
		t.Fatalf("output state = %s", state)
	}
}

func TestSplitProducesAnAmountAndItsChange(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	k1 := secret(9)
	mint.credit(t, k1, 21000)

	split, err := client.SplitNote(ctx(t), mint.callback(), []string{k1}, 5000)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if state := mint.noteState(t, k1); state != "burned" {
		t.Fatalf("input state = %s", state)
	}
	for k1, want := range map[string]int64{split.K1: 5000, split.Change: 16000} {
		info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(k1))
		if err != nil || info.MaxWithdrawableMsat != want {
			t.Fatalf("output %s = %d (%v), want %d", k1[:8], info.MaxWithdrawableMsat, err, want)
		}
	}
	if !lnurlcash.VerifyNoteSignature(split.K1, 5000, split.Signature, mint.pubkey) {
		t.Fatal("the split note's signature does not verify")
	}
}

func TestMergeSums(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	parts := []string{secret(10), secret(11), secret(12)}
	for index, k1 := range parts {
		mint.credit(t, k1, int64(1000*(index+1)))
	}

	merged, err := client.MergeNotes(ctx(t), mint.callback(), parts)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	for _, part := range parts {
		if state := mint.noteState(t, part); state != "burned" {
			t.Fatalf("input %s state = %s", part[:8], state)
		}
	}
	info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(merged.K1))
	if err != nil || info.MaxWithdrawableMsat != 6000 {
		t.Fatalf("merged = %d (%v), want 6000", info.MaxWithdrawableMsat, err)
	}
}

func TestRefusesAMutationNamingNoNote(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	if _, err := client.MergeNotes(ctx(t), mint.callback(), nil); err == nil {
		t.Fatal("a mutation with no k1 was sent")
	} else if lnurlcash.IsAmbiguous(err) {
		t.Fatalf("refusing to send is definitive, not ambiguous: %v", err)
	}
}

func TestSettleResolvesWhatAnOutputIsReallyWorth(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	k1 := secret(13)
	mint.credit(t, k1, 21000)

	split, err := client.SplitNote(ctx(t), mint.callback(), []string{k1}, 5000)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	// the caller does not know the change is 16000 - only the service does
	settled, err := client.SettleNote(ctx(t), mint.noteURL(k1), split.Change, 0, split.ChangeSignature)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if settled.AmountMsat != 16000 {
		t.Fatalf("settled amount = %d, want 16000", settled.AmountMsat)
	}
	if settled.K1 == split.Change {
		t.Fatal("the GET-exposed secret was not rotated away")
	}
}

// ---- melt ----

func TestMeltOKMeansInFlightNotSpent(t *testing.T) {
	mint := startMint(t, "--meltNeverSettles=true")
	client := lnurlcash.NewClient()
	k1 := secret(14)
	mint.credit(t, k1, 21000)

	if _, err := client.MeltNote(ctx(t), mint.callback(), k1, "lnbc210n1pjqrstuvwxyz"); err != nil {
		t.Fatalf("melt: %v", err)
	}
	if state := mint.noteState(t, k1); state != "pending" {
		t.Fatalf("state after melt = %s, want pending", state)
	}
	// and every other operation is locked out until it resolves
	if _, err := client.RotateNote(ctx(t), mint.callback(), k1); err != lnurlcash.ErrNotePending {
		t.Fatalf("want ErrNotePending, got %v", err)
	}
}

func TestAFailedMeltRestoresTheNote(t *testing.T) {
	mint := startMint(t, "--meltAlwaysFails=true")
	client := lnurlcash.NewClient()
	k1 := secret(15)
	mint.credit(t, k1, 21000)

	if _, err := client.MeltNote(ctx(t), mint.callback(), k1, "lnbc210n1pjqrstuvwxyz"); err != nil {
		t.Fatalf("melt: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	// a failed melt is never reported through the callback - it is only
	// observable as the note becoming spendable again
	if state := mint.noteState(t, k1); state != "outstanding" {
		t.Fatalf("state after a failed melt = %s", state)
	}
}

// ---- minting ----

func TestMintsANoteTheServiceNeverSawTheSecretOf(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()

	pay, err := client.FetchPayRequest(ctx(t), mint.payURL())
	if err != nil {
		t.Fatalf("payRequest: %v", err)
	}
	if pay.WithdrawLink == "" {
		t.Fatal("not a minting payRequest")
	}
	// LUD-25 minting is comment-bound, so a mint must leave room for the
	// 64-character commitment. Without it there is nowhere to name the note.
	if !pay.NamesMintOutput() || pay.CommentAllowed != 64 {
		t.Fatalf("commentAllowed = %d (present %v)", pay.CommentAllowed, pay.HasCommentAllowed)
	}

	// The wallet chooses the secret, before any invoice exists, and persists it
	// before paying. The service is told sha256 of it and nothing more.
	mintSecret := secret(42)
	invoice, err := client.RequestMintInvoice(ctx(t), pay.Callback, 21000, mintSecret)
	if err != nil {
		t.Fatalf("invoice: %v", err)
	}
	if invoice.Disposable {
		t.Fatal("a mint address should not be disposable")
	}
	paymentHash := invoice.VerifyURL[strings.LastIndex(invoice.VerifyURL, "/")+1:]
	mint.settle(t, paymentHash)

	status, err := client.FetchInvoiceStatus(ctx(t), invoice.VerifyURL)
	if err != nil || !status.Settled {
		t.Fatalf("verify: %+v (%v)", status, err)
	}
	// The preimage is settlement proof and nothing else. Every node that
	// forwarded the payment learned it; under the earlier draft that made all of
	// them holders of the note. Here it redeems nothing.
	preimage := status.Preimage
	if id, _ := lnurlcash.HashK1(preimage); id != paymentHash {
		t.Fatalf("the preimage does not hash to the payment hash")
	}
	if preimage == mintSecret {
		t.Fatal("the mint must not know the note secret")
	}
	preimageURL := lnurlcash.BuildNoteURL(pay.WithdrawLink, preimage, -1)
	if _, err := client.FetchNoteInfo(ctx(t), preimageURL); err == nil {
		t.Fatal("the payment preimage must not redeem the note")
	}

	// The wallet's own secret is the note.
	noteURL := lnurlcash.BuildNoteURL(pay.WithdrawLink, mintSecret, -1)
	info, err := client.FetchNoteInfo(ctx(t), noteURL)
	if err != nil || info.MaxWithdrawableMsat != 21000 {
		t.Fatalf("minted note = %d (%v)", info.MaxWithdrawableMsat, err)
	}
	rotated, err := client.RotateNote(ctx(t), info.Callback, mintSecret)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if state := mint.noteState(t, mintSecret); state != "burned" {
		t.Fatalf("the spent secret is still live: %s", state)
	}
	if state := mint.noteState(t, rotated.K1); state != "outstanding" {
		t.Fatalf("rotated note state = %s", state)
	}
}

func TestRefusesToPayForANoteItCannotName(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()

	pay, err := client.FetchPayRequest(ctx(t), mint.payURL())
	if err != nil {
		t.Fatalf("payRequest: %v", err)
	}

	// A malformed commitment is refused before the request leaves, so a wallet
	// never pays for a quote the service was always going to reject.
	if _, err := client.RequestMintInvoice(ctx(t), pay.Callback, 21000, "not-a-32-byte-secret"); !errors.Is(err, lnurlcash.ErrRequestRefused) {
		t.Fatalf("malformed secret = %v, want ErrRequestRefused", err)
	}

	// And an unnamed mint quote is refused by the service itself, before any
	// invoice exists to pay.
	if _, err := client.RequestInvoice(ctx(t), pay.Callback, 21000); err == nil {
		t.Fatal("an unnamed mint quote must be refused")
	}
}

func TestReadsAnAdvertisedFee(t *testing.T) {
	mint := startMint(t, "--baseFeeMsat=1000", "--feePpm=2000")
	client := lnurlcash.NewClient()
	pay, err := client.FetchPayRequest(ctx(t), mint.payURL())
	if err != nil {
		t.Fatalf("payRequest: %v", err)
	}
	if !pay.HasMintFee || pay.MintFee.BaseFeeMsat != 1000 || pay.MintFee.FeePpm != 2000 {
		t.Fatalf("fee = %+v (%v)", pay.MintFee, pay.HasMintFee)
	}
}

func TestNoFeeAdvertisedMeansFeeFree(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	pay, err := client.FetchPayRequest(ctx(t), mint.payURL())
	if err != nil {
		t.Fatalf("payRequest: %v", err)
	}
	if pay.HasMintFee {
		t.Fatalf("read a fee where none was advertised: %+v", pay.MintFee)
	}
}

func TestFindsTheExperimentalMintAddress(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	address, err := client.FetchMintAddress(ctx(t), mint.url+"/.well-known/lnurlw/mint")
	if err != nil {
		t.Fatalf("mint address: %v", err)
	}
	if address.NodePubkey != mint.pubkey {
		t.Fatalf("node pubkey = %s", address.NodePubkey)
	}
	// the wire field is nodeCapacity - renamed here, so it only arrives if it
	// is mapped rather than read under its own name
	if address.NodeCapacityMsat != 500_000_000 {
		t.Fatalf("node capacity = %d msat", address.NodeCapacityMsat)
	}
	if address.NodeNumChannels != 4 || address.NodeNumPeers != 6 {
		t.Fatalf("channels = %d, peers = %d", address.NodeNumChannels, address.NodeNumPeers)
	}
}

// ---- mandatory offline verification ----

// LUD-25 stopped treating a note signature as optional, so a service that
// issues none is non-conforming rather than merely basic. The refusal has to be
// the loud kind - but the rotate LANDED, and the fresh secret is the only key
// to the note it minted, so the error carries it out. Refusing without it would
// be this package destroying real money to make a point about conformance.
func TestAnUnsignedRotateIsRefusedWithoutLosingTheNote(t *testing.T) {
	mint := startMint(t, "--signatures=false")
	client := lnurlcash.NewClient()
	k1 := secret(30)
	mint.credit(t, k1, 21000)

	_, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if !lnurlcash.IsUnverifiable(err) {
		t.Fatalf("want an unverifiable outcome, got %v", err)
	}
	kept := lnurlcash.NewSecrets(err)
	if len(kept) != 1 {
		t.Fatalf("carried %d secrets, want 1", len(kept))
	}
	// the note the caller was refused is real, outstanding, and reachable with
	// nothing but the secret the error handed back
	if state := mint.noteState(t, kept[0]); state != "outstanding" {
		t.Fatalf("the refused note is %s, want outstanding", state)
	}
}

// The same mint, for a caller who has decided to deal with it anyway. One
// field, and the note comes back unsigned - which is what it is.
func TestAnUnsignedServiceStillWorksWhenTheCallerOptsOut(t *testing.T) {
	mint := startMint(t, "--signatures=false")
	client := lnurlcash.NewClient()
	client.Policy = lnurlcash.Policy{AllowUnsignedNotes: true}
	k1 := secret(31)
	mint.credit(t, k1, 21000)

	info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(k1))
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	rotated, err := client.RotateNote(ctx(t), info.Callback, k1)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.Signature != "" {
		t.Fatalf("an unsigned service returned a signature: %q", rotated.Signature)
	}
	if state := mint.noteState(t, rotated.K1); state != "outstanding" {
		t.Fatalf("rotated note is %s", state)
	}
}

// ---- a mutation the transport retried ----

// The mutation landed and the answer was lost on the way back. LUD-25 now
// requires the service to answer the identical request with the success it
// already gave, so asking a second time turns this from an unresolved maybe
// into a completed rotate - the caller never sees an error at all.
func TestALostRotateCompletesByAskingAgain(t *testing.T) {
	mint := startMint(t, "--dropAfterMutation=true")
	client := lnurlcash.NewClient()
	k1 := secret(32)
	mint.credit(t, k1, 21000)

	rotated, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if err != nil {
		t.Fatalf("the retry did not resolve the rotate: %v", err)
	}
	if state := mint.noteState(t, k1); state != "burned" {
		t.Fatalf("input state = %s", state)
	}
	// the replay repeats the signature, so a note recovered this way is as
	// verifiable as one whose first answer arrived
	if rotated.Signature == "" {
		t.Fatal("the replayed success carried no signature")
	}
	info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(rotated.K1))
	if err != nil || info.MaxWithdrawableMsat != 21000 {
		t.Fatalf("the rotated note is not there: %d (%v)", info.MaxWithdrawableMsat, err)
	}
}

// A service that has not implemented the replay rule answers the second attempt
// as an already-spent input, exactly as before. The package cannot tell that
// from a genuine double spend - at the wire they are the same answer - so it
// hands the secrets back rather than a verdict.
func TestAMintThatWillNotReplayStillHandsTheSecretsBack(t *testing.T) {
	mint := startMint(t, "--dropAfterMutation=true", "--retriedMutation=refuse")
	client := lnurlcash.NewClient()
	k1 := secret(33)
	mint.credit(t, k1, 21000)

	_, err := client.RotateNote(ctx(t), mint.callback(), k1)
	rescued := lnurlcash.NewSecrets(err)
	if len(rescued) != 1 {
		t.Fatalf("carried %d secrets, want 1 (err %v)", len(rescued), err)
	}
	if state := mint.noteState(t, rescued[0]); state != "outstanding" {
		t.Fatalf("the rescued note is %s, want outstanding", state)
	}
}

// ---- ambiguous outcomes ----

// A client that gives up on the first ambiguous answer, as every client did
// before LUD-25 required a service to replay a retried mutation. The tests that
// assert what an unresolved mutation carries need it: with retries on, a
// conforming mint simply answers again and there is nothing left to carry.
func noRetryClient() *lnurlcash.Client {
	client := lnurlcash.NewClient()
	client.MutationRetries = -1
	return client
}

func TestALostRotatePreservesItsFreshSecret(t *testing.T) {
	mint := startMint(t, "--dropAfterMutation=true")
	client := noRetryClient()
	k1 := secret(16)
	mint.credit(t, k1, 21000)

	_, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if !lnurlcash.IsAmbiguous(err) {
		t.Fatalf("want an ambiguous outcome, got %v", err)
	}
	rescued := lnurlcash.NewSecrets(err)
	if len(rescued) != 1 {
		t.Fatalf("carried %d secrets, want 1", len(rescued))
	}
	// the mutation did land: the input is burned and the output exists, keyed by
	// the hash of a secret only the caller holds
	if state := mint.noteState(t, k1); state != "burned" {
		t.Fatalf("input state = %s", state)
	}
	info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(rescued[0]))
	if err != nil || info.MaxWithdrawableMsat != 21000 {
		t.Fatalf("the rescued secret is not the note: %d (%v)", info.MaxWithdrawableMsat, err)
	}
}

func TestALostSplitPreservesBothSecretsInOutputOrder(t *testing.T) {
	mint := startMint(t, "--dropAfterMutation=true")
	client := noRetryClient()
	k1 := secret(17)
	mint.credit(t, k1, 21000)

	_, err := client.SplitNote(ctx(t), mint.callback(), []string{k1}, 5000)
	rescued := lnurlcash.NewSecrets(err)
	if len(rescued) != 2 {
		t.Fatalf("carried %d secrets, want 2", len(rescued))
	}
	for index, want := range []int64{5000, 16000} {
		info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(rescued[index]))
		if err != nil || info.MaxWithdrawableMsat != want {
			t.Fatalf("output %d = %d (%v), want %d", index, info.MaxWithdrawableMsat, err, want)
		}
	}
}

func TestProbingResolvesTheAmbiguity(t *testing.T) {
	mint := startMint(t, "--dropAfterMutation=true")
	client := lnurlcash.NewClient()
	k1 := secret(18)
	mint.credit(t, k1, 21000)
	_, _ = client.RotateNote(ctx(t), mint.callback(), k1)

	if fate := client.ProbeBurnedNote(ctx(t), mint.noteURL(k1)); fate != lnurlcash.NoteGone {
		t.Fatalf("fate = %s, want gone", fate)
	}
}

func TestALiveNoteProbesAsLiveAndAnOfflineProbeKnowsNothing(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	k1 := secret(19)
	mint.credit(t, k1, 21000)

	if fate := client.ProbeBurnedNote(ctx(t), mint.noteURL(k1)); fate != lnurlcash.NoteLive {
		t.Fatalf("fate = %s, want live", fate)
	}
	offline := lnurlcash.NewClient()
	offline.Offline = true
	if fate := offline.ProbeBurnedNote(ctx(t), mint.noteURL(k1)); fate != lnurlcash.NoteFateUnknown {
		t.Fatalf("offline fate = %s, want unknown", fate)
	}
}

func TestA200ThatConfirmsNothingIsAmbiguous(t *testing.T) {
	mint := startMint(t, "--unconfirmedMutation=true")
	client := noRetryClient()
	k1 := secret(20)
	mint.credit(t, k1, 21000)

	_, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if !lnurlcash.IsAmbiguous(err) {
		t.Fatalf("want ambiguous, got %v", err)
	}
	if len(lnurlcash.NewSecrets(err)) != 1 {
		t.Fatal("the fresh secret did not survive")
	}
	if state := mint.noteState(t, k1); state != "burned" {
		t.Fatalf("the mutation did land, but the input state is %s", state)
	}
}

func TestAnUnreadableResponseIsAmbiguous(t *testing.T) {
	mint := startMint(t, "--malformedJson=true")
	client := lnurlcash.NewClient()
	k1 := secret(21)
	mint.credit(t, k1, 21000)

	_, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if !lnurlcash.IsAmbiguous(err) {
		t.Fatalf("want ambiguous, got %v", err)
	}
	if len(lnurlcash.NewSecrets(err)) != 1 {
		t.Fatal("the fresh secret did not survive")
	}
}

func TestATimeoutIsAmbiguousNotFailure(t *testing.T) {
	mint := startMint(t, "--slowMs=800")
	client := lnurlcash.NewClient()
	client.Timeout = 80 * time.Millisecond
	k1 := secret(22)
	mint.credit(t, k1, 21000)

	_, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if !lnurlcash.IsAmbiguous(err) {
		t.Fatalf("want ambiguous, got %v", err)
	}
	if len(lnurlcash.NewSecrets(err)) != 1 {
		t.Fatal("the fresh secret did not survive a timeout")
	}
}

func TestARefusedRequestIsDefinitelyNotSent(t *testing.T) {
	mint := startMint(t)
	client := lnurlcash.NewClient()
	client.Offline = true
	k1 := secret(23)
	mint.credit(t, k1, 21000)

	_, err := client.RotateNote(ctx(t), mint.callback(), k1)
	if err == nil || lnurlcash.IsAmbiguous(err) {
		t.Fatalf("offline is definitive, not ambiguous: %v", err)
	}
	if state := mint.noteState(t, k1); state != "outstanding" {
		t.Fatalf("state = %s - something was sent", state)
	}
}

func TestRefusesACallbackURLItWouldNotFetch(t *testing.T) {
	client := lnurlcash.NewClient()
	_, err := client.RotateNote(ctx(t), "http://evil.example/cb", secret(24))
	if err == nil || lnurlcash.IsAmbiguous(err) {
		t.Fatalf("want a definitive refusal, got %v", err)
	}
}

// ---- a service that lies ----

func TestALyingServiceCannotInflatePastWhatItSigned(t *testing.T) {
	mint := startMint(t, "--lieAboutValue=1000000")
	client := lnurlcash.NewClient()
	k1 := secret(25)
	signature := mint.credit(t, k1, 21000)

	info, err := client.FetchNoteInfo(ctx(t), mint.noteURL(k1))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if info.MaxWithdrawableMsat != 1021000 {
		t.Fatalf("the mint did not lie: %d", info.MaxWithdrawableMsat)
	}
	// the signature was issued over the true amount, so an offline holder catches
	// the inflation without asking anyone
	if lnurlcash.VerifyNoteSignature(k1, info.MaxWithdrawableMsat, signature, mint.pubkey) {
		t.Fatal("an inflated amount verified")
	}
	if !lnurlcash.VerifyNoteSignature(k1, 21000, signature, mint.pubkey) {
		t.Fatal("the true amount did not verify")
	}
}

// A rotate whose answer never arrives must not be reported as a settled
// note. If the request landed, the service burned that k1 and minted the
// rotated note under h, and the fresh secret carried on the error is the
// only copy of it. This used to discard the error and return the burned k1
// with a nil error, so a caller could not even ask.
func TestSettleSurfacesARotateThatMayHaveApplied(t *testing.T) {
	mint := startMint(t, "--dropAfterMutation=true")
	// Retrying off, so the ambiguity survives to the caller. With the default
	// one retry the service replays the original success per LUD-25's
	// "Retrying a mutation" and this resolves cleanly - which is the point of
	// that rule, and is covered by the settle test above.
	client := lnurlcash.NewClient()
	client.MutationRetries = -1
	k1 := secret(31)
	mint.credit(t, k1, 21000)

	settled, err := client.SettleNote(ctx(t), mint.noteURL(k1), k1, 0, "")
	if err == nil {
		t.Fatalf("an unconfirmable rotate was reported as settled: %+v", settled)
	}
	if !lnurlcash.IsAmbiguous(err) {
		t.Fatalf("want an ambiguous outcome, got %T: %v", err, err)
	}
	fresh := lnurlcash.NewSecrets(err)
	if len(fresh) != 1 {
		t.Fatalf("the fresh secret did not survive the error: %v", fresh)
	}
	if fresh[0] == k1 {
		t.Fatal("the secret carried out is the one that was burned")
	}
}

// The three fields the reference mint publishes on its discovery document.
// Parsed straight from a body rather than through the mock mint: the mock
// does not emit them, and what needs grading here is the mapping and what it
// refuses, not another round trip.

func mintAddressBody(t *testing.T, extra map[string]any) lnurlcash.MintAddress {
	t.Helper()
	body := map[string]any{
		"tag":             "withdrawRequest",
		"callback":        "https://mint.example/w/cb",
		"payLink":         "https://mint.example/.well-known/lnurlp/mint",
		"minWithdrawable": 1000,
		"maxWithdrawable": 100_000_000,
	}
	for key, value := range extra {
		body[key] = value
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	address, err := lnurlcash.ParseMintAddress(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return address
}

func TestReadsEveryAddressTheNodeAnnounces(t *testing.T) {
	clearnet := "02aa@2.29.14.244:9735"
	onion := "02aa@abcdefghijklmnop.onion:9735"
	address := mintAddressBody(t, map[string]any{
		"nodeUri":  clearnet,
		"nodeUris": []any{clearnet, onion},
	})
	if len(address.NodeURIs) != 2 || address.NodeURIs[0] != clearnet || address.NodeURIs[1] != onion {
		t.Fatalf("node uris = %v", address.NodeURIs)
	}
	// the singular field is unchanged and still the first address
	if address.NodeURI != clearnet {
		t.Fatalf("node uri = %s", address.NodeURI)
	}
}

func TestAnAnnouncedNothingIsNilNotEmpty(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"absent":      {},
		"empty":       {"nodeUris": []any{}},
		"not a list":  {"nodeUris": "not a list"},
		"all dropped": {"nodeUris": []any{1, "", nil}},
	} {
		if uris := mintAddressBody(t, extra).NodeURIs; uris != nil {
			t.Fatalf("%s: node uris = %v, want nil", name, uris)
		}
	}
	if uris := mintAddressBody(t, map[string]any{"nodeUris": []any{1, "a", "", nil}}).NodeURIs; len(uris) != 1 || uris[0] != "a" {
		t.Fatalf("node uris = %v", uris)
	}
}

func TestAClosingDateIsACalendarDayOrNothing(t *testing.T) {
	for _, good := range []string{"2026-12-31", "2028-02-29"} {
		if got := mintAddressBody(t, map[string]any{"sunsetDate": good}).SunsetDate; got != good {
			t.Fatalf("sunset date = %q, want %q", got, good)
		}
	}
	// A wallet showing a holder a closing date off an unchecked string is
	// worse than showing nothing, so anything that is not a real day goes.
	for _, bad := range []any{
		"31/12/2026", "2026-12-31T09:00:00Z", "2026-02-31", "2026-02-29",
		"2026-13-01", "2026-00-10", "2026-12-00", 20261231, nil,
	} {
		if got := mintAddressBody(t, map[string]any{"sunsetDate": bad}).SunsetDate; got != "" {
			t.Fatalf("sunset date from %v = %q, want empty", bad, got)
		}
	}
	if got := mintAddressBody(t, map[string]any{}).SunsetDate; got != "" {
		t.Fatalf("sunset date = %q, want empty", got)
	}
}

func TestWhatAMintSaysItOwesKeepsZeroDistinctFromSilence(t *testing.T) {
	owed := mintAddressBody(t, map[string]any{"outstandingNotesMsat": 48_000}).OutstandingNotesMsat
	if owed == nil || *owed != 48_000 {
		t.Fatalf("outstanding = %v", owed)
	}
	// The whole reason this one is a pointer: zero is an answer.
	zero := mintAddressBody(t, map[string]any{"outstandingNotesMsat": 0}).OutstandingNotesMsat
	if zero == nil || *zero != 0 {
		t.Fatalf("outstanding = %v, want a pointer to 0", zero)
	}
	if silent := mintAddressBody(t, map[string]any{}).OutstandingNotesMsat; silent != nil {
		t.Fatalf("outstanding = %v, want nil", silent)
	}
	if text := mintAddressBody(t, map[string]any{"outstandingNotesMsat": "48000"}).OutstandingNotesMsat; text != nil {
		t.Fatalf("outstanding = %v, want nil", text)
	}
}
