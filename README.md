# lnurlcash-go

LNURLcash ([LUD-25 draft](https://github.com/lnurl/luds/pull/301)) bearer notes
for Go: mint, rotate, split, merge, melt, and verify a note offline.

```bash
go get github.com/lnurlcash/lnurlcash-go
```

Early `0.x`, tracking a **draft** spec. Pin an exact version.

## Read this before you use any LNURLcash client in Go

Every LNURLcash mutation — rotate, split, merge, melt — is an HTTP **GET**.
HTTP considers GET idempotent, so a transport may resend one when a connection
fails mid-flight. An LNURLcash mutation is emphatically *not* idempotent: the
first attempt burns the input note.

For most of this draft's life that was fatal. A service applied a rotate, the
connection dropped, a retrying transport sent it again, and the second attempt
got `"invalid or already spent k1"` — a **definitive rejection**. The caller
concluded nothing had happened and discarded the fresh secret, which was the
only copy of the note the service had just minted.

`net/http` does exactly that resend, under a condition that is easy to miss: it
retries an idempotent request that was sent on a **reused** connection. A
client with no `Transport` of its own uses `http.DefaultTransport`, whose
connection pool is shared process-wide — so whether your mutation was silently
retried depended on whether some unrelated code happened to talk to the same
host first. This package found it by running against a mock mint that hangs up
mid-mutation, and failed two tests until the transport changed.

**LUD-25 has since closed the hole at the other end.** A service MUST now
answer a byte-identical rotate, split or merge with the success it already
returned, signature and all, rather than with the already-spent refusal. So
`Client` re-sends a mutation whose answer was lost — deliberately, bounded, and
never a melt — and a dropped connection usually resolves into a completed
mutation instead of an unresolved maybe:

```go
// the connection dropped after the mint applied this. It completes anyway.
rotated, err := client.RotateNote(ctx, callback, oldK1)
```

`MutationRetries` sets how many extra attempts (zero means the default of one;
negative turns it off). Only rotate, split and merge — never a melt, which
carries `pr`, is paid asynchronously and has no replay guarantee — and only an
ambiguous failure, never a refusal the service actually considered. The
re-sent request is byte-identical, because the replay is matched on the k1 set,
`h`, `h2` and `amount`.

`NewClient` still sets `DisableKeepAlives`. A deliberate retry this package
counts is a different thing from an invisible one it does not, a service that
has not caught up still answers the second attempt as already spent, and a
fresh connection per request is not a cost worth weighing against leaving that
to chance. **If you supply your own `*http.Client`, do the same.**

## Offline verification is mandatory

A service MUST publish `mintPubkey` and MUST sign every note a rotate, split or
merge mints. `ParseNoteInfo` refuses a `withdrawRequest` publishing no valid
one, and a mutation the service confirms but does not sign returns
`*UnverifiableError` — which **carries the fresh secrets**, because the
mutation landed and the note it minted is real. Read them with `NewSecrets`
and persist them before anything else.

`Policy{AllowUnsignedNotes: true}` opts out for a service that predates the
requirement. The zero value is the strict one, so a caller has to say the
dangerous thing out loud.

## Usage

```go
client := lnurlcash.NewClient()

url := lnurlcash.ResolveNoteInput(scanned)   // bech32, lnurlw://, or https
if url == "" {
    return errors.New("not a note")
}

info, err := client.FetchNoteInfo(ctx, url)  // what is it actually worth?
if err != nil {
    return err
}

rotated, err := client.RotateNote(ctx, info.Callback, info.K1)
if err != nil {
    if lnurlcash.IsAmbiguous(err) {
        // FIRST. ALWAYS. These may be the only copy of the note.
        if saveErr := save(lnurlcash.NewSecrets(err)); saveErr != nil {
            return saveErr
        }
        switch client.ProbeBurnedNote(ctx, url) {
        case lnurlcash.NoteLive:        // nothing landed; those secrets are worthless
        case lnurlcash.NoteGone:        // the burn landed; those secrets ARE the note
        case lnurlcash.NoteFateUnknown: // keep everything, try again later
        }
    }
    return err
}
```

`lnurlcash.IsAmbiguous(err)` is the single most important question to ask about
any failure here. Its opposite — `ErrRequestRefused`, and a `*ServiceError` —
means the operation definitively did not happen.

### Bring your own HTTP stack

Everything about the protocol is a `Request`/`Parse` pair with no I/O in it:

```go
request, err := lnurlcash.RotateRequest(callback, k1, freshSecret)
// request.URL to GET, request.NewSecrets to persist FIRST
body, err := yourTransport(request.URL)
mutation, err := lnurlcash.ParseMutation(body, request.NewSecrets)
```

`Client` is a thin loop over exactly these. If you use them directly, the
retry warning above is yours to honour.

## The other three things that will cost you money

**Never let the service generate a replacement secret.** On rotate, split and
merge this package draws a fresh 32 bytes and discloses only `sha256(secret)`
as `h`. A service-issued replacement has, structurally, been seen by that
service.

**A melt's success means "in flight", not "spent".** The service pays
asynchronously and only burns the note once the payment settles, restoring it
if the payment fails. A failed melt is never reported back — only observed as
the note becoming spendable again. `ErrNotePending` means retry, never spent.

**Rotate the instant you claim a minted note.** The preimage that mints a note
is generated by the service, and if it serves LUD-21 `verify`, anyone who saw
the unpaid invoice can poll for it. First rotater wins.

## Errors

| Check | Means |
| --- | --- |
| `errors.Is(err, ErrRequestRefused)` | nothing was sent. The note is untouched. |
| `errors.Is(err, ErrNotePending)` | a melt is in flight on this `k1`. Retry. |
| `IsSpent(err)` | authoritative: already burned. |
| `IsUnknownNote(err)` | the service does not recognise it. |
| `IsAmbiguous(err)` | outcome **unknown**. `NewSecrets(err)` carries the secrets. |
| `*ProtocolError` | a non-mutating response did not match the spec. |

## Two things ports get wrong

Both are caught by the conformance vectors:

**The proportional fee term overflows.** `gross * ppm / 1_000_000` exceeds
`int64` at realistic amounts — 21M BTC is 2.1e15 msat, times 999_999 ppm is
about 2.1e21. It is computed split.

**Gross-up must be a binary search.** Estimate-then-walk is unbounded at a
99.9999% fee, so any guard on it returns a non-minimal answer — and the
*service* picks the fee.

## Seed-recoverable note secrets

LUD-25 specifies them, and this package implements the specified scheme:

```
cashHashingKey   = m/139'/0
(d1, d2, d3, d4) = HMAC-SHA256(cashHashingKey, host)[0..16] as 4 uint32
k1_i             = m/139'/d1/d2/d3/d4/i'
```

`d1..d4` are used **exactly as they fall**. BIP-32 reads any index `>= 2^31`
as hardened, so which of the four levels are hardened is decided by the mint's
own host name. Masking the top bit, or hardening all four, derives a different
tree and restores nothing, silently. Only `i` is always hardened.

```go
root, err := lnurlcash.DeriveCashRoot(seed)          // m/139'
source, err := lnurlcash.NewCashSecretSource(root, host, counter)
k1, err := source.Next()                             // hand to a mutation
save(host, source.NextIndex())                       // BEFORE the hash goes out
```

`DeriveCashDomainNode` is its own step for a reason: every unhardened level
sits at or above it, so a hardware signer provisioned with that node rather
than the seed needs **no elliptic curve at all**. The cost is that whoever
derives it can derive every note secret held at that mint - provisioning
material, one mint's subtree, not the wallet.

`DeriveNoteRoot` / `DeriveNoteSecret` are the pre-spec HMAC scheme this
project shipped before the draft had one. Not deprecated, because notes minted
under it are still money; just not what to mint under.

**The counter is half the backup.** A service must answer a hash lookup for a
burned note exactly as it answers one for a note it never issued, and a rotate
burns the index below, so a wallet that has rotated more than its gap limit
cannot find its own position by scanning. The per-host counter is not secret -
an index reveals nothing without the root - so back it up, and merge it
upwards only. `BuildNoteInfoURLByHash` is the private lookup a walk should
use; asking by secret publishes the very indices the wallet is about to mint
under.

## Amounts

`int64` milli-satoshis, everywhere, with no exceptions.

## Conformance

```bash
go test ./...    # needs node and the conformance repo alongside
```

Tested against
[lnurlcash-conformance](https://github.com/lnurlcash/lnurlcash-conformance):
the same vectors as the TypeScript, Python, Rust and Kotlin implementations,
plus a mock mint that can be told to drop a connection mid-mutation, sign in
the wrong byte order, lie about a note's value, or never settle a melt.

## Reference implementations

Both by dni, both MIT: [lnurl-mint](https://github.com/dni/lnurl-mint) and
[lnurl-wallet](https://github.com/dni/lnurl-wallet).

The wider ecosystem — wallets, mints, hardware and the sibling ports — is
indexed in [awesome-lnurlcash](https://github.com/lnurlcash/awesome-lnurlcash).

## License

MIT.
