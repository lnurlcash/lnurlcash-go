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
returned, any signatures included, rather than with the already-spent refusal. So
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

## Legacy signatures and cp1 certificates

The reference mint returns a raw Part 1 signature for a legacy hash output
when a signer is available, and may omit it in no-signer mode. This package
accepts that omission by default and passes through any signature received.

A `cp1` output is owed its `cs1` certificate, always, and no `Policy` waives
it. A mutation to one that the service confirms without it returns
`*UnverifiableError`, which **carries the fresh secrets**, because the mutation
landed and the note it minted is real. Read them with `NewSecrets` and persist
them before anything else. The `*WithHash` calls have none to carry: you named
the output, so you already hold what spends it.

`ParseNoteInfo` still refuses a `withdrawRequest` publishing no valid
`mintPubkey`, because that key is what a `cs1` verifies against.

The zero `Policy` is the default. Two fields move it:

- `RequireSignatures: true` demands the raw Part 1 signature over a hash
  output, matching the committed reference wallet.
- `AllowMissingMintPubkey: true` admits a Part 1-only mint that publishes no
  `mintPubkey`. Nothing it issues can then be verified offline.

To hold a note a recipient can check offline, rotate it into a `cp1` key.

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
mutation, err := lnurlcash.ParseMutation(body, request, lnurlcash.MutationRotate, lnurlcash.Policy{})
```

`ParseMutation` takes the whole `Request` back. Its URL records which outputs
were `cp1` keys, and so which are owed a certificate, which means a
`Request{URL, NewSecrets}` rebuilt from what you persisted is read the same way.

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
| `IsUnverifiable(err)` | the mutation **landed**, but a `cp1` output came back without its `cs1`. `NewSecrets(err)` carries the secrets. |
| `*ProtocolError` | a non-mutating response did not match the spec. |

## Two things ports get wrong

Both are caught by the conformance vectors:

**The proportional fee term overflows.** `gross * ppm / 1_000_000` exceeds
`int64` at realistic amounts — 21M BTC is 2.1e15 msat, times 999_999 ppm is
about 2.1e21. It is computed split.

**Gross-up must be a binary search.** Estimate-then-walk is unbounded at a
99.9999% fee, so any guard on it returns a non-minimal answer — and the
*service* picks the fee.

## Seed derivation

LUD-25 derives a wallet's per-mint branch from its seed, and this package
implements the specified path:

```
cashHashingKey   = m/139'/0
(d1, d2, d3, d4) = HMAC-SHA256(cashHashingKey, host)[0..16] as 4 uint32
domainNode       = m/139'/d1/d2/d3/d4
```

`d1..d4` are used **exactly as they fall**. BIP-32 reads any index `>= 2^31`
as hardened, so which of the four levels are hardened is decided by the mint's
own host name. Masking the top bit, or hardening all four, derives a different
tree and restores nothing, silently.

```go
root, err := lnurlcash.DeriveCashRoot(seed)               // m/139'
node, err := lnurlcash.DeriveCashDomainNode(root, host)   // m/139'/d1/d2/d3/d4
```

That domain node is Part 2's address branch, below. Part 1 secrets are not
derived from the seed at all: LUD-25 has the wallet draw them as plain
randomness, which is what `GenerateNoteSecret` does. An earlier deterministic
Part 1 ladder beneath this node (`DeriveCashSecret`, `CashSecretAt`,
`CashSecretSource`) was never part of the spec and is gone.

`DeriveNoteRoot` / `DeriveNoteSecret` are the pre-spec HMAC scheme this
project shipped before the draft had one. Not deprecated, because notes minted
under it are still money; just not what to mint under. `BuildNoteInfoURLByHash`
is the private lookup a restore walk over them should use; asking by secret
publishes the very secrets it is looking for.

## Notes keyed by a public key (LUD-25 Part 2)

A Part 2 note swaps the hash for a key pair. The wallet keeps `sk`; the mint
only ever sees `pk`, written `cp1…`. To spend the note you hand over `ck1…`:
the 32-byte `pk` followed by a BIP-340 Schnorr signature by `sk` over
`sha256("LNURLcash")`. The mint verifies the pair and uses `pk` to find the
note. The mint's certificate, `cs1…`, carries the note amount
in its prefix using BOLT 11 amount rules and contains the signature over
`LNURLcash:<amount_msat>:<hex(pk)>`, so a recipient can recover the claimed
amount and check the note offline. A `cp1` note is the only kind the spec
certifies.

```go
root, _ := lnurlcash.DeriveCashRoot(seed)
node, _ := lnurlcash.DeriveCashAddressNode(root, "mint.example") // m/139'/d1/d2/d3/d4
cx, _ := lnurlcash.CashNodeToCx1(node)
cx1 := lnurlcash.EncodeCx1(cx.PubkeyXOnly, cx.ChainCode)          // watch-only

pk, _ := lnurlcash.DeriveNotePubkey(cx.PubkeyXOnly, cx.ChainCode, i) // what a watcher derives
sk, _ := lnurlcash.DeriveNoteSecretKey(node.PrivateKey, node.ChainCode, i)
proof, _ := lnurlcash.SignNoteOwnership(sk)                         // pk || sig, 96 bytes
ck1 := lnurlcash.EncodeCk1(proof)                                   // the bearer secret

lnurlcash.VerifyNoteSignature(ck1, amountMsat, cs1, mintPubkey)     // offline
certificate, _ := lnurlcash.DecodeCs1WithAmount(cs1)                // amount + signature
```

`EncodeCs1WithAmount`, `DecodeCs1WithAmount` and `IsCs1WithAmount`
are the current wire API. The fixed-prefix `EncodeCs1`, `DecodeCs1` and
`IsCs1` remain for legacy notes; `DecodeAnyCs1` and `IsAnyCs1` accept either
form during migration. Verification accepts both forms, matching the reference
kit; decode the certificate separately if the application needs to compare its
carried amount with another value.

Reference-mint address management proves control with the address branch's
index-0 private key. `SignAddressProof(sk0, action, username)` returns the raw
64-byte BIP-340 proof over `sha256("LNURLcash:<action>:<username>")`; action is
`register` or `unregister`, and the username must be normalised exactly as it
is sent to the service.

A `ck1` goes anywhere a `k1` does: a note URL, `FetchNoteInfo`, rotate, split,
merge and melt. A `cp1` goes anywhere an output does: `RequestMintInvoiceWithHash`
sends it as the comment alone, and the `*WithHash` calls send it as `p1`/`p2`
while a hash keeps `h`/`h2`. `NoteIDOf(k1)` is the id a mint files either kind
under - compare notes by it, never by `k1` - and `NoteLookupOf(k1)` is what
to pass `FetchNoteInfoByHash`. A `ck1` is deterministic from its note key, so
seed recovery reproduces it byte for byte. `DecodeCk1` and the lookup helpers
also accept the old 65-byte recoverable-ECDSA shape, and a 96-byte proof
signed over the raw message rather than its digest, so existing notes remain
spendable; rotate those into a current `ck1` rather than issuing new legacy
values.

- **The branch is the spec's literal path.** `m/139'/d1/d2/d3/d4`, hashing
  key at `m/139'/0`: the same node `DeriveCashDomainNode` returns. Notes
  received under the earlier `m/139'/1'` hop are not on it.
- **A `cx1` links every note on its branch.** It spends nothing, but whoever
  holds it can list every key on the branch. Receive on it, then rotate off.
- **`i` is any uint32**, four bytes big-endian, never hardened.

`DeriveNostrAddressNode(secretKey, host)` roots the same branch in a Nostr
identity key instead of a seed phrase: `HMAC-SHA256(key, "LNURLcash/nostr-seed")`,
then the path above. That is ours, not LUD-25's, and heartwood-esp32 derives
the same branch on the device. Both are graded against conformance's
`part2.json` and `nostr-seed.json`, every field.

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
