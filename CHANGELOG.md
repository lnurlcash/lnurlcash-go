# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## 0.1.0 — unreleased

### The import path is `github.com/lnurlcash/lnurlcash-go`

The repository moved into the `lnurlcash` org. GitHub redirects the old path
and `go get` follows it, so nothing was broken — but a module path is the one
thing that cannot be corrected quietly once a version is tagged, because every
importer has it written down. Fixed here, before the first tag, rather than
becoming a rename nobody can undo.


### Three more fields off a mint address

`ParseMintAddress` reads `nodeUris`, `sunsetDate` and `outstandingNotesMsat`,
which the reference mint publishes and this dropped.

- `NodeURIs` — every address the service's node announces. `NodeURI` is the
  first of them; a node behind Tor as well as clearnet has more. Nil rather
  than an empty slice when there are none.
- `SunsetDate` — the day the service plans to close, ISO-8601. Validated as a
  real calendar day and left empty otherwise: the one thing a wallet does with
  this is show it to a holder, and a wrong date is worse than no date.
- `OutstandingNotesMsat` — what the service says it owes. A `*int64`, unlike
  every other number on this struct, because zero is a real answer and the
  zero value cannot tell "owes nothing" from "will not say".

### Seed-recoverable note secrets, and the private lookup a restore needs

- `cash.go`: LUD-25's `m/139'` scheme. `DeriveCashRoot`,
  `DeriveCashDomainNode`, `DeriveCashSecret`, `CashSecretAt`,
  `CashDomainIndices`, `CashNodeToHex`/`FromHex`, `DeriveCashChild` and
  `CashSecretSource`. `d1..d4` are raw uint32 used exactly as they fall,
  hardened only where they land at or above 2^31; masking the top bit or
  hardening all four derives a different tree from every conforming wallet.
- `DeriveNoteRoot` / `DeriveNoteSecret`: the pre-spec HMAC scheme, so notes
  minted under it stay findable. Not what to mint under.
- `BuildNoteInfoURLByHash` and `ParseNoteInfoByHash`: LUD-25's `?h=`
  informational GET. A restore walk queries a whole gap window of indices the
  wallet has not minted into yet, so asking by secret publishes exactly the
  secrets it is about to mint under.
- Graded against `lnurlcash-conformance` 0.7.0's `cash-derivation.json` and
  `derivation.json`, including BIP-32's own published test vector 1.
- `btcec` and `decred/secp256k1` move from indirect to direct requirements;
  both were already compiled in for signature verification.

First release. A Go implementation of LNURLcash, following the protocol layer
of dni's [lnurl-wallet](https://github.com/dni/lnurl-wallet) and checked against
the shared
[conformance vectors](https://github.com/lnurlcash/lnurlcash-conformance)
and the adversarial mock mint.

### Design notes

**Offline verification is mandatory, and this package insists on it.** LUD-25
stopped treating a note signature as optional: a service MUST publish
`mintPubkey` and MUST sign every note a rotate, split or merge mints. So
`ParseNoteInfo` refuses a `withdrawRequest` publishing no `mintPubkey`, or one
that is not a 33-byte compressed secp256k1 key, and `ParseMutation` returns
`*UnverifiableError` when a service confirms a mutation without signing it.
`Policy{AllowUnsignedNotes: true}` opts out; the field is named for what it
permits so the zero value is the strict one.

That error carries the fresh secrets, and the reason matters: `status` was OK,
so the mutation LANDED. The note exists at the hash the wallet disclosed and
that secret is the only key to it, so enforcing the spec must never be the
thing that strands the money.

**A spent-or-unknown refusal from a mutation carries its secrets too.** At a
service that has not implemented the replay rule below, a retried mutation is
answered as an already-spent input - so that refusal is also what a mutation
the service ALREADY applied looks like. `ServiceError` gained `NewSecrets`, and
`NewSecrets(err)` reads them off all three families that can carry them. A
refusal on policy grounds burned nothing and still carries nothing.

**A mutation whose answer was lost is re-sent, and usually completes.** LUD-25
gained a "Retrying a mutation" section: a service MUST answer a byte-identical
rotate, split or merge with the success it already returned. That closes the
hazard this package's `DisableKeepAlives` was working around, so `Client`
re-sends deliberately - `MutationRetries`, default one extra attempt.

Never a melt, which carries `pr`, is paid asynchronously and has no replay
guarantee; never a definitive refusal, which is the service's considered
answer; and the same `Request` goes out each time rather than a rebuilt one,
because the replay is matched on the k1 set, `h`, `h2` and `amount` - a
regenerated secret would make the retry a different mutation, and a second real
burn. Keep-alives stay disabled regardless: a deliberate retry this package
counts is a different thing from an invisible one it does not.

**Minting is comment-bound, and the payment preimage is only settlement proof.**
The draft keyed a fresh note by the invoice's payment preimage until 31 August
2026, when that fallback was removed outright: a preimage propagates to every
node that forwarded the payment, routinely before the payer has finished
processing it, so a note keyed by one is a note all of them can spend. A WALLET
now chooses the secret itself, before any invoice exists, and hands the SERVICE
only `sha256(secret)` in a mandatory LUD-12 `comment`; a minting `payRequest`
must advertise `commentAllowed >= 64` or it cannot mint at all. `MintInvoiceRequest` returns the secret on
`Request.NewSecrets` - persist it before paying, because the service holds
nothing that could reconstruct it.

**The mint address carries the node stats under their wire names.** lnurl-mint
advertises `nodeCapacity` in msat, so `NodeCapacityMsat` is a rename and is
mapped explicitly — the TypeScript sibling shipped that rename unmapped and
read undefined for every mint.



**`NewClient` disables keep-alives.** `net/http` retries an idempotent request
that was sent on a reused connection, and every LNURLcash mutation is a GET
that is not idempotent — so a retry gets "already spent" for its second attempt
and reports a definitive rejection, discarding the fresh secret of a note the
service just minted. Worse, a client with no `Transport` uses the
process-wide default pool, so the behaviour depends on what unrelated code did
first. Found by the mock mint's `dropAfterMutation` mode, which failed two
tests until the transport changed.

**The protocol layer has no I/O.** Each operation is a `Request` — a URL, and
the fresh secrets that must survive a lost answer — paired with a `Parse*`
function. `Client` is a thin loop over exactly those.

**The proportional fee term is computed split**, as
`(g/1e6)*ppm + ((g%1e6)*ppm)/1e6`. A direct multiply overflows `int64` at
realistic amounts: 21M BTC is 2.1e15 msat, and at 999_999 ppm the product is
about 2.1e21.

**`GrossUpForMintFee` is a binary search**, not an estimate-then-walk. At a
99.9999% fee a one-msat walk is around a million steps, so any guard on it
returns a non-minimal answer — and the fee is chosen by the service.

**A service's reason is carried through exactly as sent**, empty string
included. Substituting a friendly default before classification would be read
back as though the service had said it: "unknown service error" matches the
rule for an unknown note.

**Note URLs keep their parameter order.** `url.Values` is a map and cannot, but
a note URL's shape is user-visible — quoted in bug reports and compared by eye.
