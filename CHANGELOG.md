# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## 0.1.0 — unreleased

### A plain note is unsigned

LUD-25 Part 2 certifies `cp1` notes only: a plain hash has nothing a mint
could attest to without disclosing the secret. The reference mint and moneyer
now answer a rotate, split or merge to a hash output with a bare
`{"status":"OK"}`, and under the old default this package refused every one
of those. It follows lnurlcash-kit 0.13.0.

- `Policy.RequireSignatures` is now a field, and false by default. A hash
  output that comes back unsigned is the spec, not a fault: `Signature` (and
  `ChangeSignature`) is empty, and no `*UnverifiableError` is raised. Set it
  true to keep demanding the old Part 1 signature over the hash. A signature
  that is present is passed through as before, for the caller to verify.
- A `cp1` output is owed its `cs1` certificate whatever the `Policy` says. A
  rotate, split or merge naming one (`p1`, or `p2` for a split's change) that
  comes back without `sig` (or `sig2`) returns `*UnverifiableError`, carrying
  the fresh secrets as before. From the `*WithHash` calls that is none: the
  caller supplied the output, and this package never saw what spends it.
- `Policy.AllowMissingMintPubkey` is new, with `Policy.RequireMintPubkey()`
  saying it the other way round. It takes over the `withdrawRequest`
  `mintPubkey` check the signature requirement used to carry. Still required
  by default; set it to admit a Part 1-only mint that publishes none.
- `Policy.AllowUnsignedNotes` is gone, and so is the `RequireSignatures()`
  method, whose name the field now has. The old field switched off both checks
  at once; `AllowMissingMintPubkey: true` is what is left of it.
- `ParseMutation` takes the `Request` in place of its `NewSecrets`, and reads
  which outputs are `cp1` off its URL. From the wire rather than a field of
  its own, so a `Request` rebuilt from a persisted URL for LUD-25's
  byte-identical retry is held to the same rule.
- Graded against `lnurlcash-conformance` 0.10.0's `responses.json`, every
  case, which this suite had never driven. Each goes through the `Client`
  against a local server. `output` and `change` pick a `cp1` where a case
  mints one, and the hash cases run again through the calls that draw their
  own secrets, to grade which outcomes carry them out. CI's conformance
  checkout moves to v0.10.0.

If you relied on the default to refuse unsigned plain notes, set
`RequireSignatures: true`. If you only ever wanted verifiable notes, hold
`cp1` notes, the only kind the spec makes verifiable.

### LUD-25 Part 2: notes keyed by a public key

`recoverable.go`, mirroring lnurlcash-kit's `recoverable.ts`.

- The four encodings: `cp1` (a note's x-only key), `ck1` (the recoverable
  ownership signature that spends it), `cs1` (the mint's certificate) and `cx1`
  (a watch-only branch). Strict bech32m with no length limit. The decoders
  refuse mixed case, a bech32 checksum, a wrong prefix or length and non-zero
  padding, with an error and never a panic.
- `DeriveCashAddressNode`, `CashNodeToCx1`, `DeriveNotePubkey`,
  `DeriveNoteSecretKey`, `SignNoteOwnership` and `RecoverNoteOwnershipPubkey`.
  The branch is the reference wallet's `m/139'/1'/d1..d4`, not the spec text's
  `m/139'/d1..d4`, which is the Part 1 ladder's own node.
- `NoteIDOf` and `NoteLookupOf`: the id a mint files either kind of note under,
  and what to look it up by without disclosing it. One note has many valid
  `ck1` strings, so notes compare by id.
- A `ck1` goes anywhere a `k1` does, and a `cp1` anywhere an output does: `p1`
  and `p2` in the `*WithHash` requests (a hash keeps `h` and `h2`), `p` on the
  hash lookup, and the comment alone when minting. `ResolveNoteInput` takes a
  note URL carrying a `ck1`.
- `VerifyNoteSignature` takes a `ck1` as the k1 and a `cs1` as the signature.
  `VerifyNoteSignatureHash`, `NoteSignatureMessageForHash` and
  `NoteSignatureDigestForHash` do the same from the note's id, for a watcher
  that has only the key. All of them now refuse a hex k1 that is not 32 bytes,
  which they used to hash regardless, as the TypeScript kit does. A note secret
  is 32 bytes, so no real note was ever signed over one.
- `Client` gains `RotateNoteWithHash`, `SplitNoteWithHash`,
  `MergeNotesWithHash`, `RequestMintInvoiceWithHash` and `FetchNoteInfoByHash`.
  Minting to a key means naming your own outputs, and a caller doing that
  should not lose the retry and the safe transport for it.
- `ParseNoteInfo` compares an echoed `ck1` by the note it names, so a service
  echoing another valid spelling of the same note is not mistaken for one that
  saw it rotated away.
- `DeriveNostrCashSeed` and `DeriveNostrAddressNode`: a branch rooted in a
  Nostr identity key, for a holder with no seed phrase. An extension, not
  LUD-25.
- `DeriveCashMaster`, for walking a path this package does not name.
- Fixed: `BuildNoteInfoURLByHash` added `amount=0` to a lookup that promises to
  carry no amount, which a strict mint may refuse rather than ignore.
- Graded against `lnurlcash-conformance` 0.9.0's `part2.json` and
  `nostr-seed.json`, every field, decoded strictly so a new field fails until
  it is graded. CI now pins the conformance checkout to that tag.

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

**A cp1 note is certified, and this package insists on it.** LUD-25 Part 2
certifies `cp1` notes only: a service MUST return a `cs1` for every `cp1`
output a rotate, split or merge mints, and `ParseMutation` returns
`*UnverifiableError` when one comes back without it, whatever the `Policy`
says. A plain hash output is unsigned by design, and passes unsigned unless
`Policy{RequireSignatures: true}` asks for the old Part 1 signature.
`ParseNoteInfo` refuses a `withdrawRequest` publishing no `mintPubkey`, or one
that is not a 33-byte compressed secp256k1 key, unless
`Policy{AllowMissingMintPubkey: true}`; that field is named for what it
permits, so the zero value is the strict one.

That error carries the fresh secrets, and the reason matters: `status` was OK,
so the mutation LANDED. The note exists at the key or hash the wallet
disclosed, and whatever is behind it is the only key to it, so enforcing the
spec must never be the thing that strands the money.

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
