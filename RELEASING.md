# Releasing lnurlcash-go

Go modules need no registry upload or publishing secret. An immutable
repository tag is the release artefact, and the public module proxy indexes it
on demand.

## Rehearsal

From a clean checkout of the intended commit:

```sh
go vet ./...
test -z "$(gofmt -l .)"
go test ./...
```

Run the tests with `LNURLCASH_CONFORMANCE` pointing to the pinned
`lnurlcash-conformance` checkout when reproducing CI locally.

## Release

1. Date the matching changelog entry and merge only after CI passes.
2. Create and push the exact semantic version tag, for example `v0.1.0`.
3. Create the matching GitHub release without moving or recreating the tag.
4. Verify the public module outside this checkout:

   ```sh
   GOPROXY=https://proxy.golang.org go list -m \
     github.com/lnurlcash/lnurlcash-go@v0.1.0
   ```

The module path in `go.mod` is permanent once consumers resolve a tagged
version, so confirm it before the first tag.
