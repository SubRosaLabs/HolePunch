# Releasing HolePunch

The repository source remains public. Release **binaries**, not normal development builds, are obfuscated with [Garble](https://github.com/burrowers/garble) `v0.14.2` (`-literals`, `-trimpath`, `-s -w`). This is the last tagged Garble release that supports the repository's Go 1.24 toolchain. Do not use `@latest` without updating and testing Go and Garble together. `-tiny` is intentionally omitted so crash diagnostics remain usable.

Garble removes Go build/module metadata and hashes package paths; literal obfuscation prevents the tested static `HolePunch`, GitHub owner, and common Go module-path prefixes from appearing in the release binaries. `scripts/verify_release.py` fails the build if these exact plaintext fingerprints appear in any of the ten artifacts, then writes sorted `SHA256SUMS`. This is **not secrecy**: filenames, runtime `-version` output, behavior, and public source still identify the project; strings can be recovered by sufficiently motivated reverse engineering. Keep the source tag and `go.mod` available to users for dependency and vulnerability review, since `go version -m` will no longer provide an SBOM.

## Build and verify (no publication)

1. Use Go **1.24.x** and install the pinned build tool: `go install mvdan.cc/garble@v0.14.2`. Ensure that `go` and `garble` on `PATH` match those versions.
2. Run `go test -race ./...` and `go vet ./...` on the source.
3. Run `make release`. This cross-builds client and server for Linux amd64/arm64, macOS amd64/arm64, and Windows amd64; it does not tag or publish.
4. Run `make checksums` to revalidate and regenerate `bin/release/SHA256SUMS` after an independent inspection. On Linux run `cd bin/release && sha256sum -c SHA256SUMS` as a second check. Run your native server/client with `-version` and test the protocol before publishing. Cross-compiled binaries should also be exercised on each target OS where available.

Development `make build` remains ordinary Go for debugging. The release verifier checks a *specific fingerprint list*, not every potentially revealing string or embedded resource. Update its list and tests if the product's public identifiers change.

## Publish on GitHub

1. Merge the release-pipeline PR into the default branch through normal review. Choose an intentional semantic version (`vX.Y.Z`) and write release notes in a local file.
2. Check out the clean merged commit, create an annotated tag and push **only the tag**: `git tag -a vX.Y.Z -m 'Release vX.Y.Z' && git push origin vX.Y.Z`. Verify that the public GitHub tag resolves to the same commit before publishing. Never bypass the default-branch PR workflow.
3. Build from the clean tagged checkout with `make release`; review binaries, tests, and `SHA256SUMS`.
4. Authenticate `gh` to the public GitHub repository with release/Contents write access (or set `GH_TOKEN` in the environment). Do not put tokens on the command line, in release notes, or in Git.
5. Run `make dry-run-release TAG=vX.Y.Z NOTES_FILE=/path/to/notes.md`. This checks the local and public tags, clean worktree, assets, checksums, and notes without creating anything.
6. Run `make publish-release TAG=vX.Y.Z NOTES_FILE=/path/to/notes.md`. It creates a draft release, uploads the ten binaries and `SHA256SUMS`, reads back the asset list, then publishes and reads back the release. Check the resulting public page. An interrupted draft is **not** automatically deleted; inspect it before retrying.

Publication requires a human-selected tag and notes. `make release` alone never creates a tag, pushes code, or publishes assets.
