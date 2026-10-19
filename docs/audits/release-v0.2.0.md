# Release v0.2.0

Written for: the repo owner and future maintainers. The release notes, build and publish commands
are below; the "Publish log" at the end records what was actually run and when (it is appended after
the tag, so the tagged tree's copy ends at the log's header). **The repository stays private: the
LICENSE and the visibility flip are a separate sign-off and were not done.** Labels: [V] ran and observed in this session, [R] reported by
another audit page, [I] inferred.

`v0.1.0` (a local tag, never pushed) predates every audit fix and ships three defects
(`export-priv > f` writes a 0644 key file; a negative `-ttl` disables expiry; `verify` of a bad
signature exits 1). Do not push it. This release supersedes it
([release-v0.1.0.md](release-v0.1.0.md) is the historical record).

## Version and why

**`v0.2.0`, a minor bump.** The v0 policy: patch for fixes, minor for everything else including
breaking changes, never `v1`. The post-tag behaviour changes (list below) are breaking for
scripts, so a patch (`v0.1.1`) would be wrong. `v0.1.0` was never published (no remote), so
nothing collides with it. The alternative, moving the local `v0.1.0` tag to the new commit, was
rejected: it would rewrite a tag the committed v0.1.0 record describes and would collide with that
record's file name. If you prefer it, nothing else in this page changes except the version string.

The exported Go surface against `v0.1.0` [V, `go doc -all` diff by the L4 audit, reported in
[the A7 pages](gap-audit.md)]: `pkg/keystore` no symbol added, removed or re-typed; `pkg/agent`
one symbol added (`ErrNegativeLifetime`). Contracts changed are listed under Breaking.

## Release notes

Each line names the merge on `main`; the full list is `git log --merges v0.1.0..main`.

### Breaking (with the migration step)

- **A redirected export is refused** when stdout is a regular file that group or others can
  read (`export-priv > key.pem` under umask 022 used to write a 0644 key file). Migration: use
  `-o FILE` (created 0600), `chmod 600` the file first, or pass `-force`. (96d0b98)
- **`verify` exits 3** for a well-formed signature that does not verify; 1 still means the check
  could not be made (unreadable or malformed signature file, bad key file, unreadable input).
  Migration: scripts that tested `$? = 1` for a forged signature must test 3. (2793e3c, 9880179)
- **Passphrase sources:** an explicit `-passfile`/`-new-passfile` outranked by
  `KEYSTORE_PASSPHRASE` or the keychain is announced when unlocking and **refused** when it would
  establish a passphrase (`keygen`, `add`, `import`, `add-secret`, `import-secret`, `passwd`).
  Migration: unset one of the two. An empty `KEYSTORE_PASSPHRASE`/`KEYSTORE_KEYCHAIN` is treated
  as unset. (2e39346)
- **No ring path and no home directory** (cron, a system unit): a ring verb exits 2 instead of
  creating `./default.ks`. `sign -agent` is exempt. Migration: pass `-keystore` or set
  `KEYSTORE_FILE`. (49a29bf)
- **`keystore-agent`:** negative `-ttl`/`-idle` are refused (they used to mean no limit)
  (ffe9c9c); the agent stops cleanly on SIGHUP (exit 0; was death by signal, exit 129) unless it
  inherited SIGHUP ignored, as under `nohup` (58408dc); it stops within about 10 s and exits 1
  if its socket file is removed or replaced (ebf5897); `-h` exits 0 (bc08d87).
- **Library:** `Add`/`AddSecret`/`Import`/`ImportSecret` (and `ChangePassphrase`'s new passphrase)
  refuse an empty passphrase (a2003af); `Import` refuses a key whose public half is not its
  seed's (78e19fa); `Keystore.Signer` and `agent.ResolveSigner` return a nil `Signer` on every
  error (5075321); `agent.Listen` makes a relative path absolute and applies the OS length limit
  to the absolute form, so a short relative name in a deep directory is now refused (446f79b,
  [decisions row 47](../design/decisions.md)); `Serve` rejects negative lifetimes with the new
  `ErrNegativeLifetime`.
- **Ring reading:** a repeated `entries` key rejects the ring (`ErrBadFormat`); no writer emits
  one. (b04b179, decisions row 41)

### Fixes and hardening

- Agent: accept errors (EMFILE retried, others stop cleanly) (a859214); socket-path length
  reported instead of a bind failure (22a2a19); umask change serialised in `Listen` (8b32c90);
  an orphaned agent (socket removed) stops instead of holding the key forever (ebf5897);
  stopping never unlinks a file that replaced the socket (8d45831); frame bodies are read
  incrementally, so stalled peers do not pin 1 MiB each (d4be234); the client shows at most 256
  bytes of an agent's error text (908a08f); log and error lines are control-character safe
  (49b2ec1, 0632c47).
- CLI: nothing operator-supplied reaches the terminal raw (44076e8); the passphrase prompt
  restores the terminal on SIGQUIT/SIGHUP (389c386); `sign` names the key it used on stderr and
  accepts `-expect-fp` (43811fd); `verify` inputs are capped at 64 KiB (db9d151); PEM errors say
  what was found (29e9973); lock files are 0600 whatever the umask (ce8c582); small cleanups
  (af60243).
- Parsing: ring entries are validated as they are decoded, so a hostile ring no longer costs
  gigabytes (dafd3f6); a repeated `entries` key no longer amplifies (b04b179).
- Build and CI: `--release` refuses a dirty tree and builds only from exactly a tag (8a90392,
  93dcbb3); the CI systemd check can fail and the workflow token is read-only (43655ff); CI vets
  the `integration` and `topology` tiers and fuzzes every target (1d06882).

### Additions

- Documentation: the trust model and its limits (what is and is not authenticated), user guide
  and agent protocol corrected, agent operating notes and bounded restart settings in the unit
  and plist (7b66068, 50370f9, addf124, 039ed2f).
- Tests and tooling (no shipped code): golden bytes for every format and wire contract (77f56c7),
  known-answer vectors (0670225), eight fuzz targets (f33cecf), harnesses and seams (963ab93),
  benchmarks (bf89ccc), mutation hardening, 63.1% to 90.9% on the audit's own 417 mutants
  (3f059ac), a live Linux/OpenSSL tier (a35b07a) and a real-topology tier (7dd11c1). The audit
  record is in [docs/audits/](README.md).

### Verification block

Pre-flight on `main` at `446f79b` [V, this session, strict gate]: `gofmt -l .` empty; `go build`,
`go vet` (darwin and `GOOS=linux GOARCH=arm64`) clean; `staticcheck` clean; `deadcode -test`
silent; `go mod tidy -diff` empty; `go test -race -count=1 ./...` green for every package
including the six examples and `TestReference`; `govulncheck ./...` 0 affecting; `testdata/golden.ks`
sha256 unchanged `bf2462491e501a051e81f5a73ea4687eba30567dfdd2f6e12cd81352938d03f6`. Also
`go vet -tags integration,topology ./...` clean [R: merge 1d06882]. The diff-scoped adversarial
re-audit (A1) of the 21 production files changed since the tag found 0 high, 0 medium, 4 low (all
fixed and merged: 8d45831, 446f79b, 93dcbb3, 908a08f) and 9 info [R: audit pass, local
report]; the crypto core (seal, kdf, ids, peercred, entry, keystore) is byte-identical to the tag
[V by the audit's empty diff]. Private-name screen: no tracked file or commit message names a
private org repository, and `go.mod` requires only `golang.org/x/crypto` and `golang.org/x/sys`
[V this session]. Not run: a real systemd or launchd start, macOS cross-uid peer credentials,
amd64 execution, Linux `-race`, the installer, the real keychain. GitHub Actions ran for the
first time on `main` after the repository was created: run 1 failed (`deadcode` on ubuntu also
reports the darwin-only `checkService`; fixed by `393c0ea`), run 2 at `393c0ea` was green for all
four jobs (`ci`, `ci-macos`, `fuzz`, `fuzz-all`) [V: `gh run view`] ([open-items.md](open-items.md)).

## Build (reproducible)

```sh
# in a clean checkout of the tag; build/keystore --release refuses anything else
build/keystore --release
# = GOWORK=off CGO_ENABLED=0 go build -trimpath -buildvcs=true \
#     -ldflags "-s -w -X main.version=v0.2.0 -X main.build=<rev>" ./cmd/keystore ./cmd/keystore-agent
#   for linux/{amd64,arm64} darwin/{amd64,arm64}; toolchain go1.27.2 (pinned in go.mod)
```

Dry run [V, this session]: a scratch clone of `main` at `446f79b` with a throwaway annotated tag
`v0.2.0` (the real repository was not tagged) built all four archives and `SHA256SUMS`;
`keystore version` printed `keystore v0.2.0 (446f79bd26ab)`; the binary's build info showed
`-trimpath=true`, `CGO_ENABLED=0`, `vcs.modified=false` and the two pinned dependencies. The
archive digests of that dry run are **not** the release digests: the revision is stamped into the
binary, so a commit after `446f79b` (including a commit of this page) changes them. Produce the
real digests at the tag; the binaries (not the archives, which embed timestamps) are byte-identical
across two builds of the same commit [R: A7 skeptic, build-dirty review].

## Third-party notices shipped

`THIRD-PARTY-NOTICES` is inside every release archive (and installed to
`/usr/local/share/doc/keystore/`). It reproduces one stanza for the Go standard library,
`golang.org/x/crypto v0.56.0` and `golang.org/x/sys v0.47.0`, all BSD-3-Clause. [V this
session] The reproduced license text hashes identically (sha256 prefix `911f8f5782931320`) to the
`LICENSE` of the Go 1.27.2 tree, `x/crypto@v0.56.0` and `x/sys@v0.47.0`, and the SBOM
(`keystore.spdx`, SPDX 2.3) in the archive lists the same module versions. The SBOM lists the
components; the notice file reproduces the text (BSD clause 2). Attach `THIRD-PARTY-NOTICES` to
the GitHub release as a separate asset as well. No container image is shipped.

## To publish (needs sign-off; none of it was run)

1. Create the GitHub repository (private) and push `main`; let CI run its four jobs (`ci`,
   `ci-macos`, `fuzz`, `fuzz-all`) for the first time and fix what a hosted runner finds. Do not
   push the local `v0.1.0` tag (`git push origin main`, not `--tags`).
2. Tag the release commit: `git -c user.email=noreply@anthropic.com tag -a v0.2.0 <sha> -m "keystore v0.2.0: …"`
   then `git push origin v0.2.0`. (The old local `v0.1.0` stays unpushed; delete it with
   `git tag -d v0.1.0` if you want it gone.)
3. From the tag: `build/keystore --release`; `gh release create v0.2.0 --latest --title "keystore v0.2.0"
   --notes-file <this page's Release notes section> build/install/release/*`; also attach
   `THIRD-PARTY-NOTICES`.
4. Verify from a clean environment: `GOFLAGS=-mod=mod go install github.com/netstar-labs/keystore/cmd/keystore@v0.2.0`
   in a throwaway directory, then `keystore version` and a signature round trip.
5. Repository metadata (first release): `gh repo edit netstar-labs/keystore --description "An
   encrypted single-file keyring for Ed25519 signing keys and secrets, with a CLI, a Go library
   and a signing agent."`, topics `go golang cryptography security cli library ed25519 keyring`,
   homepage `https://pkg.go.dev/github.com/netstar-labs/keystore`; confirm the default branch is
   `main`; branch protection `require-checks` (`ci` green, no force-push, no bypass), Tier-B per
   the house rules unless you classify it Tier-A. Record the final description and topics here.
6. Going public (separate sign-off): add `LICENSE` (Apache-2.0, copyright "NetSTAR Global, Inc.",
   decisions row 2), confirm GitHub detects it, re-run the private-name screen over tracked files
   and over `gh issue list`/`gh pr list`/`git log --all --format=%B`, then flip visibility.

## Rollback

Delete the GitHub release and the tag (`gh release delete v0.2.0 && git push --delete origin
v0.2.0`); if the module proxy already fetched it, add a `retract v0.2.0` line to `go.mod` in a
`v0.2.1` release. Nothing published means nothing to roll back today.

## Publish log

Run on 2026-10-19 by the assistant with the owner's go-ahead for steps 1 to 5 of "To publish" (step 6, the
LICENSE and the visibility flip, was not authorised and was not done). Labels as above; every line is [V]
unless marked.

1. **Repository:** `gh repo create netstar-labs/keystore --private`, remote `origin`, `git push -u origin main`
   (branches only; no tags). Visibility `PRIVATE`, default branch `main`. The local `v0.1.0` tag was not pushed
   (`git ls-remote --tags origin` listed only `v0.2.0` afterwards).
2. **CI:** the first run (at `60f42b0`) failed in the `ci` job: `deadcode` on an ubuntu build also reports the
   darwin-only `checkService` as unreachable, which local darwin runs never showed. Fixed by merge `393c0ea` (an
   exact allowance in the workflow; a planted dead function still fails). Runs at `393c0ea` and at `87189fa`
   (the release commit) were green for all four jobs (`ci`, `ci-macos`, `fuzz`, `fuzz-all`).
3. **Tag:** annotated `v0.2.0` on `87189fa` (the CI-green commit), `git push origin v0.2.0`.
4. **Build:** `build/keystore --release` from the tagged, clean tree built four archives; `shasum -a 256 -c
   SHA256SUMS` passed; the binaries print `keystore v0.2.0 (87189fa3ed49)`.
5. **GitHub release:** `gh release create v0.2.0 --latest` (private repository, so private release) with the
   four archives, `SHA256SUMS` and `THIRD-PARTY-NOTICES`. A download of the darwin-arm64 archive and
   `SHA256SUMS` from the release verified and the extracted binary ran.
6. **Module install from a clean environment:** `GOPATH=<empty temp dir> GOPRIVATE=github.com/netstar-labs
   GOPROXY=direct go install github.com/netstar-labs/keystore/cmd/keystore@v0.2.0` (and `keystore-agent`)
   succeeded. One finding: a binary built this way prints `keystore dev (none)`, because the version is
   stamped only by the release script's `-ldflags`; see [open-items.md](open-items.md), O9.
7. **Repository metadata:** description (set at creation), homepage `https://pkg.go.dev/github.com/netstar-labs/keystore`
   and topics `cli cryptography ed25519 go golang keyring library security` set. **Branch protection was not
   applied:** GitHub returns HTTP 403 for rulesets on a private repository on this plan ("Upgrade to GitHub Pro
   or make this repository public"); the house recipe also requires a `pr-issue-link` check this repository does
   not have. Apply it when the repository goes public or the plan changes.
8. **Not done, by design:** the `LICENSE` file (Apache-2.0, "NetSTAR Global, Inc.", decisions row 2) and the
   visibility flip; the private-name screen must be re-run first (tracked files and commit messages were clean at
   `87189fa`; issues and pull requests do not exist yet).
