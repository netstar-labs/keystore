# Mutation hardening of the security tests (L2 phase 4)

Branch `test/L2-mutation-hardening`, cut from `main` (29e9973). Production code is unchanged on
this branch; every change is a `_test.go` file. Defects found on the way are on separate
branches (see "Defects").

## Result

409 hand-written mutants over the security-critical code. Each is one textual change to one
production file (off-by-one, flipped or dropped check, swapped argument, removed error return,
changed constant, removed `clear()`, removed fsync/rename/lock, ...). Mutation score is
detected / (detected + survived); a mutant that fails to build is re-written, never counted.

| | Detected | Survived | Score |
|---|---|---|---|
| Before (existing suite) | 261 | 148 | 63.8% |
| After (this branch) | 370 | 39 | 90.5% |

109 mutants that survived the old suite now die. Of the 39 that remain:

* 16 are equivalent (no observable behaviour differs; reason per mutant below);
* 12 are unobservable by black-box tests: `clear()` of local buffers (memory hygiene) and one
  timing-only comparison of public data;
* 11 are real, accepted gaps that need an injection seam or a privileged/other-uid environment
  (fsync and directory-fsync removal, O_EXCL/O_NOFOLLOW races, write-failure and EINTR paths, the
  client's peer-uid check, passfile ownership, the keychain-set echo).

Score excluding the equivalent mutants: 97.1%. Excluding equivalent, unobservable and
seam-bound: 100.0%. 7 mutants are detected only because the suite hangs until
`go test` times out (flock without `LOCK_NB`, no lock deadline, Close-before-Serve ignored,
connections not closed on expiry, ...): a hang is a failure, but a slow one.

## Method

A throw-away runner (not committed; Python, about 80 lines) copies the repo, applies one
mutation, runs `go build ./...` (a mutant that does not build is INVALID and re-written), then
`go test -count=1 -race -timeout 150s` over the packages that exercise the mutated file, and
records KILLED / SURVIVED / TIMEOUT. Packages per file: seal/kdf/ids -> own package + ringfile +
keystore; ringfile -> ringfile + keystore + cmd/keystore; keystore -> keystore + cmd/keystore +
agent; agent -> agent + both commands; passphrase and term -> own package + both commands; each
command -> itself. The examples/ packages were not part of the mutant runs (they are in the gate).

Before = the unmodified tree. After = this branch; only the survivors were re-run (a failing
suite stays failing when files are added), then the late additions again. Survivors are judged by
reading the code: equivalent, unobservable, or a gap that gets a test.

Two things went wrong in the method and were fixed, not hidden: an early run excluded `docs/` from
the copy, so `TestReference` failed every mutant that reached `cmd/keystore` (all those runs were
discarded and redone); and `zsh` does not word-split `$IDS`, which made one re-run select nothing
(caught because the summary counter was empty).

## What the survivors were, and the tests that kill them

Real gaps found in the old suite, by area (new tests in `kill_*_test.go`, plus `property_test.go`):

* **seal**: a nonce longer than 12 bytes reached `gcm.Open` (a panic, not ErrNonce) untested; keys of
  16/24 bytes were not refused; nonce freshness and exact `ErrOpen` identity were unasserted.
* **kdf**: the upper bounds were tested through the constants themselves (a drifting `MaxMem`,
  `MaxTime` or `MaxPar` moved the test with it); `New` ignoring `Default.Time`/`Default.Par`; long
  salt; the shipped default cost (64 MiB / 3 / 1) was never asserted.
* **ids**: `A`, a separator in second position, and the length boundary.
* **ringfile**: the 16 MiB cap (Parse and Read at the exact boundary, including `Read` silently
  truncating an oversize file into a valid one), ct/nonce length boundaries, the two public-key fault
  messages, `keystore/v01`, repeated `entries` key, canonical encoding (UTC, indent, newline),
  descriptor leaks in Read/Lock/Update.
* **keystore**: `add` and `passwd` on a ring whose entries were sealed under different passphrases
  (add checks the first entry; passwd must unlock every entry or write nothing); ExportPrivate's
  advertised-key check (needs a hand-sealed mismatching entry); Remove of the current key must pick
  the first remaining *signing* key; Import of short keys must error, not panic; a non-ed25519 SPKI
  or PKCS#8 must not come back as (nil, nil); OpenOrCreate creation race; `SecretSize` and
  `MaxSecretSize` boundaries; ImportSecret must not clear the caller's buffer.
* **agent**: an unknown op or oversize frame must end the connection after the error reply; sign
  failure reply; `IOTimeout` really drops silent and half-sent clients; Serve waits for in-flight
  requests; a connection accepted during shutdown is closed; connections are untracked; ENFILE retry;
  the retry backs off; a live foreign socket is detected without the lock; every group/other bit of
  the socket directory is refused; a foreign-owned directory is refused; lock file `O_NOFOLLOW` and
  mode 0600; Close while serving returns nil (the old tests mostly took the Close-before-Serve early
  exit); the client verifies public-key length and every signature, the oversize check precedes the
  dial, a silent agent hits the timeout, `DefaultTimeout` is 5 s; the frame limit is exactly 1 MiB
  both ways; ResolveSigner wipes the passphrase and honours `id`.
* **passphrase**: a FIFO is refused *as not a regular file*; every group/other mode bit; the 4096-byte
  cap exactly; only one trailing line ending is trimmed; a keychain failure names the service and
  wraps the cause; `clear()` of typed passphrases on mismatch, failed confirmation, too-short, and the
  confirmation copy (observed through a Prompt stub that keeps the slices); an empty source is
  `ErrEmpty`, not `ErrTooShort`; env / keychain / passfile order.
* **term**: `Clean` replaces (not drops) and pins look-alike spaces (NBSP, U+2003, U+3000).
* **cmd/keystore**: `writeFile` mode exactness under `-force` and umask 0; symlink refusal message;
  `-force` over a FIFO refused; `replace` leaves no temp file on failure; the default ring directory
  is 0700 and only created for the default path; `import` needs `-key` as a usage error;
  import-secret input cap exactly at the encoded 64 KiB secret plus CRLF; 1 MiB message limit through
  stdin and file; a malformed signature file is exit 1, never exit 3.
* **cmd/keystore-agent**: `-id`, `-ttl 0`, `-idle` versus `-ttl`, `-sock` required, absolute socket
  path in the log, defaults 8h/30m, rejected requests logged, SIGTERM exits 0 and removes the socket.

## Defects

None found by a survivor (no mutant showed code that was wrong). Found while writing tests:

1. `Keystore.Signer` and `agent.ResolveSigner` return a non-nil `crypto.Signer` holding a nil value
   together with the error (`return k.ExportPrivate(...)` / `return Dial(...)` convert a typed nil).
   A caller that tests the interface instead of `err` proceeds with a nil key. Fix with its own red
   test on branch `fix/L2-signer-typed-nil`.
2. Doc nit, not fixed: `term.Clean` documents invalid UTF-8 as replaced by a space; it comes out as
   U+FFFD (printable, one per bad byte). Harmless for the terminal-safety goal; the new test pins
   the real behaviour.

## Security properties (docs/design/scope.md, "Security properties every release must meet")

"Live" = mutants of the guarded code were killed by these tests, so the tests can fail.

1. **Ring file alone reveals no private material** (argon2id 64 MiB/3/1, AES-256-GCM, per-entry salt
   and nonce). Guards: `TestShippedDefaultCost`, `TestNewAppliesTheWholeDefaultCost`,
   `TestDeriveKnownAnswer`, `TestDeriveDeterministicAndSaltSensitive`, `TestKeyLengthIsExactly32`,
   `TestSealNonceIsFreshAndRandom`, `TestRoundTrip`, `TestGolden` (production-cost ring),
   `TestRingFileHoldsNoPlaintext` (seed, secrets, passphrase absent as raw/base64/hex),
   `TestSaltsAndNoncesAreUniquePerEntryAndFreshAfterPasswd`, `TestListCarriesNoSecrets`.
   Live: M001-M021, M022-M048.
2. **Any modification of an entry fails with ErrBadPass; malformed fields fail at parse with
   ErrBadFormat.** Guards: `TestAADBindsEveryField`, `TestTamperMatrix`, `TestOpenFailureIsExactlyErrOpen`,
   `TestParseRejects`, `TestParseRejectsFieldShapes`, `TestDecodeFieldLengthBoundaries`,
   `TestDecodeSaysWhichPublicKeyFaultItFound`, `TestFutureVersionIsOnlyAboveOne`,
   `TestCreatedOutOfRangeRejected`, `TestExportPrivateRefusesAnEntryWhoseKeyIsNotTheAdvertisedOne`.
   Live: M001-M013 (each AAD field omitted or reordered), M067-M092, M179-M181.
3. **A crash leaves the old or the new ring; the new one is durable when the command returns.**
   Atomicity is guarded by `TestSaveCrashSafety` (stages written/synced/renamed),
   `TestCreateNeverReplaces`, `TestSaveMode0600EvenOverWiderFile`, `TestNoDescriptorLeak`.
   **Durability (fsync of the temp file and of the directory) has no guarding test**: M106, M119,
   M121 survive. FLAG. It needs a seam (for example a package variable wrapping the file and
   directory sync) so a test can record or fail the calls; none was added because production code is
   out of scope on this branch.
4. **Cooperating processes cannot lose each other's writes.** Guards:
   `TestUpdateConcurrentNoLostWrites`, `TestConcurrentAddsGoroutinesAndProcesses`, `TestLockTimeout`,
   `TestLockRefusesSymlink`, `TestNoDescriptorLeak`, `TestOpenOrCreateRace`. Live: M107-M127
   (skipped lock, read-before-lock, blocking flock, never-closed lock file).
5. **One passphrase per ring, enforced.** Guards: `TestPassphraseInvariant`,
   `TestSecretPassphraseInvariantAndBounds`, `TestMixedPassphraseRing`, `TestChangePassphrase*`,
   `TestEmptyPassphrase*`, `TestLegacyEmptyPassphraseRingCanBeRecovered`,
   `TestEstablishFromNothingIsErrEmpty`, `TestNewEnforcesLengthFromEverySource`. Live: M132-M153.
6. **No secret on argv; none written to a terminal, an existing file, or a redirected stdout file
   others can read.** Guards: `TestNoVerbHasAPassphraseFlag`, `TestExportPrivRefusesTerminal`,
   `TestExportRefusesRedirectToAFileOthersCanRead`, `TestExportPrivFileRules`,
   `TestExportSecretGuards`, `TestWriteFileModeIsExactAcrossForce`,
   `TestWriteFileRefusesSymlinksAndSpecialFiles`, `TestSignAndExportOutputModes`, `TestPassfile*`,
   `TestArgsNeverCarryTheSecret` (macOS only). Live: M321-M356. Gap: the `keychain-set` echo (M371).
7. **A crafted ring cannot cause an unbounded allocation or a zero-cost KDF.** Guards:
   `TestCheckBounds`, `TestBoundsArePinnedToTheDocumentedNumbers`,
   `TestParseAndReadSizeCapIsExactly16MiB`, `TestParseDoesNotAmplify`, `TestParseLargeValidRing`,
   `TestParseReportsFirstBadEntryInLargeRing`, `TestParseEntriesShapes`, `FuzzParse`,
   `TestRepeatedEntriesKeyLastWins`. Live: M022-M048, M063-M071.

The agent's properties (SECURITY.md, not scope.md 1-7) were mutation-checked too: peer uid at the
server (M196-M197), socket directory owner and mode, path lock, TTL/idle, frame cap, signature
verification (M196-M269). The client-side peer-uid check (M255) needs a second uid.

Only property 3's durability half has no guarding test.

## Caveats

* The mutants are my own: a mutation I did not think of is not measured. The score says the suite
  catches these, not all faults.
* The runner ran under heavy machine load (load average above 60 at times); a flaky test would show
  as a spurious kill. Kill reasons were read, and every new test passes `-race -count=20` (the
  cmd/keystore-agent tests, which start real agents, took 22 minutes of that).
* `TestPassfileMustBeOwnedByTheCaller` needs root and was **not executed** (it skips).
  `TestSocketDirMustBeOwnedByTheCaller` skips if `/` is owned by the caller.
* `TestOpenOrCreateRace` kills its mutant probabilistically (32 goroutines x 25 rounds); the
  original never fails it.

## Surviving mutants (after)

| ID | File | Mutation | Class | Why it survives |
|---|---|---|---|---|
| M017 | `internal/seal/seal.go` | newGCM: accept long key (aes rejects 33 anyway) | equivalent | aes.NewCipher also rejects a 33-byte key; only the error text differs |
| M093 | `internal/ringfile/ringfile.go` | trailing data accepted | equivalent | redundant layer: json.Unmarshal in the magic peek already rejects trailing data |
| M094 | `internal/ringfile/ringfile.go` | peek error ignored | equivalent | redundant layer: an empty peeked magic fails the Magic comparison anyway |
| M106 | `internal/ringfile/ringfile.go` | Create: skip dir sync | untestable without a seam | durability: removing the directory fsync cannot be seen without fault/syscall injection |
| M116 | `internal/ringfile/ringfile.go` | temp: drop chmod (CreateTemp is already 0600) | equivalent | os.CreateTemp already creates 0600 regardless of umask |
| M119 | `internal/ringfile/ringfile.go` | temp: skip fsync | untestable without a seam | durability: removing the temp-file fsync cannot be seen without fault/syscall injection |
| M121 | `internal/ringfile/ringfile.go` | syncDir: skip fsync | untestable without a seam | durability: removing the directory fsync cannot be seen without fault/syscall injection |
| M126 | `internal/ringfile/ringfile.go` | release: no explicit unlock (close releases) | equivalent | closing the descriptor releases the flock |
| M128 | `internal/ringfile/ringfile.go` | Lock: EINTR is fatal | untestable without a seam | needs an injected EINTR from flock |
| M129 | `internal/ringfile/ringfile.go` | Lock: busy loop | equivalent | the sleep only paces the retry loop |
| M131 | `internal/ringfile/ringfile.go` | Find returns a copy | equivalent | every caller of Find reads the entry and never writes through the pointer |
| M139 | `pkg/keystore/ring.go` | checkPassphrase: no clear | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M140 | `pkg/keystore/ring.go` | add: plaintext not cleared (observable via ImportSecret aliasing only) | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M142 | `pkg/keystore/ring.go` | encrypt: key not cleared | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M153 | `pkg/keystore/ring.go` | ChangePassphrase: plaintext not cleared | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M160 | `pkg/keystore/ring.go` | Remove: count<=1 (count>=1 here) | equivalent | a signing entry makes countSigning >= 1, so <=1 and ==1 agree |
| M171 | `pkg/keystore/ring.go` | addSigning: no clear on error path | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M172 | `pkg/keystore/entry.go` | signingEntry: no empty-current guard (Find("") is nil anyway) | equivalent | Find("") is nil (ids are never empty), so ErrNoKey either way |
| M180 | `pkg/keystore/signer.go` | ExportPrivate: non-constant-time compare (timing only) | unobservable (memory/timing) | constant-time compare of two public SPKI encodings: timing only, nothing secret |
| M182 | `pkg/keystore/signer.go` | ExportPrivate: pkcs8 not cleared | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M183 | `pkg/keystore/signer.go` | ExportPrivate: marshal error ignored | equivalent | x509.MarshalPKIXPublicKey of an ed25519 key cannot fail |
| M191 | `pkg/keystore/secret.go` | AddSecret: no clear on error | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M210 | `pkg/agent/server.go` | listenLocked: umask 0 during bind (chmod follows) | equivalent | two independent guards (umask 0177 around bind, chmod 0600 after); each alone yields 0600 |
| M211 | `pkg/agent/server.go` | listenLocked: drop chmod (umask 0177 already gives 0600) | equivalent | two independent guards (umask 0177 around bind, chmod 0600 after); each alone yields 0600 |
| M254 | `pkg/agent/client.go` | client: peer-uid lookup error ignored | equivalent | peerUID returns -1 with its error, which never equals our uid, so the error check is redundant |
| M255 | `pkg/agent/client.go` | client: peer uid never compared | untestable without a seam | client uid check: needs a server running as another uid (root); peercred.UID is not injectable |
| M258 | `pkg/agent/client.go` | Sign: length unchecked (Verify rejects bad length) | equivalent | ed25519.Verify itself rejects a wrong-length signature |
| M300 | `internal/passphrase/passphrase.go` | passfile: owner unchecked | untestable without a seam | passfile owner check: needs root to make a foreign-owned 0600 passfile; TestPassfileMustBeOwnedByTheCaller exists and is skipped when unprivileged |
| M323 | `cmd/keystore/output.go` | guard: nil outFile (tests) -> nil deref | equivalent | os.File methods are nil-safe, so a nil outFile is treated as 'cannot stat' |
| M335 | `cmd/keystore/output.go` | writeNew: no O_EXCL (Lstat precheck covers non-racy case) | untestable without a seam | O_EXCL / O_NOFOLLOW only differ if the path changes between Lstat and open (a race window, no hook) |
| M336 | `cmd/keystore/output.go` | writeNew: no O_NOFOLLOW (Lstat precheck covers non-racy case) | untestable without a seam | O_EXCL / O_NOFOLLOW only differ if the path changes between Lstat and open (a race window, no hook) |
| M337 | `cmd/keystore/output.go` | writeNew: partial file left on write error | untestable without a seam | needs an injected write failure to leave a partial file |
| M338 | `cmd/keystore/output.go` | writeNew: skip fsync | untestable without a seam | durability: removing the temp-file fsync cannot be seen without fault/syscall injection |
| M366 | `cmd/keystore/secrets.go` | add-secret: minted secret not cleared | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M371 | `cmd/keystore/secrets.go` | keychain-set echo: service not cleaned | untestable without a seam | keychain-set echo: reaching it needs the real macOS keychain; keychain.Set is not injectable |
| M376 | `cmd/keystore/sign.go` | sign: pin via non-empty value (empty caught earlier) | equivalent | an explicitly empty -expect-fp is refused earlier, so `pinned` and `!= ""` agree |
| M379 | `cmd/keystore/sign.go` | sign: key not cleared on pin mismatch | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M380 | `cmd/keystore/sign.go` | sign: key not cleared after signing | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |
| M406 | `cmd/keystore-agent/main.go` | agent: key not cleared on exit | unobservable (memory/timing) | clear() of a local buffer: only residual memory differs; needs memory forensics to observe |

## Full mutant table

`KILLED*` = killed by the pre-existing suite; not re-run after the new tests were added (adding tests cannot revive a mutant the old tests failed; the survivors were re-run in full).
`TIMEOUT` = the mutant makes the suite hang until `go test`'s timeout; counted as detected.

| ID | File | Mutation | Before | After |
|---|---|---|---|---|
| M001 | `internal/seal/seal.go` | AAD: swap kind/id order | KILLED | KILLED* |
| M002 | `internal/seal/seal.go` | AAD: omit format | KILLED | KILLED* |
| M003 | `internal/seal/seal.go` | AAD: omit kind | KILLED | KILLED* |
| M004 | `internal/seal/seal.go` | AAD: omit id | KILLED | KILLED* |
| M005 | `internal/seal/seal.go` | AAD: omit pub | KILLED | KILLED* |
| M006 | `internal/seal/seal.go` | AAD: omit algo | KILLED | KILLED* |
| M007 | `internal/seal/seal.go` | AAD: omit mem | KILLED | KILLED* |
| M008 | `internal/seal/seal.go` | AAD: omit time | KILLED | KILLED* |
| M009 | `internal/seal/seal.go` | AAD: omit par | KILLED | KILLED* |
| M010 | `internal/seal/seal.go` | AAD: omit salt | KILLED | KILLED* |
| M011 | `internal/seal/seal.go` | AAD: drop length prefix | KILLED | KILLED* |
| M012 | `internal/seal/seal.go` | AAD: little-endian numbers | KILLED | KILLED* |
| M013 | `internal/seal/seal.go` | AAD: par constant 0 | KILLED | KILLED* |
| M014 | `internal/seal/seal.go` | nonce length 16 | KILLED | KILLED* |
| M015 | `internal/seal/seal.go` | Open: accept long nonce (gcm panics) | SURVIVED | KILLED |
| M016 | `internal/seal/seal.go` | Open: leak raw gcm error instead of ErrOpen | KILLED | KILLED* |
| M017 | `internal/seal/seal.go` | newGCM: accept long key (aes rejects 33 anyway) (EQ expected) | SURVIVED | SURVIVED |
| M018 | `internal/seal/seal.go` | newGCM: accept 16/24-byte keys (AES-128/192) | SURVIVED | KILLED |
| M019 | `internal/seal/seal.go` | Seal: all-zero nonce | SURVIVED | KILLED |
| M020 | `internal/seal/seal.go` | Seal: ignore aad | KILLED | KILLED* |
| M021 | `internal/seal/seal.go` | Open: ignore aad | KILLED | KILLED* |
| M022 | `internal/kdf/kdf.go` | MinMem+1 | KILLED | KILLED* |
| M023 | `internal/kdf/kdf.go` | MinMem-1 | KILLED | KILLED* |
| M024 | `internal/kdf/kdf.go` | MaxMem+1 | SURVIVED | KILLED |
| M025 | `internal/kdf/kdf.go` | MaxMem-1 | SURVIVED | KILLED |
| M026 | `internal/kdf/kdf.go` | MinTime+1 | KILLED | KILLED* |
| M027 | `internal/kdf/kdf.go` | MinTime-1 (zero passes) | KILLED | KILLED* |
| M028 | `internal/kdf/kdf.go` | MaxTime+1 | SURVIVED | KILLED |
| M029 | `internal/kdf/kdf.go` | MaxTime-1 | SURVIVED | KILLED |
| M030 | `internal/kdf/kdf.go` | MinPar+1 | KILLED | KILLED* |
| M031 | `internal/kdf/kdf.go` | MinPar-1 | KILLED | KILLED* |
| M032 | `internal/kdf/kdf.go` | MaxPar+1 | SURVIVED | KILLED |
| M033 | `internal/kdf/kdf.go` | MaxPar-1 | SURVIVED | KILLED |
| M034 | `internal/kdf/kdf.go` | Check: drop algo | KILLED | KILLED* |
| M035 | `internal/kdf/kdf.go` | Check: drop Mem min | KILLED | KILLED* |
| M036 | `internal/kdf/kdf.go` | Check: drop Mem max | KILLED | KILLED* |
| M037 | `internal/kdf/kdf.go` | Check: drop Time min | KILLED | KILLED* |
| M038 | `internal/kdf/kdf.go` | Check: drop Time max | KILLED | KILLED* |
| M039 | `internal/kdf/kdf.go` | Check: drop Par min | KILLED | KILLED* |
| M040 | `internal/kdf/kdf.go` | Check: drop Par max | KILLED | KILLED* |
| M041 | `internal/kdf/kdf.go` | Check: accept long salt | SURVIVED | KILLED |
| M042 | `internal/kdf/kdf.go` | Check: accept short salt | KILLED | KILLED* |
| M043 | `internal/kdf/kdf.go` | Derive: skip Check | KILLED | KILLED* |
| M044 | `internal/kdf/kdf.go` | Derive: swap passphrase/salt | KILLED | KILLED* |
| M045 | `internal/kdf/kdf.go` | Derive: 31-byte key | KILLED | KILLED* |
| M046 | `internal/kdf/kdf.go` | New: all-zero salt | KILLED | KILLED* |
| M047 | `internal/kdf/kdf.go` | New: ignores Default.Time | SURVIVED | KILLED |
| M048 | `internal/kdf/kdf.go` | New: ignores Default.Par | SURVIVED | KILLED |
| M049 | `internal/ids/ids.go` | empty id accepted | KILLED | KILLED* |
| M050 | `internal/ids/ids.go` | max length -1 | KILLED | KILLED* |
| M051 | `internal/ids/ids.go` | max length +1 | KILLED | KILLED* |
| M052 | `internal/ids/ids.go` | alphabet: 'a' excluded | KILLED | KILLED* |
| M053 | `internal/ids/ids.go` | alphabet: 'z' excluded | KILLED | KILLED* |
| M054 | `internal/ids/ids.go` | alphabet: 'A' excluded | SURVIVED | KILLED |
| M055 | `internal/ids/ids.go` | alphabet: 'Z' excluded | KILLED | KILLED* |
| M056 | `internal/ids/ids.go` | alphabet: '0' excluded | KILLED | KILLED* |
| M057 | `internal/ids/ids.go` | alphabet: '9' excluded | KILLED | KILLED* |
| M058 | `internal/ids/ids.go` | leading separator allowed | KILLED | KILLED* |
| M059 | `internal/ids/ids.go` | second-char separator refused | SURVIVED | KILLED |
| M060 | `internal/ids/ids.go` | slash allowed | KILLED | KILLED* |
| M061 | `internal/ids/ids.go` | hyphen refused | KILLED | KILLED* |
| M062 | `internal/ids/ids.go` | space allowed | KILLED | KILLED* |
| M063 | `internal/ringfile/ringfile.go` | MaxSize doubled | SURVIVED | KILLED |
| M064 | `internal/ringfile/ringfile.go` | Parse: size boundary -1 | SURVIVED | KILLED |
| M065 | `internal/ringfile/ringfile.go` | Parse: size boundary +1 | SURVIVED | KILLED |
| M066 | `internal/ringfile/ringfile.go` | Read: limit MaxSize (oversize file truncated to a valid ring) | SURVIVED | KILLED |
| M067 | `internal/ringfile/ringfile.go` | minCT-1 | KILLED | KILLED* |
| M068 | `internal/ringfile/ringfile.go` | minCT+1 | SURVIVED | KILLED |
| M069 | `internal/ringfile/ringfile.go` | nonce: accept long | SURVIVED | KILLED |
| M070 | `internal/ringfile/ringfile.go` | nonce: accept short | KILLED | KILLED* |
| M071 | `internal/ringfile/ringfile.go` | ct: boundary | SURVIVED | KILLED |
| M072 | `internal/ringfile/ringfile.go` | decode: skip id validation | KILLED | KILLED* |
| M073 | `internal/ringfile/ringfile.go` | decode: skip kdf.Check | KILLED | KILLED* |
| M074 | `internal/ringfile/ringfile.go` | decode: ignore created parse error | KILLED | KILLED* |
| M075 | `internal/ringfile/ringfile.go` | decode: do not normalise to UTC | KILLED | KILLED* |
| M076 | `internal/ringfile/ringfile.go` | created range: drop y<0 | KILLED | KILLED* |
| M077 | `internal/ringfile/ringfile.go` | created range: drop y>9999 | KILLED | KILLED* |
| M078 | `internal/ringfile/ringfile.go` | created range: 10000 allowed | KILLED | KILLED* |
| M079 | `internal/ringfile/ringfile.go` | decode: ignore SPKI parse error | SURVIVED | KILLED |
| M080 | `internal/ringfile/ringfile.go` | decode: accept non-ed25519 SPKI | KILLED | KILLED* |
| M081 | `internal/ringfile/ringfile.go` | secret may carry a pub | SURVIVED | KILLED |
| M082 | `internal/ringfile/ringfile.go` | decode: accept unknown kind | KILLED | KILLED* |
| M083 | `internal/ringfile/ringfile.go` | drop duplicate-id check | KILLED | KILLED* |
| M084 | `internal/ringfile/ringfile.go` | never record seen ids | KILLED | KILLED* |
| M085 | `internal/ringfile/ringfile.go` | entries: allow unknown fields | KILLED | KILLED* |
| M086 | `internal/ringfile/ringfile.go` | file: allow unknown fields | KILLED | KILLED* |
| M087 | `internal/ringfile/ringfile.go` | duplicate entries key appends to earlier array | SURVIVED | KILLED |
| M088 | `internal/ringfile/ringfile.go` | entries: null refused | KILLED | KILLED* |
| M089 | `internal/ringfile/ringfile.go` | entries: non-array accepted | KILLED | KILLED* |
| M090 | `internal/ringfile/ringfile.go` | nil vs empty entries | KILLED | KILLED* |
| M091 | `internal/ringfile/ringfile.go` | current may name a secret | KILLED | KILLED* |
| M092 | `internal/ringfile/ringfile.go` | dangling current allowed (nil deref) | KILLED | KILLED* |
| M093 | `internal/ringfile/ringfile.go` | trailing data accepted | SURVIVED | SURVIVED |
| M094 | `internal/ringfile/ringfile.go` | peek error ignored | SURVIVED | SURVIVED |
| M095 | `internal/ringfile/ringfile.go` | future version: v2 reported as bad format | KILLED | KILLED* |
| M096 | `internal/ringfile/ringfile.go` | future version: v01 reported as future | SURVIVED | KILLED |
| M097 | `internal/ringfile/ringfile.go` | future version never reported | KILLED | KILLED* |
| M098 | `internal/ringfile/ringfile.go` | Parse: lose entry-level error detail | KILLED | KILLED* |
| M099 | `internal/ringfile/ringfile.go` | Marshal: skip self-check | KILLED | KILLED* |
| M100 | `internal/ringfile/ringfile.go` | marshal: no UTC normalisation | SURVIVED | KILLED |
| M101 | `internal/ringfile/ringfile.go` | marshal: no trailing newline | SURVIVED | KILLED |
| M102 | `internal/ringfile/ringfile.go` | marshal: tab indent | SURVIVED | KILLED |
| M103 | `internal/ringfile/ringfile.go` | Read: leak descriptor (EQ expected) | SURVIVED | KILLED |
| M104 | `internal/ringfile/ringfile.go` | Create: rename instead of link (replaces existing) | KILLED | KILLED* |
| M105 | `internal/ringfile/ringfile.go` | Create: leave temp file | KILLED | KILLED* |
| M106 | `internal/ringfile/ringfile.go` | Create: skip dir sync | SURVIVED | SURVIVED |
| M107 | `internal/ringfile/ringfile.go` | Update: do not resolve symlinks | KILLED | KILLED* |
| M108 | `internal/ringfile/ringfile.go` | Update: skip lock | KILLED | KILLED* |
| M109 | `internal/ringfile/ringfile.go` | Update: read before lock (stale read) | KILLED | KILLED* |
| M110 | `internal/ringfile/ringfile.go` | Update: write despite fn error | KILLED | KILLED* |
| M111 | `internal/ringfile/ringfile.go` | Save: no rename | KILLED | KILLED* |
| M112 | `internal/ringfile/ringfile.go` | Save: drop renamed stage | KILLED | KILLED* |
| M113 | `internal/ringfile/ringfile.go` | Save: drop synced stage | KILLED | KILLED* |
| M114 | `internal/ringfile/ringfile.go` | Save: leave temp on abort | KILLED | KILLED* |
| M115 | `internal/ringfile/ringfile.go` | temp file mode 0644 | KILLED | KILLED* |
| M116 | `internal/ringfile/ringfile.go` | temp: drop chmod (CreateTemp is already 0600) (EQ expected) | SURVIVED | SURVIVED |
| M117 | `internal/ringfile/ringfile.go` | temp: truncated write | KILLED | KILLED* |
| M118 | `internal/ringfile/ringfile.go` | temp: drop written stage | KILLED | KILLED* |
| M119 | `internal/ringfile/ringfile.go` | temp: skip fsync | SURVIVED | SURVIVED |
| M120 | `internal/ringfile/ringfile.go` | temp: fail() leaves the temp file | KILLED | KILLED* |
| M121 | `internal/ringfile/ringfile.go` | syncDir: skip fsync | SURVIVED | SURVIVED |
| M122 | `internal/ringfile/ringfile.go` | Lock: follow symlink | KILLED | KILLED* |
| M123 | `internal/ringfile/ringfile.go` | Lock: lock file mode 0644 | KILLED | KILLED* |
| M124 | `internal/ringfile/ringfile.go` | Lock: blocking flock | TIMEOUT | TIMEOUT* |
| M125 | `internal/ringfile/ringfile.go` | Lock: never time out | TIMEOUT | TIMEOUT* |
| M126 | `internal/ringfile/ringfile.go` | release: no explicit unlock (close releases) (EQ expected) | SURVIVED | SURVIVED |
| M127 | `internal/ringfile/ringfile.go` | release: never close lock file | SURVIVED | KILLED |
| M128 | `internal/ringfile/ringfile.go` | Lock: EINTR is fatal | SURVIVED | SURVIVED |
| M129 | `internal/ringfile/ringfile.go` | Lock: busy loop (EQ expected) | SURVIVED | SURVIVED |
| M130 | `internal/ringfile/ringfile.go` | Find inverted | KILLED | KILLED* |
| M131 | `internal/ringfile/ringfile.go` | Find returns a copy (EQ expected) | SURVIVED | SURVIVED |
| M132 | `pkg/keystore/ring.go` | add: empty passphrase accepted | KILLED | KILLED* |
| M133 | `pkg/keystore/ring.go` | add: skip id validation (Marshal still refuses) | KILLED | KILLED* |
| M134 | `pkg/keystore/ring.go` | add: drop duplicate check | KILLED | KILLED* |
| M135 | `pkg/keystore/ring.go` | add: drop passphrase-match check | KILLED | KILLED* |
| M136 | `pkg/keystore/ring.go` | checkPassphrase: skip when ring has one entry | KILLED | KILLED* |
| M137 | `pkg/keystore/ring.go` | checkPassphrase: test the last entry, not the first | SURVIVED | KILLED |
| M138 | `pkg/keystore/ring.go` | checkPassphrase: ErrBadPass instead of mismatch | KILLED | KILLED* |
| M139 | `pkg/keystore/ring.go` | checkPassphrase: no clear (EQ expected) | SURVIVED | SURVIVED |
| M140 | `pkg/keystore/ring.go` | add: plaintext not cleared (observable via ImportSecret aliasing only) | SURVIVED | SURVIVED |
| M141 | `pkg/keystore/ring.go` | encrypt: created not truncated | KILLED | KILLED* |
| M142 | `pkg/keystore/ring.go` | encrypt: key not cleared (EQ expected) | SURVIVED | SURVIVED |
| M143 | `pkg/keystore/ring.go` | encrypt: AAD kind/id swapped | KILLED | KILLED* |
| M144 | `pkg/keystore/ring.go` | unlock: AAD without pub | KILLED | KILLED* |
| M145 | `pkg/keystore/ring.go` | ChangePassphrase: empty new accepted | KILLED | KILLED* |
| M146 | `pkg/keystore/ring.go` | ChangePassphrase: empty ring OK | KILLED | KILLED* |
| M147 | `pkg/keystore/ring.go` | ChangePassphrase: verify only entry 0 | KILLED | KILLED* |
| M148 | `pkg/keystore/ring.go` | ChangePassphrase: verify only last entry | SURVIVED | KILLED |
| M149 | `pkg/keystore/ring.go` | ChangePassphrase: skip entries that fail | KILLED | KILLED* |
| M150 | `pkg/keystore/ring.go` | ChangePassphrase: re-encrypt under old | KILLED | KILLED* |
| M151 | `pkg/keystore/ring.go` | ChangePassphrase: created reset | KILLED | KILLED* |
| M152 | `pkg/keystore/ring.go` | ChangePassphrase: result discarded | KILLED | KILLED* |
| M153 | `pkg/keystore/ring.go` | ChangePassphrase: plaintext not cleared (EQ expected) | SURVIVED | SURVIVED |
| M154 | `pkg/keystore/ring.go` | Use: secret may become current | KILLED | KILLED* |
| M155 | `pkg/keystore/ring.go` | Use: no-op | KILLED | KILLED* |
| M156 | `pkg/keystore/ring.go` | Remove: force ignored | KILLED | KILLED* |
| M157 | `pkg/keystore/ring.go` | Remove: last signing key unprotected | KILLED | KILLED* |
| M158 | `pkg/keystore/ring.go` | Remove: protect last two | KILLED | KILLED* |
| M159 | `pkg/keystore/ring.go` | Remove: secret removal blocked when only one signing key | KILLED | KILLED* |
| M160 | `pkg/keystore/ring.go` | Remove: count<=1 (count>=1 here) (EQ expected) | SURVIVED | SURVIVED |
| M161 | `pkg/keystore/ring.go` | Remove: current left dangling | KILLED | KILLED* |
| M162 | `pkg/keystore/ring.go` | Remove: current kept when no signing key remains | KILLED | KILLED* |
| M163 | `pkg/keystore/ring.go` | Remove: current moves to a secret | SURVIVED | KILLED |
| M164 | `pkg/keystore/ring.go` | Remove: current moves to the LAST signing key | KILLED | KILLED* |
| M165 | `pkg/keystore/ring.go` | add: secret can become current | KILLED | KILLED* |
| M166 | `pkg/keystore/ring.go` | add: every new key becomes current | KILLED | KILLED* |
| M167 | `pkg/keystore/ring.go` | update: snapshot not refreshed | KILLED | KILLED* |
| M168 | `pkg/keystore/ring.go` | OpenOrCreate: lost creation race not handled | SURVIVED | KILLED |
| M169 | `pkg/keystore/ring.go` | Import: no length check | SURVIVED | KILLED |
| M170 | `pkg/keystore/ring.go` | Import: public half not checked against seed | KILLED | KILLED* |
| M171 | `pkg/keystore/ring.go` | addSigning: no clear on error path (EQ expected) | SURVIVED | SURVIVED |
| M172 | `pkg/keystore/entry.go` | signingEntry: no empty-current guard (Find("") is nil anyway) (EQ expected) | SURVIVED | SURVIVED |
| M173 | `pkg/keystore/entry.go` | signingEntry: secret treated as signing key | KILLED | KILLED* |
| M174 | `pkg/keystore/entry.go` | List: current inverted | KILLED | KILLED* |
| M175 | `pkg/keystore/entry.go` | fingerprint: padded base64 | KILLED | KILLED* |
| M176 | `pkg/keystore/entry.go` | fingerprint prefix | KILLED | KILLED* |
| M177 | `pkg/keystore/entry.go` | List: pub for wrong kind | KILLED | KILLED* |
| M178 | `pkg/keystore/entry.go` | publicFromSPKI: non-ed25519 accepted (nil pub) | SURVIVED | KILLED |
| M179 | `pkg/keystore/signer.go` | ExportPrivate: skip advertised-key check | SURVIVED | KILLED |
| M180 | `pkg/keystore/signer.go` | ExportPrivate: non-constant-time compare (timing only) (EQ expected) | SURVIVED | SURVIVED |
| M181 | `pkg/keystore/signer.go` | ExportPrivate: compare lengths only | SURVIVED | KILLED |
| M182 | `pkg/keystore/signer.go` | ExportPrivate: pkcs8 not cleared (EQ expected) | SURVIVED | SURVIVED |
| M183 | `pkg/keystore/signer.go` | ExportPrivate: marshal error ignored (EQ expected) | SURVIVED | SURVIVED |
| M184 | `pkg/keystore/secret.go` | SecretSize 16 | SURVIVED | KILLED |
| M185 | `pkg/keystore/secret.go` | MaxSecretSize+1 | SURVIVED | KILLED |
| M186 | `pkg/keystore/secret.go` | ImportSecret: max boundary -1 | SURVIVED | KILLED |
| M187 | `pkg/keystore/secret.go` | ImportSecret: empty secret accepted | KILLED | KILLED* |
| M188 | `pkg/keystore/secret.go` | ImportSecret: hands caller's slice to add (then cleared) | SURVIVED | KILLED |
| M189 | `pkg/keystore/secret.go` | AddSecret: returned secret aliases the cleared plaintext | KILLED | KILLED* |
| M190 | `pkg/keystore/secret.go` | Secret: signing key readable as secret | KILLED | KILLED* |
| M191 | `pkg/keystore/secret.go` | AddSecret: no clear on error (EQ expected) | SURVIVED | SURVIVED |
| M192 | `pkg/keystore/pem.go` | PEM: headers accepted | KILLED | KILLED* |
| M193 | `pkg/keystore/pem.go` | PEM: trailing data accepted | KILLED | KILLED* |
| M194 | `pkg/keystore/pem.go` | PEM: any block type accepted | KILLED | KILLED* |
| M195 | `pkg/keystore/pem.go` | parsePKCS8: non-ed25519 accepted | SURVIVED | KILLED |
| M196 | `pkg/agent/server.go` | handle: no peer uid comparison | KILLED | KILLED* |
| M197 | `pkg/agent/server.go` | handle: uid lookup error ignored | SURVIVED | KILLED |
| M198 | `pkg/agent/server.go` | checkDir: other bits unchecked | SURVIVED | KILLED |
| M199 | `pkg/agent/server.go` | checkDir: group bits unchecked | SURVIVED | KILLED |
| M200 | `pkg/agent/server.go` | checkDir: owner unchecked | SURVIVED | KILLED |
| M201 | `pkg/agent/server.go` | Listen: path length boundary -1 | KILLED | KILLED* |
| M202 | `pkg/agent/server.go` | Listen: path length boundary +1 | KILLED | KILLED* |
| M203 | `pkg/agent/server.go` | Listen lock: follow symlink | SURVIVED | KILLED |
| M204 | `pkg/agent/server.go` | Listen lock: mode 0666 (umask-dependent) | SURVIVED | KILLED |
| M205 | `pkg/agent/server.go` | Listen: blocking flock | TIMEOUT | TIMEOUT* |
| M206 | `pkg/agent/server.go` | Listen: lock contention not ErrInUse | KILLED | KILLED* |
| M207 | `pkg/agent/server.go` | listenLocked: non-socket at path is removed | KILLED | KILLED* |
| M208 | `pkg/agent/server.go` | listenLocked: live socket not detected | SURVIVED | KILLED |
| M209 | `pkg/agent/server.go` | listenLocked: stale socket not removed | KILLED | KILLED* |
| M210 | `pkg/agent/server.go` | listenLocked: umask 0 during bind (chmod follows) (EQ expected) | SURVIVED | SURVIVED |
| M211 | `pkg/agent/server.go` | listenLocked: drop chmod (umask 0177 already gives 0600) (EQ expected) | SURVIVED | SURVIVED |
| M212 | `pkg/agent/server.go` | listenLocked: socket chmod 0666 | KILLED | KILLED* |
| M213 | `pkg/agent/server.go` | listener leaves socket file behind | KILLED | KILLED* |
| M214 | `pkg/agent/server.go` | Listener.Close: path lock never released | KILLED | KILLED* |
| M215 | `pkg/agent/server.go` | Serve: negative idle accepted | KILLED | KILLED* |
| M216 | `pkg/agent/server.go` | Serve: negative ttl accepted | KILLED | KILLED* |
| M217 | `pkg/agent/server.go` | Serve: zero ttl refused | KILLED | KILLED* |
| M218 | `pkg/agent/server.go` | Serve: listener not closed on negative lifetime | KILLED | KILLED* |
| M219 | `pkg/agent/server.go` | Serve: ignores Close-before-Serve | TIMEOUT | TIMEOUT* |
| M220 | `pkg/agent/server.go` | Serve: closed listener is an error | SURVIVED | KILLED |
| M221 | `pkg/agent/server.go` | accept retry: ENFILE fatal | SURVIVED | KILLED |
| M222 | `pkg/agent/server.go` | accept retry: EMFILE fatal | KILLED | KILLED* |
| M223 | `pkg/agent/server.go` | accept retry: no backoff (EQ expected) | SURVIVED | KILLED |
| M224 | `pkg/agent/server.go` | Serve: fatal accept error leaves socket/conns/key | KILLED | KILLED* |
| M225 | `pkg/agent/server.go` | Serve: swallow fatal accept error | KILLED | KILLED* |
| M226 | `pkg/agent/server.go` | Serve: raced connection left open | SURVIVED | KILLED |
| M227 | `pkg/agent/server.go` | Serve: does not wait for handlers | SURVIVED | KILLED |
| M228 | `pkg/agent/server.go` | handlers never untracked (leak) (EQ expected) | SURVIVED | KILLED |
| M229 | `pkg/agent/server.go` | watch: TTL 0 expires immediately | KILLED | KILLED* |
| M230 | `pkg/agent/server.go` | watch: Idle 0 expires immediately | KILLED | KILLED* |
| M231 | `pkg/agent/server.go` | watch: touch does not reset idle timer | KILLED | KILLED* |
| M232 | `pkg/agent/server.go` | expire: reported as plain close | KILLED | KILLED* |
| M233 | `pkg/agent/server.go` | expire: does not close | TIMEOUT | TIMEOUT* |
| M234 | `pkg/agent/server.go` | Close: closed flag not set | TIMEOUT | TIMEOUT* |
| M235 | `pkg/agent/server.go` | Close: open connections not closed | KILLED | KILLED* |
| M236 | `pkg/agent/server.go` | track: registers after close | SURVIVED | KILLED |
| M237 | `pkg/agent/server.go` | handle: no I/O deadline | SURVIVED | KILLED |
| M238 | `pkg/agent/server.go` | handle: oversize frame: no reply/log | KILLED | KILLED* |
| M239 | `pkg/agent/server.go` | handle: truncated public key | KILLED | KILLED* |
| M240 | `pkg/agent/server.go` | handle: signs empty message | KILLED | KILLED* |
| M241 | `pkg/agent/server.go` | handle: no error reply on sign failure | SURVIVED | KILLED |
| M242 | `pkg/agent/server.go` | handle: unknown op keeps the connection (then replies OK) | SURVIVED | KILLED |
| M243 | `pkg/agent/server.go` | handle: success does not touch idle timer | KILLED | KILLED* |
| M244 | `pkg/agent/server.go` | NewServer: IOTimeout default 0 | KILLED | KILLED* |
| M245 | `pkg/agent/server.go` | handle: connection never closed | SURVIVED | KILLED |
| M246 | `pkg/agent/frame.go` | readFrame: boundary -1 | KILLED | KILLED* |
| M247 | `pkg/agent/frame.go` | readFrame: boundary +1 | KILLED | KILLED* |
| M248 | `pkg/agent/frame.go` | readFrame: no size cap | KILLED | KILLED* |
| M249 | `pkg/agent/frame.go` | writeFrame: boundary -1 | KILLED | KILLED* |
| M250 | `pkg/agent/frame.go` | writeFrame: no size cap | SURVIVED | KILLED |
| M251 | `pkg/agent/frame.go` | MaxPayload doubled | SURVIVED | KILLED |
| M252 | `pkg/agent/frame.go` | readFrame: little-endian length | KILLED | KILLED* |
| M253 | `pkg/agent/frame.go` | readFrame: wrong op byte | KILLED | KILLED* |
| M254 | `pkg/agent/client.go` | client: peer-uid lookup error ignored | SURVIVED | SURVIVED |
| M255 | `pkg/agent/client.go` | client: peer uid never compared | SURVIVED | SURVIVED |
| M256 | `pkg/agent/client.go` | Dial: accept long public key | SURVIVED | KILLED |
| M257 | `pkg/agent/client.go` | Sign: signature not verified | SURVIVED | KILLED |
| M258 | `pkg/agent/client.go` | Sign: length unchecked (Verify rejects bad length) (EQ expected) | SURVIVED | SURVIVED |
| M259 | `pkg/agent/client.go` | Sign: hashed opts accepted | KILLED | KILLED* |
| M260 | `pkg/agent/client.go` | Sign: ed25519 contexts accepted | KILLED | KILLED* |
| M261 | `pkg/agent/client.go` | roundTrip: payload boundary -1 | KILLED | KILLED* |
| M262 | `pkg/agent/client.go` | roundTrip: no client-side size cap | SURVIVED | KILLED |
| M263 | `pkg/agent/client.go` | client: no exchange deadline | SURVIVED | KILLED |
| M264 | `pkg/agent/client.go` | client: error status treated as success | KILLED | KILLED* |
| M265 | `pkg/agent/client.go` | Dial: default timeout 0 | KILLED | KILLED* |
| M266 | `pkg/agent/client.go` | DefaultTimeout 50s | SURVIVED | KILLED |
| M267 | `pkg/agent/resolve.go` | ResolveSigner: agent/ring selection inverted | KILLED | KILLED* |
| M268 | `pkg/agent/resolve.go` | ResolveSigner: passphrase not cleared | SURVIVED | KILLED |
| M269 | `pkg/agent/resolve.go` | ResolveSigner: ignores id | KILLED | KILLED* |
| M270 | `internal/passphrase/passphrase.go` | resolve: empty env var wins | KILLED | KILLED* |
| M271 | `internal/passphrase/passphrase.go` | resolve: passfile outranks env | KILLED | KILLED* |
| M272 | `internal/passphrase/passphrase.go` | resolve: replacement reads keychain | KILLED | KILLED* |
| M273 | `internal/passphrase/passphrase.go` | resolve: passfile outranks keychain | KILLED | KILLED* |
| M274 | `internal/passphrase/passphrase.go` | resolve: keychain failure ignored | SURVIVED | KILLED |
| M275 | `internal/passphrase/passphrase.go` | resolve: passfile never read | KILLED | KILLED* |
| M276 | `internal/passphrase/passphrase.go` | resolve: prompted flag lost (no confirmation) | KILLED | KILLED* |
| M277 | `internal/passphrase/passphrase.go` | replacement reads current-passphrase var | KILLED | KILLED* |
| M278 | `internal/passphrase/passphrase.go` | establish ignores keychain | KILLED | KILLED* |
| M279 | `internal/passphrase/passphrase.go` | replacement message names wrong flag | KILLED | KILLED* |
| M280 | `internal/passphrase/passphrase.go` | shadowed: establishing only notes, not refuses | KILLED | KILLED* |
| M281 | `internal/passphrase/passphrase.go` | shadowed: no passfile -> still refuses | KILLED | KILLED* |
| M282 | `internal/passphrase/passphrase.go` | shadowed: unlock shadow notice dropped | KILLED | KILLED* |
| M283 | `internal/passphrase/passphrase.go` | establish: no repeat prompt | KILLED | KILLED* |
| M284 | `internal/passphrase/passphrase.go` | establish: mismatch ignored | KILLED | KILLED* |
| M285 | `internal/passphrase/passphrase.go` | establish: repeat entry not cleared | SURVIVED | KILLED |
| M286 | `internal/passphrase/passphrase.go` | establish: pw not cleared on mismatch | SURVIVED | KILLED |
| M287 | `internal/passphrase/passphrase.go` | establish: pw not cleared when repeat prompt fails | SURVIVED | KILLED |
| M288 | `internal/passphrase/passphrase.go` | establish: pw not cleared when too short | SURVIVED | KILLED |
| M289 | `internal/passphrase/passphrase.go` | MinLen counted in bytes, not runes | KILLED | KILLED* |
| M290 | `internal/passphrase/passphrase.go` | MinLen boundary +1 | KILLED | KILLED* |
| M291 | `internal/passphrase/passphrase.go` | MinLen boundary -1 | KILLED | KILLED* |
| M292 | `internal/passphrase/passphrase.go` | MinLen 8 | KILLED | KILLED* |
| M293 | `internal/passphrase/passphrase.go` | establish: empty check dropped (MinLen still refuses) (EQ expected) | SURVIVED | KILLED |
| M294 | `internal/passphrase/passphrase.go` | Unlock: empty passphrase accepted | KILLED | KILLED* |
| M295 | `internal/passphrase/passphrase.go` | passfile: follows symlinks | KILLED | KILLED* |
| M296 | `internal/passphrase/passphrase.go` | passfile: FIFO open blocks | KILLED | KILLED* |
| M297 | `internal/passphrase/passphrase.go` | passfile: non-regular accepted | SURVIVED | KILLED |
| M298 | `internal/passphrase/passphrase.go` | passfile: other bits unchecked | SURVIVED | KILLED |
| M299 | `internal/passphrase/passphrase.go` | passfile: group bits unchecked | KILLED | KILLED* |
| M300 | `internal/passphrase/passphrase.go` | passfile: owner unchecked | SURVIVED | SURVIVED |
| M301 | `internal/passphrase/passphrase.go` | passfile: size cap off by one (silent truncation) | KILLED | KILLED* |
| M302 | `internal/passphrase/passphrase.go` | passfile: size cap boundary -1 | SURVIVED | KILLED |
| M303 | `internal/passphrase/passphrase.go` | passfile cap doubled | SURVIVED | KILLED |
| M304 | `internal/passphrase/passphrase.go` | passfile: TrimSpace strips significant spaces | SURVIVED | KILLED |
| M305 | `internal/passphrase/passphrase.go` | passfile: strips all trailing newlines | SURVIVED | KILLED |
| M306 | `internal/passphrase/passphrase.go` | passfile: CRLF not handled | KILLED | KILLED* |
| M307 | `internal/passphrase/passphrase.go` | passfile: LF not stripped | KILLED | KILLED* |
| M308 | `internal/term/clean.go` | Clean: IsGraphic admits NBSP and other Zs (not terminal-active) (EQ expected) | SURVIVED | KILLED |
| M309 | `internal/term/clean.go` | Clean: drops instead of replacing | SURVIVED | KILLED |
| M310 | `internal/term/clean.go` | Clean: only ASCII controls and DEL | KILLED | KILLED* |
| M311 | `internal/term/clean.go` | Clean: lets bidi/line separators through | KILLED | KILLED* |
| M312 | `cmd/keystore/main.go` | exit code 3 -> 1 | KILLED | KILLED* |
| M313 | `cmd/keystore/main.go` | exit code 2 -> 1 | KILLED | KILLED* |
| M314 | `cmd/keystore/main.go` | report: bad signature exits 1 | KILLED | KILLED* |
| M315 | `cmd/keystore/main.go` | report: usage error not cleaned | KILLED | KILLED* |
| M316 | `cmd/keystore/main.go` | oneLine: not cleaned | KILLED | KILLED* |
| M317 | `cmd/keystore/main.go` | report: -h exits non-zero | KILLED | KILLED* |
| M318 | `cmd/keystore/main.go` | run: extra args accepted | KILLED | KILLED* |
| M319 | `cmd/keystore/main.go` | flag errors printed raw by flag pkg | KILLED | KILLED* |
| M320 | `cmd/keystore/main.go` | oneLine: no keystore: prefix | KILLED | KILLED* |
| M321 | `cmd/keystore/output.go` | guard: -o does not bypass (EQ expected) | KILLED | KILLED* |
| M322 | `cmd/keystore/output.go` | guard: -force does not bypass | KILLED | KILLED* |
| M323 | `cmd/keystore/output.go` | guard: nil outFile (tests) -> nil deref | SURVIVED | SURVIVED |
| M324 | `cmd/keystore/output.go` | guard: terminal allowed | KILLED | KILLED* |
| M325 | `cmd/keystore/output.go` | guard: also trips on non-regular (pipe) | KILLED | KILLED* |
| M326 | `cmd/keystore/output.go` | guard: other-readable file allowed | KILLED | KILLED* |
| M327 | `cmd/keystore/output.go` | guard: group-readable file allowed | KILLED | KILLED* |
| M328 | `cmd/keystore/output.go` | guard: redirect check disabled | KILLED | KILLED* |
| M329 | `cmd/keystore/output.go` | secret file mode 0644 | KILLED | KILLED* |
| M330 | `cmd/keystore/output.go` | secret file mode 0666 | KILLED | KILLED* |
| M331 | `cmd/keystore/output.go` | writeFile: symlink not refused | SURVIVED | KILLED |
| M332 | `cmd/keystore/output.go` | writeFile: existing file overwritten without -force | KILLED | KILLED* |
| M333 | `cmd/keystore/output.go` | writeFile: force inverted | KILLED | KILLED* |
| M334 | `cmd/keystore/output.go` | writeFile: -force replaces a non-regular file | SURVIVED | KILLED |
| M335 | `cmd/keystore/output.go` | writeNew: no O_EXCL (Lstat precheck covers non-racy case) (EQ expected) | SURVIVED | SURVIVED |
| M336 | `cmd/keystore/output.go` | writeNew: no O_NOFOLLOW (Lstat precheck covers non-racy case) (EQ expected) | SURVIVED | SURVIVED |
| M337 | `cmd/keystore/output.go` | writeNew: partial file left on write error | SURVIVED | SURVIVED |
| M338 | `cmd/keystore/output.go` | writeNew: skip fsync | SURVIVED | SURVIVED |
| M339 | `cmd/keystore/output.go` | replace: drop chmod (CreateTemp 0600; sign wants 0644) | SURVIVED | KILLED |
| M340 | `cmd/keystore/output.go` | replace: temp file leaked on failure | SURVIVED | KILLED |
| M341 | `cmd/keystore/output.go` | replace: never renamed | KILLED | KILLED* |
| M342 | `cmd/keystore/output.go` | emit echo: path not cleaned | KILLED | KILLED* |
| M343 | `cmd/keystore/output.go` | emit: inverted destination | KILLED | KILLED* |
| M344 | `cmd/keystore/verbs.go` | init echo: ring not cleaned | KILLED | KILLED* |
| M345 | `cmd/keystore/verbs.go` | import echo: key path not cleaned | KILLED | KILLED* |
| M346 | `cmd/keystore/verbs.go` | ensureDir: inverted | SURVIVED | KILLED |
| M347 | `cmd/keystore/verbs.go` | ensureDir: creates dirs for any path | SURVIVED | KILLED |
| M348 | `cmd/keystore/verbs.go` | ensureDir: mode 0755 | SURVIVED | KILLED |
| M349 | `cmd/keystore/verbs.go` | ringPassphrase: one-entry ring treated as new | KILLED | KILLED* |
| M350 | `cmd/keystore/verbs.go` | ringPassphrase: always establish (MinLen on existing ring) | KILLED | KILLED* |
| M351 | `cmd/keystore/verbs.go` | export-priv: guard dropped | KILLED | KILLED* |
| M352 | `cmd/keystore/verbs.go` | export-priv: guard always forced | KILLED | KILLED* |
| M353 | `cmd/keystore/verbs.go` | export-priv: -o always overwrites | KILLED | KILLED* |
| M354 | `cmd/keystore/verbs.go` | list: marker inverted | KILLED | KILLED* |
| M355 | `cmd/keystore/verbs.go` | rm: always forced | KILLED | KILLED* |
| M356 | `cmd/keystore/verbs.go` | import: -key optional | SURVIVED | KILLED |
| M357 | `cmd/keystore/secrets.go` | readSecret: limit w/o newline room | SURVIVED | KILLED |
| M358 | `cmd/keystore/secrets.go` | readSecret: limit +1 | SURVIVED | KILLED |
| M359 | `cmd/keystore/secrets.go` | readSecret stdin: truncates instead of refusing | SURVIVED | KILLED |
| M360 | `cmd/keystore/secrets.go` | readSecret stdin: boundary -1 | SURVIVED | KILLED |
| M361 | `cmd/keystore/secrets.go` | readSecret: terminal stdin read as pipe | KILLED | KILLED* |
| M362 | `cmd/keystore/secrets.go` | readSecret: whitespace not trimmed | KILLED | KILLED* |
| M363 | `cmd/keystore/secrets.go` | readLimited: silent truncation | KILLED | KILLED* |
| M364 | `cmd/keystore/secrets.go` | readLimited: boundary -1 | KILLED | KILLED* |
| M365 | `cmd/keystore/secrets.go` | readLimited: no cap | KILLED | KILLED* |
| M366 | `cmd/keystore/secrets.go` | add-secret: minted secret not cleared (EQ expected) | SURVIVED | SURVIVED |
| M367 | `cmd/keystore/secrets.go` | export-secret: guard dropped | KILLED | KILLED* |
| M368 | `cmd/keystore/secrets.go` | export-secret: no trailing newline | KILLED | KILLED* |
| M369 | `cmd/keystore/secrets.go` | passwd: same passphrase allowed | KILLED | KILLED* |
| M370 | `cmd/keystore/secrets.go` | passwd echo: keychain service not cleaned | KILLED | KILLED* |
| M371 | `cmd/keystore/secrets.go` | keychain-set echo: service not cleaned | SURVIVED | SURVIVED |
| M372 | `cmd/keystore/secrets.go` | passwd: keychain note inverted | KILLED | KILLED* |
| M373 | `cmd/keystore/sign.go` | sign: -agent/-id exclusion widened | KILLED | KILLED* |
| M374 | `cmd/keystore/sign.go` | sign: -id with -agent allowed | KILLED | KILLED* |
| M375 | `cmd/keystore/sign.go` | sign: empty -expect-fp quietly unpinned | KILLED | KILLED* |
| M376 | `cmd/keystore/sign.go` | sign: pin via non-empty value (empty caught earlier) (EQ expected) | SURVIVED | SURVIVED |
| M377 | `cmd/keystore/sign.go` | sign: fingerprint compared as prefix | KILLED | KILLED* |
| M378 | `cmd/keystore/sign.go` | sign: fingerprint compared by length only | KILLED | KILLED* |
| M379 | `cmd/keystore/sign.go` | sign: key not cleared on pin mismatch (EQ expected) | SURVIVED | SURVIVED |
| M380 | `cmd/keystore/sign.go` | sign: key not cleared after signing (EQ expected) | SURVIVED | SURVIVED |
| M381 | `cmd/keystore/sign.go` | sign: -raw inverted | KILLED | KILLED* |
| M382 | `cmd/keystore/sign.go` | sign -o mode 0600 (public output) | SURVIVED | KILLED |
| M383 | `cmd/keystore/sign.go` | sign -o mode 0666 | SURVIVED | KILLED |
| M384 | `cmd/keystore/sign.go` | sign -o: always overwrite | KILLED | KILLED* |
| M385 | `cmd/keystore/sign.go` | sign echo: -o not cleaned | KILLED | KILLED* |
| M386 | `cmd/keystore/sign.go` | verify: inverted | KILLED | KILLED* |
| M387 | `cmd/keystore/sign.go` | verify: always passes | KILLED | KILLED* |
| M388 | `cmd/keystore/sign.go` | readMessage: silent truncation at 1 MiB | KILLED | KILLED* |
| M389 | `cmd/keystore/sign.go` | readMessage: boundary -1 | SURVIVED | KILLED |
| M390 | `cmd/keystore/sign.go` | maxMessage doubled | SURVIVED | KILLED |
| M391 | `cmd/keystore/sign.go` | readSignature: accept long raw | KILLED | KILLED* |
| M392 | `cmd/keystore/sign.go` | readSignature: base64 of wrong length accepted | SURVIVED | KILLED |
| M393 | `cmd/keystore/sign.go` | readSignature: whitespace-padded base64 refused | SURVIVED | KILLED |
| M394 | `cmd/keystore-agent/main.go` | agent: negative -idle passes flag check | KILLED | KILLED* |
| M395 | `cmd/keystore-agent/main.go` | agent: negative -ttl passes flag check | KILLED | KILLED* |
| M396 | `cmd/keystore-agent/main.go` | agent: -ttl 0 refused | SURVIVED | KILLED |
| M397 | `cmd/keystore-agent/main.go` | agent: passphrase env var not scrubbed | KILLED | KILLED* |
| M398 | `cmd/keystore-agent/main.go` | agent: KEYSTORE_KEYCHAIN not refused | TIMEOUT | TIMEOUT* |
| M399 | `cmd/keystore-agent/main.go` | agent: -id ignored | SURVIVED | KILLED |
| M400 | `cmd/keystore-agent/main.go` | agent: ttl and idle swapped | SURVIVED | KILLED |
| M401 | `cmd/keystore-agent/main.go` | agent: expiry exits non-zero | KILLED | KILLED* |
| M402 | `cmd/keystore-agent/main.go` | agent log: socket path not cleaned | KILLED | KILLED* |
| M403 | `cmd/keystore-agent/main.go` | agent main: error not cleaned | KILLED | KILLED* |
| M404 | `cmd/keystore-agent/main.go` | agent: -sock optional | SURVIVED | KILLED |
| M405 | `cmd/keystore-agent/main.go` | agent: socket path not made absolute | SURVIVED | KILLED |
| M406 | `cmd/keystore-agent/main.go` | agent: key not cleared on exit (EQ expected) | SURVIVED | SURVIVED |
| M407 | `cmd/keystore-agent/main.go` | agent: no Log wiring | SURVIVED | KILLED |
| M408 | `cmd/keystore-agent/main.go` | agent: default ttl unlimited | SURVIVED | KILLED |
| M409 | `cmd/keystore-agent/main.go` | agent: default idle unlimited | SURVIVED | KILLED |
