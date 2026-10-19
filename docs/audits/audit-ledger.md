# keystore audit ledger (the running ledger, kept as written) — candidates awaiting the finding skeptic

Status key: CAND = auditor claim, unverified by a skeptic · all claims below are the auditors' reports, not yet re-derived by me unless marked.

## Wave 1 — A1 / A2 (auditors A, B, C reported; D pending)

| ID | Src | Sev (claimed) | Claim | Repro by auditor | Initial disposition |
|---|---|---|---|---|---|
| W1-01 | C#1 | HIGH (security-relevant) | Negative `-ttl`/`-idle` silently disables agent expiry (`server.go:199-210` arms timers only if >0; `keystore-agent/main.go:45-46` no validation) | yes: agent alive after 3 s, still signing | fix (validate in CLI + Serve); I will re-run the repro myself |
| W1-02 | C#2 | HIGH/low-mod | Library `Add/AddSecret/encrypt/checkPassphrase` accept nil/empty passphrase; `ChangePassphrase` rejects it; SECURITY.md says library "accepts any non-empty passphrase" | yes: `Add("a", nil)` err=nil | fix (reject empty at library boundary) |
| W1-03 | C#3 | PERF/avail | `passwd` holds ring lock for 2N argon2 runs; ~40 entries = 11 s > 10 s LockTimeout, concurrent writer fails | yes: 40 secrets, 11.05 s, writer failed 10.5 s | decide: availability only; likely DELIBERATE/doc unless cheap fix |
| W1-04 | C#4 | MINOR | `Listen` flips process-wide umask without serialisation; 166/200 rounds leave umask 0177 | yes | fix (mutex or drop umask dance; check why both umask + chmod) |
| W1-05 | C#5 | MINOR | `*Keystore` data race on `k.f` (ring.go:228 vs :71), undocumented | yes: -race WARNING | fix: document, or atomic pointer |
| W1-06 | C#6 | MINOR | socket path > sun_path: cryptic bind error, `.lock` left behind | yes | fix (up-front length check) |
| W1-07 | C#7 | MINOR | `keygen` leaves an empty ring file when passphrase establishment fails (verbs.go:126-130) | yes | fix (resolve passphrase before creating) |
| W1-08 | A#1 / C#8 | HIGH(A)/MINOR(C) | `len([]rune(string(pw)))` (passphrase.go:109) copies passphrase into uncleared string; `utf8.RuneCount` equivalent (0 mismatches / 2M inputs) | A: equivalence test | fix |
| W1-09 | C#9 | SPEC | `Serve` returns on non-closed Accept error without closing listener/conns | no | skeptic to try to reproduce (EMFILE) |
| W1-10 | C#10 | MINOR | `readSecret` on a terminal capped at 1024 B (term.MaxLen) while MaxSecretSize is 64 KiB; error says "passphrase too long"; example readPassfile claims "same rule" as CLI but follows symlinks/no owner check; export files not dir-fsynced | no | doc/fix triage |
| W1-11 | B#2 | MINOR | `verify -pub` (sign.go:79) and `readSignature` (sign.go:124) use uncapped `os.ReadFile`; every other input read is capped | yes (reading) | fix (use capped helper) |
| W1-12 | B#1 | HIGH(test) | six byte-identical `examples/*/run_test.go` | diff | fix (one table test) — low value, least-code says do it only if cheap |
| W1-13 | B#4 | MODERATE | constants that must agree: ring magic/prefix/`n>1`; frame-limit text vs `MaxPayload`; keychain id-rule text vs `ids` | reading | fix drift-protection ones |
| W1-14 | A#3 | MODERATE | agent builds `crypto.Signer` then type-asserts to `ed25519.PrivateKey` (`keystore-agent/main.go:81-86`); `ExportPrivate` direct is safer | reading | fix (1 LOC) |
| W1-15 | A#2 | MODERATE | dead error branches after `crypto/rand.Read` (Go>=1.24 never errors) | verified in GOROOT | probably DELIBERATE: crypto-path signature change, fail-closed handling is harmless |
| W1-16 | A#4/B#3/A#5/B#2 | MODERATE | write/sync/close ladder and capped-read idiom repeated in `cmd/keystore` | reading | fix cmd-local helper only; do NOT merge with `ringfile.writeTemp` (crash hooks) |
| W1-17 | A#6 | MODERATE | redundant `LOCK_UN` before `Close` (ringfile.go:403-406) | scratch test | fix (1 LOC) — only if skeptic agrees; trivial |
| W1-18 | A#7/#8 | MINOR | `examples/signed-requests/rand.go` seam; micro-cleanups | — | batch umbrella `chore` |
| W1-19 | B#9 | — | `Keystore.Path` unreachable, public API | deadcode | DELIBERATE keep |

Considered-and-rejected lists from A and B (load-bearing checks) are recorded in their reports; carry into `audit-simplify.md` / `audit-dedup.md`.

## Wave 2 — blind implementer (reported)

| ID | Claim | Evidence |
|---|---|---|
| W2-B0 | **Spec == code**: independent implementation from `docs/format.md` alone decrypted both golden entries; round-trip with real CLI both ways; all authenticated fields fail as specified, `created`/`current` unauthenticated as documented | agent output |
| W2-B1 | format.md underspecified (doc fixes, A6): JSON null/dup keys/missing fields/empty `entries`; secret `pub` absent vs `""` (CLI rejects `""`); base64 canonical/whitespace; `pub` parsed at load; "newer vN" comparison for v10/v01; `current` pointing at a secret | agent list; none changed the AAD or KDF |
| W2-B2 | untested by blind agent (to cover in A6/L2): duplicate JSON keys, null, non-canonical base64, duplicate entry ids, 16 MiB limit | — |

## Pending reports
D (doc drift), A3-1 … A3-5, interop/Linux/OpenSSL.

## Wave 1 — auditor D (doc drift) reported

| ID | Sev (claimed) | Claim | Evidence (auditor) | Disposition |
|---|---|---|---|---|
| W1-D1 | HIGH (security overstatement) | Docs say any modification / "every value used" is authenticated (SECURITY.md:12,38; exec-summary:17; introduction:15; scope #2). Code authenticates only format/kind/id/pub/KDF/salt/nonce/ct. **`current`, entry order, entry set (delete), whole-ring rollback are unauthenticated.** Editing `current` k1->k2 then `sign` signed with k2, no error. | experiments on a 3-entry ring | doc fix now (list what is/is not authenticated). **Authenticating `current` = ring-format change -> STOP-AND-ASK trigger (plan §2.5), do not fold into a cleanup** |
| W1-D2 | MOD | "Concurrent writers cannot lose/corrupt" omits "cooperating" (flock advisory; architecture.md says so) | reading | doc fix |
| W1-D3 | MOD | "agent env var removed once read" — still visible in `ps eww` (macOS) / /proc/PID/environ | `ps eww` observed | doc fix (+ SECURITY known limit); consider code option |
| W1-D4 | MOD | README/build say release **archives** are reproducible; 3 runs gave different SHA256SUMS for all tgz (binaries identical; SBOM date + tar mtimes) | 3 runs | fix build determinism (SOURCE_DATE_EPOCH, tar --sort/--mtime, gzip -n) or reword; L4-adjacent -> record, fix only if cheap |
| W1-D5 | MOD | userguide: "every verb accepts -keystore" false for verify, keychain-set | run | doc fix |
| W1-D6..10 | LOW | agent has no default ring / refuses KEYSTORE_KEYCHAIN; format.md `created` rule + year range; architecture dep diagram edges; scope.md stale API names + "one named error" (kind/nonce tamper fail at parse w/ ErrBadFormat); misc (dead link to gitignored plan, socket-path length undocumented, passphrase length caps undocumented, comments) | verified per item | batch doc umbrella |

Verified clean per D: verb table/reference.md, passphrase order + 12-rune minimum, all numbers, file modes, format.md AAD (re-implemented, golden decrypts), agent protocol spoken raw from Python, deps/notices, README layout.
Note for W1-01: D observed `-idle` expiry works at ~4 s with positive values; only negative is broken (consistent with C).

## Wave 2 — A3-1 format & AEAD binding (reported; auditor says no CRITICAL/HIGH, AEAD construction sound)

| ID | Sev (claimed) | Claim | Evidence | Disposition |
|---|---|---|---|---|
| W2-1-F1 | MED | `pub` is readable without passphrase (`list`, `export-pub`, `Public()`) but authenticated only at unlock; ring-writer can swap `pub`, `export-pub` then hands out attacker key (examples/provision flow). Signing still fails closed (ErrOpen). | real CLI output + lib test | doc (trust model) + code option: verified export (`export-pub -verify`/`VerifiedPublic`) — no format change |
| W2-1-F2 | MED (LOW if `-id` always passed) | No ring binding in AAD -> same-id entry transplant between rings sharing a passphrase unlocks; `current`/order unbound -> silent re-point. Cross-id/cross-kind moves fail. | PoC output | **needs format change (ring_id in AAD = v2) to fix -> STOP-AND-ASK**. Non-format mitigations: print fingerprint used by `Signer("")`/`sign`, `sign -expect-fp`; document |
| W2-1-F3 | LOW | rollback/replay undetectable; deleted (compromised) key unlockable again from old snapshot; not in SECURITY.md known limits | restored snapshot test | doc (known limit); counter = format change, ask |
| W2-1-F4 | LOW | `Import(id, priv, pass)` accepts a 64-byte key whose public half != seed -> bricked entry, misleading "not a keystore file" | PoC | fix (validate; own error) — library-misuse |
| W2-1-F5 | INFO | SECURITY.md "passwd can take hours" overstated: measured max 56.4 s (1 GiB, t=64, p=1) per command + ~1 GiB RSS; passwd aborts at first auth failure; `list`/`export-pub` do no KDF | timings | doc fix |
| W2-1-F6 | INFO | non-canonical base64 (padding bits) opens fine; stdlib PKCS#8 parse ignores trailing bytes (post-auth) | PoC | optional `Strict()`; doc |

Verified-sound per A3-1: AAD injective (352,947 tuples / 300k fuzz, no collisions); no nonce/key reuse (66 unique salts+nonces after 20 passwd rounds; sole Seal call site); single indistinguishable ErrOpen (timing equal within noise at real cost); KDF params authenticated; pub cross-checked at export.
Cross-validation: F2/F3 + D#1 independently surface the same unauthenticated `current`/rollback/set -> HIGH-confidence doc finding.

## DECISION QUEUE for the user (format/boundary changes; not auto-fixed)
- Q1: Bind entries to their ring (random ring_id in AAD, format v2) and/or authenticate `current` (needs a MAC key derived from passphrase — "keyed MAC over pub+current" idea) — fixes W2-1-F2, W1-D1 root. Alternative: accept as ring-write-boundary limit and document. Recommendation pending skeptic + remaining A3 reports.

## Wave 2/6/7 — interop + Linux + cross-uid prover (reported; all PASS, no defect)

Proven by the agent [its output]: Linux arm64 (alpine, kernel 6.18) 17/17 test binaries pass as root AND uid 1000, incl. 6 example run.sh; OpenSSL 3.5.9 interop (export-pub/sign/verify both directions, export-priv, import of OpenSSL key, 15/18 wrong-format imports refused with ring unchanged); RFC 8032 TEST 1/2/3/1024/SHA(abc) exact; NIST GCM TC16 via seal.Open + tamper cases; kdf.Derive == argon2.IDKey == OpenSSL argon2id at 64MiB/t=3/p=1; **cross-uid agent rejection**: non-root other uid refused by file mode (never reaches agent); root client -> agent peer-uid check refuses ("peer uid 0 (want 1000)"); after hostile chmod 0777 on dir+socket uid 1001 and root still refused by SO_PEERCRED check; systemd-analyze verify rc=0 (systemd 257, debian container).
Closes release-v0.1.0 "not run": Linux runtime, cross-uid, OpenSSL3 interop, systemd-analyze. Not run: live systemd PID1 sandbox effects, linux/amd64, argon2 SSE4 path, SPDX validator.
Recipe + scripts: scratch area (not kept)/interop/{t/run_tests.sh,t2/*.sh,kat.py,rawclient}. KAT tests (seal NIST GCM, kdf prod-cost) exist only in the scratch copy -> promote to repo tests in L2.

| ID | Sev | Claim | Disposition |
|---|---|---|---|
| W2-I1 | cosmetic | agent rejection log ends with literal `<nil>` (server.go:288) | fix (log err only if non-nil); trivial |
| W2-I2 | low | encrypted PKCS#8 / PKCS#1 / SEC1 import gives "expected exactly one PEM block of the right type" | fix (specific message; for encrypted: decrypt first) |
| W2-I3 | low | import accepts text before the BEGIN line (pem.Decode skips leading junk); reference/err text imply "exactly one block" | decide: require prefix or document |
| W2-I4 | low doc | `import` does not create the ring (init/keygen first); userguide silent | doc/error text |
| W2-I5 | cosmetic | "mode -rwxrwxrwx" in agent dir error; doc says 0700 | fix (%04o) |
| non-defect | | OpenSSL CLI cannot verify empty message (RFC TEST 1 verified by keystore verify) | none |
| infra | | unit review [inferred]: PrivateNetwork/ProtectSystem/RuntimeDirectory interplay; user-manager sandbox needs userns | note in docs/untestable-without-x |

## Wave 2 — A3-5 CLI & operator surface (reported; no CRITICAL/HIGH/MED; documented guarantee held in every run)

| ID | Sev | Claim | Evidence | Disposition |
|---|---|---|---|---|
| W2-5-1 | LOW | SIGQUIT/SIGHUP at the passphrase prompt leave echo OFF (+ ~170-line Go traceback, exit 2 == usage code); only SIGINT/SIGTERM handled (`term.go:52`). Traceback does not contain the typed text (grep). | pty tests | fix: add SIGQUIT/SIGHUP/SIGTSTP, restore before exit; pty regression test |
| W2-5-2 | LOW | terminal escape/CR injection via echoed paths: `oneLine` strips only `\n` (main.go:94); `sign -in $'x\e[31m...\r...'` prints raw ESC/CR; log-spoofing of "verified:" lines | `od -c` | fix: escape C0/C1/DEL/CR in all echoed strings (`wrote`, `remove the plaintext file`, passfile errors) |
| W2-5-3 | LOW | exit codes undocumented; verify bad-signature exits 1 same as I/O errors; SIGQUIT exit 2 == usage | observed | fix: distinct code for bad signature + exit-code table (a behaviour change to a CLI contract -> note in docs) |
| W2-5-4 | LOW | `export-priv/export-secret > file` (shell redirect) passes terminal guard; file created at umask mode (0644 observed), plaintext key; only `-o` enforces 0600 | `ls -l` | fix: fstat stdout; refuse or fchmod 0600 if group/other bits set (scope #6 "by accident") |
| W2-5-5 | LOW | CLI never unsets KEYSTORE_PASSPHRASE / KEYSTORE_NEW_PASSPHRASE; `/usr/bin/security` child inherits them (shim ENV log) | shim logs | fix: filter env for the security child |
| W2-5-I | INFO | keychain `Get` maps any `security` failure to ErrNotFound (locked/denied mislabelled); `add-generic-password` without `-T ""` [SPECULATIVE, not tested: default ACL may let same-uid `security find-generic-password -w` read w/o prompt]; agent sets no RLIMIT_CORE/PR_SET_DUMPABLE (relies on unit/plist) [SPEC]; examples/secrets/run.sh:19 passes HMAC key on argv; passfile bare CR stripped; ambient env overrides `-passfile` even when establishing; default ring dir not tightened if pre-existing 755; import follows symlinks/FIFO | various | triage: core-dump hardening in agent = candidate fix (cheap, Linux prctl/rlimit via x/sys); others doc/ DELIBERATE |

Verified sound per A3-5: no secret on argv across 16 verbs and many flag spellings; export guards (terminal/-o /dev/tty/symlink/dir/force/0600/no tmp leftovers); passphrase source precedence + passfile checks on the open fd; keychain-set argv has no passphrase (bare -w); 3 GB stdin to sign fails at 12 MB RSS; ids validated before any file opened; no secret in error strings; examples sound except run.sh:19.

## Wave 2 — A3-2 KDF, passphrase & key lifecycle (reported; no flaw in the crypto core; nothing CRITICAL/HIGH)

| ID | Sev | Claim | Evidence | Disposition |
|---|---|---|---|---|
| W2-2-1 | MED (auditor) | Agent's `os.Unsetenv(KEYSTORE_PASSPHRASE)` does not hide the passphrase from same-uid `ps eww` / KERN_PROCARGS2 on **macOS** (decisions #25 says only Linux; userguide says "removed from its environment"); passphrase decrypts all entries offline. Only matters in env mode (shipped units/plist/examples use -passfile). **Cross-validates auditor D#3.** | `ps eww` printed the value | doc fix (both OS); code: stderr warning when agent starts with the env var set |
| W2-2-2 | LOW | ambient `KEYSTORE_PASSPHRASE` silently overrides explicit `-passfile`, incl. when establishing (`keygen -passfile strong` established under the stale env value; rc 0). Same for `KEYSTORE_NEW_PASSPHRASE`/`-new-passfile`. Contradicts spirit of decision #16 | run | fix: flag wins, or fail "both set" (**also seen by A3-5**) |
| W2-2-3 | LOW | hard kill (SIGKILL/power) leaves `.RING.*.tmp` (full encrypted ring copy, 0600) never swept; docs never say `rm`/`passwd` do not revoke earlier copies/backups or rotate private keys | re-exec kill test: leftover with new id | doc (SECURITY + userguide); optional code: sweep stale temp under lock |
| W2-2-4 | LOW | `Import` accepts inconsistent 64-byte key (**same as A3-1 F4**), misleading error | test | fix |
| W2-2-5 | INFO | keychain item no per-app isolation (no `-T ""`) [inferred]; PKCS#8 import lenient (trailing DER, RFC 8410 v2 pub ignored); 12-char minimum no quality floor, no Unicode normalisation (composed vs decomposed é differ); `Save` returns syncDir error *after* rename (op reports failure though ring changed); `add` never upgrades older entries to a newer Default cost (only `passwd`); agent sets no PR_SET_DUMPABLE/RLIMIT_CORE (**same as A3-5**) | | doc / triage |

Verified sound per A3-2: argon2id params (64MiB/t=3/p=1) vs RFC 9106/OWASP; `kdf.Derive == argon2.IDKey == C reference (argon2-cffi)`; KDF params AAD-bound (independent of derived key); `kdf.Default` unreachable from outside the module and fails closed on bad values; all randomness crypto/rand, no math/rand anywhere; passwd atomic, old passphrase verified against every entry first, fresh salt+nonce per entry, corrupt-entry case leaves ring unchanged (user must `rm` the bad entry); 6 concurrent keygen -> exactly 1 wins; no secret compare with `==`.
Known-limit refinement: emptied-ring window = time the user takes to type the passphrase (CLI decides from List() at open, verbs.go:96-100), not microseconds.

## Wave 2 — A3-3 signing agent & IPC (reported; nothing CRITICAL/HIGH; auth/lifetime/framing/Linux peercred held)

| ID | Sev | Claim | Evidence | Disposition |
|---|---|---|---|---|
| W2-3-1 | MED | `Serve` returns on ANY non-ErrClosed Accept error (server.go:179-182) incl. EMFILE/ENFILE, without closing listener/conns. Flood: agent exits 1, leaves sock+lock, key lost. **Zombie**: with one busy connection kept open the listener stays bound/backlogged, nothing accepts, key stays in memory, new clients time out until the last conn leaves. No connection-count cap. **Corroborates C#9 (reproduced now).** | `ulimit -Hn 40` flood + zomb PoC, 16 s | fix: retry temporary/EMFILE with backoff (as net/http), `Close()` on real error, optional conn cap; regression test with a Listener returning EMFILE once |
| W2-3-2 | MED | passphrase visible to same-uid on macOS via `ps eww` (3rd independent confirmation: D#3, A3-2 #1, A3-3 #2) | `ps eww` | doc (both OS) + warn/refuse env passphrase in agent |
| W2-3-3 | LOW [inferred] | no memory-protection hardening on key-holding process (no PR_SET_DUMPABLE/RLIMIT_CORE/PT_DENY_ATTACH); only unit/plist set core=0 (**3rd confirmation** with A3-2/A3-5) | grep | fix (cheap prctl/setrlimit via x/sys); note ptrace_scope |
| W2-3-4 | LOW [inferred] | library `Server` keeps the signer reference after Close/expiry; only the cmd clears the key | reading | fix (nil after wg.Wait) or document |
| W2-3-I | INFO | idle timer postponed forever by trivial `P` pings (TTL is the hard stop; `-ttl 0` = unbounded) — consider only sign resets idle; euid vs real-uid mismatch (`os.Getuid` vs peer effective uid; matters for setuid agent); `P` payload ignored (doc says empty); client prints agent-controlled error bytes raw (same-uid squatter only); no expected-pubkey pinning in client (caller must compare); checkDir stat-then-use TOCTOU via writable grandparent [theoretical, not demonstrated]; path-length error (**= W1-06**) | various | triage |

Verified sound per A3-3: peer uid checked before first read on every conn, fails closed; socket first-observed mode `Srw-------` in 40/40 trials; client has uid check + verifies every signature, all I/O deadlines; framing: uint32 length checked before make, FuzzReadFrame 3.3M execs clean, adversarial frames handled; `go test -race -count=100 ./pkg/agent` ok (215 s); 200-iteration stress, 20 clients, concurrent Close: goroutines 2->2, fds 5->5; stale Close does not remove a successor's socket; Linux SO_PEERCRED path runs in alpine container; GOOS=linux vet clean.

## Wave 2 — A3-4 ring file, locking & filesystem (reported; properties 3 and 4 held under every test; one property-7 violation)

| ID | Sev | Claim | Evidence | Disposition |
|---|---|---|---|---|
| W2-4-1 | MED | **`Parse` decodes the whole `entries` array into `[]wireEntry` (~176 B each) before validating; 16 MiB of `{}` (5.59M elements, 16,777,164 B) -> real binary `list`: max RSS 3,739,172,864 (3.7 GB), peak footprint 5.5 GB, 1.75 s, then "invalid entry id"; in-process HeapSys 5244 MiB (~328x file).** Violates scope #7 / intent of decision #6; SECURITY.md covers CPU cost, not this | `/usr/bin/time -l` on real binary + TestA34EntriesAmplification | **fix, no format change**: incremental decode (`dec.More()`) + hard entry-count cap (e.g. 4096); regression test: TotalAlloc growth < 64 MiB |
| W2-4-2 | LOW | lock file: no owner/mode check; in a shared sticky dir another user pre-creates `<ring>.lock` -> permanent "permission denied" (0600) or 10 s ErrLocked (0666 + held flock). DoS only | alpine container, uids daemon/nobody, 1777 | fix: fstat owner==euid & regular, else clear error |
| W2-4-3 | LOW | umask 0277 creates lock 0400 -> every later O_RDWR open fails until lock removed (writeTemp chmods explicitly; lock doesn't) | APFS repro | fix: Chmod 0600 after open |
| W2-4-4 | LOW | hardlink alias takes a different lock; rename breaks the link; rings diverge (lost-update race via two aliases inferred) | `ls -li` inodes differ | fix (nlink>1 refuse/warn) or doc |
| W2-4-5 | LOW | stale `.<ring>.*.tmp` after kill, never swept; existing "no temps" test injects an error in-process, not a real crash (**3rd confirmation of leftover-temp: A3-2 #3**). 600-iteration SIGKILL loop: 318 kills, 0 invariant violations, 33 stray temps | kill_loop.py | fix: sweep stale temps under lock; add real-kill test |
| W2-4-6 | LOW/INFO | exFAT: `Create` uses os.Link -> init/keygen fail ("operation not supported"; add works); bind-mounted ring file -> `add` EBUSY on rename (Docker `-v file:file`); rewrite resets mode 0660->0600 and ownership to writer euid (root rewrite locks user out [inferred]); FIFO ring path blocks forever in Open; dir-fsync error after rename reported as failure; lock held through both KDF runs: 40 concurrent `add` at real cost = 31/120 spurious ErrLocked (**same family as C#3 passwd**), no data loss | various | fix link fallback + FIFO guard; doc rest |
| W2-4-7 | INFO | base64 non-strict (padding bits, embedded \n/\r\n accepted; same bytes) — **same as A3-1 F6 / blind-implementer ambiguity** | tests | optional `Strict()`; doc |
| W2-4-8 | INFO | no warning when ring dir world-writable / not 0700; pre-existing 0777 default dir stays 0777 (**same as A3-5**) | init in 1777 dir | doc/optional warn |

Verified sound per A3-4: temp O_EXCL 0600 + chmod, all write/sync/close errors checked, fsync(file)->rename->fsync(dir); macOS durability genuinely F_FULLFSYNC (3.39 ms vs 31 µs raw fsync); ENOSPC on 64 KiB tmpfs: ring intact, 0 temps; **property 3 crash-safe: per-stage SIGKILL on real binary (5 stages) + 600 random kills, 0 violations**; **property 4: 150 rounds x 8 concurrent `add` = 1200/1200, mixed add/rm/use/passwd 150 rounds 0 lost**; size cap before read (LimitReader; /dev/zero 47 MB RSS); par/mem/time overflow/negative/float/exponent forms all rejected (no wrap); FuzzParse 4 min 34.6M execs clean; APFS case-insensitive spellings share one lock.

## Finding-skeptic S5 (simplify/dedup) — REPORTED
Verdicts (skeptic ran full suite on the batch: 18/18 -race, golden sha256 unchanged, staticcheck/deadcode clean):
- DO: W1-08 (RuneCount; 0 mismatches / ~3M inputs; drops uncleared string copy), W1-13c (keychain id-rule text -> wrap ids.ErrBadID; 0 LOC), W1-14 (agent: ExportPrivate directly; -1 LOC), W1-18 rand.go seam delete (-5 LOC).
- SKIP (not worth the diff): W1-13a/b/d, W1-15 (rand.Read error branches dead but fail-closed; kdf.New signature change not worth it), W1-16 (capped-read helper ~0 LOC; write ladder -5 LOC untestable on failure paths), W1-17 (LOCK_UN redundant but harmless margin vs inherited fd), W1-19 (keep public API).
- OPTIONAL: W1-12 (six run_test.go -> one table test, -105 LOC; loses per-example `go test ./examples/<n>` selectivity) — I will skip per least-code unless owner wants it.
Batch branch: `fix/W1-s5-small-cleanups` (W1-08, W1-13c, W1-14, W1-18 seam).

## Finding-skeptic S1 (agent cluster) — REPORTED (workdir scratch area (not kept)/skeptic/s1; tests in pkg/agent/zz_skeptic_test.go, fix sketches in its server.go)
| ID | Skeptic verdict | Sev | Fix | Owner confirm |
|---|---|---|---|---|
| W1-01 neg ttl/idle | CONFIRMED (both flags; alive & signing after 3-4 s) | MEDIUM (same-uid/operator misconfig) | reject TTL<0\|\|Idle<0 at top of Serve (4 LOC) + fail-fast in cmd before unlock (3 LOC) | N |
| W1-04 umask race | CONFIRMED (round 0, 4 concurrent Listen) | LOW (embedder only; fails closed) | delete the Umask dance in listenLocked, keep Chmod (checkDir already requires 0700 owned dir) (-3 LOC) | Y small (drops defense-in-depth) |
| W1-06 long socket path | CONFIRMED (142-byte path: "bind: invalid argument", .lock left) | LOW | length check before lock open (3 LOC) | N |
| W1-09/W2-3-1 accept EMFILE | CONFIRMED exit+stale files (ulimit -n 20 flood; deterministic RLIMIT test fails pre-fix); zombie variant PLAUSIBLE not run | LOW (was MED: same-uid can kill agent) | EMFILE/ENFILE -> log, sleep 50ms, continue; other err -> s.Close() before return (~6 LOC) | N |
| W2-3-1 conn cap | REFUTED as defect | | none | |
| W2-3-3 core dump/dumpable | REFUTED INFO (Go does not dump core by default: SEGV with ulimit -c unlimited -> 0 cores on macOS; Linux not run) | INFO | none | |
| W2-3-4 signer ref | REFUTED INFO (cmd clears; nil-ing zeroes nothing) | | 1 doc sentence at most | |
| W2-3-I idle by P / P payload | REFUTED (documented 'successful request'; no doc says empty payload) | | none | |
| W2-3-I euid vs uid | INFO | | optional Geteuid in 2 sites | N |
| W2-3-I raw agent error bytes | PLAUSIBLE LOW (needs same-uid squatter) | LOW | `%s`->`%q` at client.go roundTrip (1 char; not run) | N |
| checkDir TOCTOU | INFO theoretical | | none | |
| env passphrase (W1-D3=W2-2-1=W2-3-2) | CONFIRMED macOS `ps eww` + Linux /proc/PID/environ; `-passfile` avoids (0 hits both OS); all shipped unit/plist/example use -passfile | LOW (was MED) | DOC ONLY: reword main.go header, decisions #25, SECURITY known-limit "use -passfile for the agent"; optional 2-LOC stderr warning; keep Unsetenv | Y (wording) |
Note: skeptic's own long-path test asserts "too long" but message says "limit" — test string to be fixed when I write the real test.

## Finding-skeptic S3 (CLI/passphrase) — REPORTED (8 regression tests exist in scratch area (not kept)/skeptic/s3: cmd/keystore/w3_test.go, internal/passphrase/w3_test.go, pkg/agent/w3_test.go)
| ID | Verdict | Sev | Fix | Owner confirm |
|---|---|---|---|---|
| W2-5-1 term signals | CONFIRMED (SIGQUIT: echo stays off, exit 2, 16 KB traceback; SIGHUP: echo off) | LOW | add SIGQUIT,SIGHUP to Notify (term.go:52) — NOT SIGTSTP; pty test | N |
| W2-5-2 escape injection | CONFIRMED (od -c) | INFO/LOW | `oneLine`: strings.Map(unicode.IsControl -> ' ') (~6 LOC), error paths only | N |
| W2-5-3 bad-sig exit code | CONFIRMED | LOW | exit 3 for errBadSig + userguide exit-code table (~10 LOC) | **Y (contract)** |
| W2-5-4 redirect export | CONFIRMED (0644) | LOW | **refuse** when stdout is a regular file with mode&077!=0 (guardTerminal, ~6 LOC; `-force` bypass like terminal guard); `\| tee` uncovered | **Y (behaviour)** |
| W2-5-5 env to security child | CONFIRMED mechanically, DOWNGRADED INFO (Apple binary, same uid, no new attacker position) | INFO | none (opt 4 LOC) | N |
| W2-5-I | partly confirmed / `-T ""` untested | INFO | doc/DELIBERATE | N |
| W2-2-2 env shadows -passfile | CONFIRMED | LOW | keep documented precedence + one-line stderr notice when explicit passfile shadowed (~8 LOC; honours decision #16 intent) | N for notice |
| W1-07 keygen empty ring | CONFIRMED, DOWNGRADED INFO (same state as `init`) | INFO | doc only | N |
| W1-08 RuneCount | CONFIRMED | INFO/LOW | 1 LOC (S5 also confirmed) | N |
| W1-11 uncapped reads | CONFIRMED (1 GiB sparse -sig = ~2 GB RSS, -pub ~1.1 GB) | LOW | `readLimited(path, 64<<10)` at sign.go:79,:124 (2 LOC) | N |
| W1-10 tty secret cap | CONFIRMED UX hang (tty canonical line cap ~1024 B; 1000-byte secret hangs) | INFO | userguide sentence (use -in/stdin; ~768 B typed limit) | N |
| W2-I1/I5 | CONFIRMED cosmetic | | reject log without `<nil>`; dir mode `%04o` (~6 LOC) | N |
| W2-I2 | CONFIRMED low | | name the PEM block type in the error (~4 LOC) | N |
| W2-I3 | CONFIRMED, LEAVE (tightening breaks `openssl pkcs12` "Bag Attributes" output) | | doc | N |
| W2-I4 | CONFIRMED doc | | userguide: import needs the ring to exist | N |
| W2-1-F1 pub swap | CONFIRMED, doc-only (writer could replace whole ring; `export-pub` cannot authenticate by design; signing fails closed) | LOW code / MED doc gap | doc: publish pubkey at provisioning, verify via sign+verify, record fingerprints; optional verified export ~10 LOC | N |

## Finding-skeptic S4 (crypto/format/docs) — REPORTED
All crypto claims reproduce. Key results (each [V] by the skeptic):
- W1-D1 CONFIRMED (LOW as code / MED as doc falsehood): `current` edit k1->k2 then `sign` (no -id) signs with k2, exit 0, prints only "wrote s2.sig"; entry delete/reorder accepted; rollback restores a removed key AND the old passphrase (restored backup undoes a `passwd`) [the passwd+restore pair is inferred]. "One named error" in scope #2 is false as worded: out-of-range/malformed fields fail at PARSE with ErrBadFormat; AEAD-bound fields fail at unlock with ErrBadPass; any bad entry makes the whole ring unreadable.
- W2-1-F2 CONFIRMED LOW (same-id+kind entry from ring A unlocks in B; cross-id fails; gain mostly DoS unless a verifier trusts both keys). F3 CONFIRMED LOW. Both doc-only.
- **F5 CONFIRMED as overstatement**: forged 1 GiB/t=64 entry costs ~54-57 s and ~1.1-1.2 GB RSS per command, not hours; `add` unlocks Entries[0] only; `passwd` stops at first failing entry; list/export-pub/use/rm do no KDF.
- F1 CONFIRMED LOW-MED: only case giving more than DoS (ring-writer swaps `pub`; if operator later runs `export-pub` and publishes, verifiers trust attacker). examples/provision & ci-release take the pub from keygen output (safe flow) but provision README says export-pub (fix wording).
- F6/B1/B2 doc facts: base64 pad bits unchecked, CR/LF inside values ignored; PKCS#8 trailing bytes ignored post-auth; JSON keys case-insensitive, duplicate key = last wins, null == absent, `{"magic":"keystore/v1"}` is a valid empty ring; secret `pub` absent/""/null all accepted (ledger's "CLI rejects \"\"" was WRONG at parse); "newer" rule = Atoi of text after `keystore/v` (v2,v10,v02,v+2 newer; v01,v0 not); 16 MiB exact accepted; `created` T/Z uppercase, offsets normalised, fractions dropped, year 0..9999 after UTC.
- A4-1 CONFIRMED (CI `|| true` never fails; 'Executable path' filter does not match systemd 257 wording; unknown key/bad value only warn rc 0): tested replacement step. A4-2 DOWNGRADED (add `permissions: contents: read` instead of SHA pins). A4-4 DOWNGRADED.
- W1-D4 CONFIRMED: archives differ run to run (SBOM date, tar mtimes, gzip header); binaries identical -> reword README now, leave build script (release work paused).
- W1-D2/D3/D5/D6-10 CONFIRMED doc fixes (exact texts supplied by skeptic).

**v2 format analysis (skeptic):** ring_id in AAD ~30-50 LOC (new magic, golden+v1 reader, migration verb) stops cross-ring transplant only; keyed MAC over current+set+order ~150-250 LOC, needs passphrase for `use`/`rm` (changes CLI model), still no passphrase-free verification; rollback counter needs external state (different feature). **Recommendation: no v2 for this.** Docs made true + `sign` prints signing key fingerprint on stderr + optional `-expect-fp`. If a v2 is ever cut for another reason, add ring_id then; do not add the MAC.
=> DECISION Q1 resolves to NO FORMAT CHANGE (I follow the skeptic; surfaced to the user in the final report rather than blocking). `-expect-fp` is a new CLI flag: implement with the fingerprint print (14 LOC), flag in report.

## Finding-skeptic S2 (ring file/library) — REPORTED (copy: scratch area (not kept)/skeptic/s2; fix sketch + tests: ringfile.go, amp_test.go, ring.go)
| ID | Verdict | Sev | Fix |
|---|---|---|---|
| W2-4-1 Parse amplification | CONFIRMED: 16,770,048-byte ring of 5.59M `{}` -> `list` max RSS 3.85 GB, 2.89 s; with fix 67 MB, 0.57 s; TotalAlloc 7065 -> 48 MiB | LOW-MED | incremental decode (wireEntries.UnmarshalJSON with dec.More(), decodeEntry per entry, dup-id check) +28/-16 LOC. **NO hard entry cap**: largest valid ring = 48,661 entries ~128 MiB; a cap would reject rings accepted today (owner decision if wanted). Test threshold 64 MiB tight -> use 96 MiB |
| W2-4-2 foreign lock file | DOWNGRADED INFO (owner check only improves the message; attacker can equally block via the ring path) | | doc sentence: don't keep a ring in a dir other users can write |
| W2-4-3 umask 0277 lock 0400 | CONFIRMED INFO | | `fh.Chmod(0o600)` after open in Lock (2 LOC, optional) |
| W2-4-4 hardlink alias | CONFIRMED INFO (inherent to atomic rename) | | doc: use a symlink, not a hardlink |
| W2-4-5+W2-2-3 stale temp | CONFIRMED LOW/INFO (288 kills -> 8 stray temps, ring intact) | | DOC: rm/passwd do not revoke earlier copies (backups, crash temp files); rotate the keys. No sweep (deleting files in the user's dir) |
| W2-4-6 | exFAT Create/link CONFIRMED; bind-mount EBUSY CONFIRMED; mode reset CONFIRMED (deliberate 0600); ownership reset PLAUSIBLE; FIFO blocks forever CONFIRMED; dir-fsync-after-rename reports failure though committed CONFIRMED (dir mode 0300) | LOW/INFO | doc (needs hardlink-capable FS; ring must not be a mount point; mode policy); FIFO guard 4 LOC optional; dir-fsync: wrap as "committed but not synced" 3 LOC (owner-confirm) |
| W1-03 passwd lock | CONFIRMED (40 entries 10.8 s; writer ErrLocked at 10.0 s; ~0.29 s/entry) | LOW availability | DOC the limit; optimistic scheme not worth it (25-40 LOC); do not lower KDF |
| W1-02 empty passphrase | CONFIRMED | LOW | 3 LOC in `add` (covers Add/AddSecret/Import/ImportSecret) |
| W2-1-F4 + W2-2-4 Import mismatch | CONFIRMED | LOW | 3 LOC in Import with its own error |
| W1-05 race | CONFIRMED | MINOR | doc: Keystore not safe for concurrent use |

## STATUS CHECKPOINT (2026-10-19) — fix pipeline
MERGED to main (each with a skeptic FIXED-VERIFIED recorded in its merge commit; `git log --merges --oneline`):
W1-01 neg ttl/idle · W1-09 accept errors/EMFILE · W2-5-1 prompt signals · W1-02 empty passphrase (library) · W2-4-1 Parse streaming decode ·
W1-11 verify input caps · DOC1 trust-model docs (decision 39) · DOC2 userguide/agent-protocol/README drift · W2-1-F4 Import consistency ·
W1-s5 cleanups (RuneCount, keychain err text, agent ExportPrivate, rand.go) · W1-04 Listen umask mutex · W2-5-2 term.Clean sanitiser (4 skeptic rounds) ·
W2-5-4 refuse export > loose file (behaviour change; owner confirm in report) · W1-06 socket path length · W2-I agent log/err messages.
IN FLIGHT: W2-2-2 shadowed passfile (round-2 skeptic running; behaviour change: establishing refuses, decision 40) ·
W2-5-3 verify exit code 3 (branch fix/W2-5-3-badsig-exit-code, worktree fx/W2-5-3, no skeptic yet; behaviour change).
NOT YET WRITTEN: W1-D1 `sign` prints signing-key fingerprint + `-expect-fp` (new flag) · W2-I2 PEM import error text ·
W2-4-3 lock file chmod 0600 · A4-1 CI systemd step `|| true` + `permissions: contents: read` · docs sync: userguide sentence for sanitiser,
README internal/term row, exit 3 (in branch), shadow rule (in branch) · optional: FIFO guard, dir-fsync-after-rename wording.
DECISIONS TAKEN WITHOUT BLOCKING (report to owner): no ring-format change (decision 39); refuse-not-chmod for redirected export;
establish-refuses for shadowed passfile; exit code 3; -expect-fp new flag (pending).
REMAINING WAVES: A5 silent degradation · A6 format compat (goldens + docs gaps already found by blind implementer) ·
L1 verification/optimization · L2 test/bench/fuzz/harden (ledger, clock seam, fake keychain, KAT tests promoted from scratch,
mutation of security tests, benches) · L3 live (keychain gated; Linux container; OpenSSL) · L3b real-topology (SIGKILL loop, cross-process
contention, cross-uid, fleet sim) · A7 gap audit · closing docs/audits/* deliverables + open-items. L4 NOT done (held).
Scratch tooling: scratch area (not kept)/gate.sh, fix-skeptic-contract.md, fixer-contract.md, docs-spec.md, interop recipe scratch area (not kept)/interop/.
