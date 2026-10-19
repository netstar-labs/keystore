# Verification and optimization (L1)

Subject: `main` at `c37f379` (read-only; all experiments ran on a copy with added test files, which were
not kept). GOWORK=off, go1.27.2 darwin/arm64, Apple `container` linux/arm64. This page is the report as
written; the status table below says what became of each finding. Where the report names scratch files
(scripts, logs, benchmark outputs) they were session scratch and are not kept; the numbers in the text are
what remains.
Labels: [V] = the auditor ran it and saw it; [I] = inferred.
Caveat on all timings [V]: the host load average was 52-58 on 8 cores (other agents running suites and benchmarks) for the whole session. Allocation counts and scaling ratios are reliable; absolute ns/op are inflated 1-3x (the count=10 batch ran ~2x slower than the count=5 batch). Re-measure on a quiet machine before quoting any figure.

## Executive summary
- No critical or high defect found. Suite green everywhere (macOS race, Linux arm64 root and non-root); 0 data races; 2 fuzz targets x 60 s clean (3.3M and 3.5M execs); no goroutine or fd leaks; no stray files after any of 24 failing-verb paths except the already-known empty ring after a failed first `keygen` (W1-07).
- Real findings are all LOW/INFO: (1) duplicate-`entries`-key CPU/garbage amplification in Parse, (2) one unreachable error branch in Parse, (3) agent allocates the claimed frame length (up to 1 MiB) from a 5-byte header, (4) SIGHUP kills the agent leaving socket+lock (self-heals), (5) coverage gaps listed below (defer to L2).
- Performance: nothing worth doing. argon2id (133 ms, 64 MiB, per unlock) is 3 orders of magnitude above everything else a command does; Parse of a normal ring is ~7 us, ring Save is 9-10 ms (fsync). Scaling is linear everywhere (no O(n^2)).

## Status after the audit

| # | Finding | Status |
|---|---|---|
| 1 | duplicate `entries` keys amplify CPU and garbage in `Parse` (16 MiB accepted, 1.93 s, 786 MiB TotalAlloc) | **Fixed**, merge `b04b179`: a second `entries` key rejects the ring (decision 41); 786 MiB -> 48 MiB [R: merge message] |
| 2 | the agent allocates the claimed frame length from a 5-byte header (697 stalled connections: +698 MiB) | **Fixed**, merge `d4be234`: frame bodies are read incrementally; 700 stalled claims of 1 MiB: +642 MiB -> +9 MiB on a real agent [R: merge message]; accepted cost about 0.6 ms and 1.2 MiB extra garbage per 1 MiB frame |
| 3 | `ringfile.go` trailing-data branch unreachable | **Kept and commented** (audit A7 G7; [gap-audit.md](gap-audit.md)) |
| 4 | SIGHUP terminates the agent leaving socket and lock | **Fixed**, merge `58408dc`: SIGHUP is a clean stop, exit 0, unless inherited as ignored |
| 5 | failed first `keygen` leaves an empty ring (W1-07) | Documented, not fixed |
| 6 | test gaps (agent client invalid-signature and uid-mismatch refusals, `writeTemp` failure cleanup, `Listen` error cleanup, no fuzz for PEM, base64 secret, passfile, signature reader; `ErrNegativeLifetime` matched by string) | Addressed by the L2 pass: see [test-ledger.md](test-ledger.md). Fuzz targets went from 2 to 10 |
| - | `TestGetMissing` runs the real `security(1)` (found later by A7) | **Deleted**, merge `1d06882` |
| - | optimization candidates (Parse allocation, a persistent agent connection) | **None taken** (rationale in "Phase 5"); the KDF cost is deliberate and was never lowered |

## Phase 1
### 1.1 Doc vs code (changes since audit + random sample)
Sampled 27 claims from SECURITY.md, userguide, README, decisions; ran each against built binaries (script (scratch, not kept), output (scratch, not kept)) [V]. All hold: ring/lock/p-file modes 0600 and rewrite resets 0664 to 0600; passfile 0644 refused; 12 chars counted as characters (12 x 'é' accepted, 11 refused); twelve spaces accepted (as SECURITY.md says); CRLF passfile trimmed; verify exit 0/3/2; `sign -expect-fp` mismatch refused; sign 1 MiB ok / +1 refused; export-priv to loose file refused, -o is 0600, existing -o refused, pipe allowed; env shadows -passfile with notice; `keygen` into empty ring refuses when env and -passfile both set (decision 40); `passwd` with env set uses env as old and -new-passfile as new (consistent); symlinked ring stays a symlink after write; `.lock` symlink refused (O_NOFOLLOW, victim not created); `list` on a forged 1 GiB/64-pass ring 0.00 s, `export-pub/use/rm` 0.08 s (no KDF, as documented); ErrLocked after exactly 10 s; agent socket and .lock 0600; sign via agent verifies; agent env passphrase visible to `ps eww` (documented); control characters in ring/-in/-o paths are replaced by spaces in messages (W2-5-2, od -c); agent default ttl 8h / idle 30m (from -h). Timing claim "0.1-0.3 s per derivation": 133 ms measured (quiet moment) [V]. Doc drift found: none.
Platform claim "macOS and Linux": darwin/linux x amd64/arm64 all build and vet [V]; freebsd does not compile (internal/term lacks ioctl consts) [V], consistent with README but see dead-stub note.
Comment sample: Parse doc says "trailing data ... ErrBadFormat" - true, but see 1.2 (the branch that implements it is unreachable; the earlier peek Unmarshal rejects trailing data first).
### 1.2 Dead code
- `go vet` clean on darwin and linux; `staticcheck ./...` clean (darwin, linux); `deadcode -test ./...` empty; plain `deadcode ./...`: only `Keystore.Path` (public API, W1-19 keep) [V]. On GOOS=linux plain deadcode also lists `keychain.checkService` (used by the darwin file only; not dead).
- Unreachable branch [V coverage 0 + I reasoning]: internal/ringfile/ringfile.go:179-181 (`dec.Token() != io.EOF -> ErrBadFormat // trailing data`). The peek `json.Unmarshal(b,&peek)` at the top already rejects any trailing bytes, so this cannot fire. Harmless defence in depth; remove or comment. Effort: 3 lines.
- peercred_other.go and keychain_other.go ("!linux && !darwin" stubs) are never built on a supported platform and the module does not compile elsewhere anyway (internal/term, freebsd [V]). Remove or keep as intent; INFO.
- Sentinel errors: every exported sentinel is returned; most are matched only by library callers or tests. `pkg/agent.ErrNegativeLifetime`: no test uses errors.Is (the two tests match on the substring "negative"); INFO. peercred/keychain `ErrUnsupported` reachable only on unsupported OSes.
- govulncheck: 0 affecting; 1 module-level advisory GO-2026-5932 (x/crypto/openpgp, not imported) [V].
### 1.3 New duplication from the fixes
Only: the "read up to limit+1, error if over" idiom now exists in readLimited (cmd/keystore/secrets.go), readMessage (sign.go), readPassfile, ringfile.Read (4 copies, 4-6 lines each, different error texts/limits; least-code: leave, S5 already decided). Parse now decodes the document three times (peek, decode, and Marshal re-parses its own output by design, decision 34); intentional.

## Phase 3
### 3.1 Race suite [V] (`go test -race -count=1 -v ./...`, 29.6 s wall)
228 test runs (incl. subtests), 228 pass, 0 fail, 0 skip, no "data race". Per package: cmd/keystore 8.5 s, cmd/keystore-agent 4.7, examples/agent-service 11.1, ci-release 6.9, provision 5.5, rotation 5.5, secrets 8.5, signed-requests 9.0, internal/ids 2.2, kdf 2.1, keychain 2.1, passphrase 1.7, peercred 1.9, ringfile 17.3, seal 4.9, term 4.5, pkg/agent 7.4, pkg/keystore 19.8. `-race -count=3` on pkg/agent, internal/ringfile, cmd/*: all ok (8.7/37.7/18.2/11.7 s). `-race -cpu 1,4 -count=2 -shuffle=on` on pkg/agent and ringfile: ok (ringfile 232 s under load; note it is slow at -cpu 1). A wider `-cpu 1,2,4` run hit go's default 10 min timeout (ringfile 601 s) because my added zz tests were included under load; not a failure of the suite.
### Coverage [V] (`go test -cover`)
cmd/keystore 83.8 (in-process only), keystore-agent 91.2, secrets 65.7, signed-requests 79.8, ids 100, kdf 90.0, keychain 70.6, passphrase 91.5, peercred 75.0, ringfile 88.4, seal 86.8, term 54.5, pkg/agent 88.5, pkg/keystore 90.2.
Uncovered statements in security-relevant packages (go tool cover -func + profile; all are error returns unless noted):
- seal: Seal rand/newGCM errors (55,59), Open newGCM err (71), newGCM bad key length (82) and aes error (86).
- kdf: New rand error (59). 
- ringfile: 180 (unreachable, above); Marshal/marshal error returns (242,262); Read 271,276; Create 287,291,298; Update 312,321,327; Save 359; writeTemp 373,382,385,391,394 (write/chmod/sync failure cleanup); syncDir 403; Lock 424 (non-EWOULDBLOCK flock error close). The ENOSPC/IO-failure cleanup of writeTemp is therefore not exercised in-tree (A3-4 tested it by hand on a 64 KiB tmpfs).
- pkg/keystore: Fingerprint marshal err, publicFromSPKI non-ed25519 (70,74), PEM marshal errors, parsePKCS8 non-PKCS8/non-ed25519 (82,86), Import non-ed25519 length (100), OpenOrCreate race branch (66), ChangePassphrase mid-loop (189), Secret ErrNoKey (secret.go:54), signer.go:31,37.
- pkg/agent: client.go:37 (bad pubkey from agent), **client.go:61 (agent returns an invalid signature; the documented "verifies every signature" defence)**, **client.go:77 (peer uid mismatch refusal on the client)**, client.go:81; frame.go:46 (writeFrame ErrTooLarge); server.go:107,114,134-151 (Listen error paths), 164 (dir not owned), 218 (accept raced shutdown), 286, 296, 345 (sign failed reply), 355, 359 (default switch).
- passphrase: 104 (clear on mismatch repeat), 115, 178, 187 (passfile owned by other uid), 191.
- term.ReadPassword 0% (needs a pty; exercised only by the CLI pty tests in subprocess, which -cover does not attribute); peercred.UID/peerUID 75% (mismatch path).
These belong to L2; the two named in bold are documented security properties with no test of the failing side.
### 3.2 Benchmarks [V]
No pre-existing Benchmark functions in the repo. I wrote ad-hoc ones (zz_bench_test.go in the scratch copy). Results (median of count=5, loaded host; spread in (scratch, not kept), count=10 in (scratch, not kept), summariser (scratch, not kept)):
| bench | median | allocs |
|---|---|---|
| argon2id production cost (64 MiB, t=3, p=1) | 133 ms (min 132.5, max 135.4, cv 0.8%) | 67.1 MB, 31 allocs |
| Parse 1 / 100 / 10,000 entries | 7.0 us / 0.52 ms / 47.7 ms | 4.9 KB 33 / 252 KB 1049 / 32.5 MB 100,302 |
| Marshal (incl. validating re-Parse) 1/100/10k | 8.8 us / 0.61 ms / 58.6 ms | 6.2 KB / 376 KB / 69 MB |
| Read (file+Parse) 1/100/10k | 23 us / 0.51 ms / 48 ms | 6.5 KB / 350 KB / 42.8 MB |
| keystore Open+List 100/2000/10k | 1.36 / 25.8 / 91 ms | 0.4 / 8.0 / 47.9 MB |
| ringfile.Save 1 / 100 entries (fsync+rename+dir fsync) | 10.3 / 10.4 ms | 7.7 KB / 393 KB |
| ringfile.Update (lock+read+save) 1 entry | 12.1 ms | 18 KB |
| Lock+unlock | 30 us | 312 B 5 |
| seal 48 B / 1 KiB / 64 KiB; open same | 1.3 / 1.6 / 28 us; 0.76 / 1.25 / 27.6 us | 4 / 3 allocs |
| ed25519 sign direct | 43 us (loaded; ~30 us min) | 1 alloc |
| sign via ring Signer | 53 us | 1 alloc |
| sign via agent, new connection per Sign (Client.Sign), 1 / 8 / 64 concurrent clients | 181 / 64 / 63 us per op (about 5.5k / 15.6k / 15.8k sign/s) | 35 allocs, 2.7 KB |
| sign via agent, persistent connection (raw frames) | 53 us | 7 allocs, 762 B |
| frame write+read 256 B | 0.8 us | 5 allocs |
Keystore.Add at production cost: median 657 ms per call on a ring that already has entries (checkPassphrase derive + encrypt derive = 2 x ~133 ms + ~10 ms write; spread 523-907 ms under load); Signer() 1 derive (~133 ms quiet; my first Signer bench is skewed by an un-reset setup Add, discard it).
High-variance (cv > 10%) benchmarks are all load artefacts (host load ~57); no benchmark has a quiet-machine cv figure.
CPU/memory bound: Parse/Marshal/Read are allocation-bound (json decoding); KDF is memory-bandwidth bound; seal is CPU-bound AES-GCM.
### 3.3 Fuzz [V] (-fuzztime=60s each)
FuzzParse (internal/ringfile): 3,317,106 execs, corpus 617 (4 new interesting), PASS, no crash. FuzzReadFrame (pkg/agent): 3,463,201 execs, 8 inputs, PASS. Only two fuzz targets exist (grep 'func Fuzz'). Not fuzzed (no target): base64 secret decode, passfile reader, PEM parse (ParsePublicKeyPEM / import), ids.Valid, signature file reader. Defer to L2.
### 3.4 Integration [V]
No build-tagged integration tests (only !linux&&!darwin stubs carry tags). The examples' run.sh scripts run through `go test ./examples/...` (6 packages, each builds the binaries and runs the shell scenario; 5-11 s each) and passed with and without -race. Linux container (alpine, linux/arm64, cross-compiled `go test -c` per package, recipe from interop/t/run_tests.sh, Go toolchain mounted for the examples, -mod=vendor): every one of 18 test binaries rc=0 as root AND as uid 1000, 0 skips, 2m total [V]. Not run on Linux: -race (cross-compiled without cgo), keychain (darwin-only; the darwin test file runs on the host), peer-uid mismatch with a real second uid (client.go:77; the server side is covered by an injected uidOf only).
### 3.5 Race detector: see 3.1. Confidence in goroutine safety: high [V for the tests that exist; goroutine inventory below is [I]/read].
### 3.6.1 Input boundaries [V]
| boundary | nil/empty | truncated | oversize | duplicate | bad encoding | numeric limits |
|---|---|---|---|---|---|---|
| ring JSON (Parse) | err | err (fuzz, tests) | MaxSize 16 MiB; table below | dup ids rejected; dup JSON keys: last wins (documented F7) | bad base64/UTF-8 rejected | par 256/-1/1.5/"1" err; par 0,17 err; par 16 ok; mem 2^32 err, 2^32-1 err, 1048576 ok, 1048577 err; time 2^32 err, 65 err, 0 err; 8192.0 and 8.192e3 rejected |
| created time | | | | | 24:00, month 13 rejected | year 0 and 9999 ok at UTC; 10000, and offsets that normalise outside 0-9999 rejected; Marshal round-trips every accepted value |
| frame (readFrame) | EOF err | short header/body err | >1 MiB ErrTooLarge before allocating (uint32 max tested by the seed) | n/a | n/a | fuzz round-trip holds |
| PEM / passfile / secrets / ids | covered by unit tests (cmd, keystore, passphrase, ids); passfile cap 4096, secret cap base64(MaxSecretSize)+2, -pub/-sig 64 KiB, message 1 MiB, term line MaxLen |  |  |  |  |  |
Parse resource profile at the 16 MiB limit (TotalAlloc, one run, not peak RSS; test TestL1Amplification):
nested arrays 4 ms/16 MB; nested objects 6 ms/16 MB; 5.6M empty objects 1.2 s/48 MB, rejected at entry 0; one 16 MB unknown field 0.44 s/80 MB; 16 MB id 0.54 s/96 MB; 12 MB base64 ct 20 ms/16 MB; 37,530 valid entries (13.9 MB) 0.5 s/90 MB, accepted; whitespace padding 34 ms/48 MB; **1.29M repeated `"entries":[],` keys 1.93 s/786 MiB, ACCEPTED (err=nil)**. The W2-4-1 fix holds (the 3.7 GB RSS case is now 48 MB).
### 3.6.2 Error handling
Writers: writeTemp, writeNew, replace check Write/Sync/Close and remove partial files [V read]. Discarded Close errors are on read paths, lock files and failure cleanup only. Strings are matched only in tests; production code uses errors.Is. Error-path coverage: see uncovered list (ringfile and agent Listen cleanup paths are the notable untested ones).
### 3.6.3 Concurrency
Goroutine spawns (4 in non-test code) [V read]: agent per-connection handler (tracked by WaitGroup, closed by Close/stop), agent `watch` (stopped by close(stop), Serve defers wg.Wait then close(stop)), cmd/keystore-agent signal goroutine (process-lifetime), term.restoreOnSignal (stopped by returned stop()). No channels are closed by more than one party (the only close is stop). s.mu is never held across I/O (Close closes conns after unlocking). Lock order: only umaskMu then nothing; s.mu leaf. Goroutine/fd leak test [V]: 20 start/serve/abandon/close cycles with 5 hostile connections each (idle, half header, oversize header, partial body) plus 10 TTL-expiry cycles: goroutines 2->2, fds 5->5 (runtime.NumGoroutine and /dev/fd, under -race).
### 3.6.4 Resources and cleanup [V]
Script (scratch, not kept) runs 26 failing verb invocations in fresh dirs and diffs the directory (output (scratch, not kept)): wrong passphrase, duplicate id, missing ring, bad PEM, bad base64, rm/use missing, rm last signer, passwd wrong old/short new, oversize/overwrite sign and exports, corrupt ring, init over existing, agent with wrong passphrase / 0755 socket dir / 163-byte path / negative ttl / missing key. Result: zero stray temp, lock, or socket files. Only residue: `keygen` that fails on passphrase length or id validation leaves an empty 63-byte ring (known W1-07, "doc only"; also after the decision-40 refusal). Agent stop: SIGTERM/SIGINT remove the socket and leave `<sock>.lock` (documented in userguide); SIGKILL leaves socket+lock, restart over them succeeds; **SIGHUP exits 129 leaving socket+lock (fixed; see status table row 4)** (not handled; self-heals on restart; key dies with the process) [V].
fd and memory limits on untrusted input [V]: Parse capped 16 MiB (above); frame 1 MiB; passfile 4 KiB; base64 secret and verify inputs capped. Slow clients: IOTimeout 5 s per request; an idle connection that sends nothing is dropped after 5 s; but a client can hold a connection indefinitely with valid requests (documented, TTL is the stop). Stalled conn test: 697 connections each sending a 5-byte header claiming 1 MiB and nothing more: +697 goroutines, **HeapAlloc +698 MiB** (readFrame does `make([]byte,n)` before reading the body), legitimate sign during the stall still 1.07 ms, all released after IOTimeout. Connection count is bounded only by the listen backlog (~697 reached before ECONNREFUSED) and the fd limit; same-uid only.
### 3.6.5 Integer overflow / truncation [V read + tests]
All integer conversions in non-test code: seal.go `uint32(len(v))` (len bounded by 16 MiB ring), `uint32(p.Par)` (widening), frame.go `uint32(len(p))` after the MaxPayload check, secrets.go int64 widenings. JSON uint8/uint32 fields reject out-of-range and fractional/exponent numbers (table above); Check() is the only gate before Derive and Derive re-checks. No truncating conversion of untrusted data found. Time: RFC 3339 range and UTC normalisation tested at both ends; Marshal re-parse guarantees no write of an unreadable ring.
### 3.6.6 DoS
No regexp anywhere. KDF bounds enforced before any work (mem 8 MiB..1 GiB, t 1..64, p 1..16, salt 16); worst forged entry is ~1 min / 1.1 GB per unlocking command (S4 measured; SECURITY.md says the same), `list/export-pub/use/rm` run no KDF [V above]. Parse: linear (benchmarks: 100x entries -> 92x time, 20x -> 19x for List); one superlinear-looking input found (duplicate keys, below). No rate limiting on the agent beyond uid check (by design, same-uid). passwd holds the lock for 2N derivations (known W1-03, documented).

## Phase 4 profiling [V]
CPU profile of Parse at 10,000 entries (40 iterations): time is spread over encoding/json (ConsumeSimpleString 15%, consumeObject/consumeValue 30% cum, wireEntries.UnmarshalJSON 32% cum) plus GC/madvise ~25% (alloc churn). Alloc profile: json decoderState.fetch 50% (the per-call Decoder copies the array text), wireEntries.UnmarshalJSON 35%, x509.ParsePKIXPublicKey 7%. No application-level hotspot; it is the standard-library JSON decoder.
Scaling (benchmark at two sizes): Parse 100->10,000 entries: 0.516 ms -> 47.7 ms = 92x for 100x (linear); Read 0.51 -> 48 ms; Marshal 0.61 -> 58.6 ms; List 2,000 -> 10,000: 25.8 -> 91 ms (3.5x for 5x). No O(n^2).
Memory ratio: Parse allocates ~15x the file size (32.5 MB for 2.2 MB); worst case at the 16 MiB cap is ~90 MB (measured), garbage not retained.
Agent: per-Sign cost with a fresh connection is 181 us, of which ~130 us is connect+uid check+accept/goroutine start (persistent connection: 53 us); ed25519 itself 30-43 us. Throughput saturates at ~15.6k sign/s with 8 clients (8 cores), flat to 64 clients (no contention collapse; p99 not measured).
Save: 9-10 ms regardless of ring size (1 vs 100 entries) = dominated by F_FULLFSYNC on darwin; correct and intended.

## Phase 5 optimization candidates
Nothing worth doing. Rationale with numbers: a real command = one KDF (133 ms) + one Read (<0.1 ms for typical rings) + at most one Save (10 ms). Candidates considered, none implemented because none clears the bar:
1. Parse allocation (json decoder fetch copy, ~50% of Parse bytes): would save at most a few MB at 10k entries; Parse of a 1-10 entry ring is 7-15 us against a 133 ms KDF (<0.01%). [I, profile-based; not prototyped, no measured gain claimed.] Counter-argument: complexity in the security-critical parser for no observable benefit.
2. Persistent client connection in agent.Client: measured upper bound 181 -> 53 us per Sign (3.4x), but it changes failure/uid-check/deadline semantics, needs locking and reconnect, and the callers (request signing) do not sign at rates where 130 us matters. Not recommended. [V for the two numbers; the gain of an actual implementation is unmeasured.]
3. KDF cost: DELIBERATE, never lower. Allocation of 64 MiB per derive is inherent to argon2.
No before/after prototypes were built, so there is no measured-gain table.

## Defects and hardening items, ranked (none critical)
1. LOW: duplicate `entries` keys amplify CPU/garbage in Parse. 16 MiB of `{"magic":"keystore/v1","current":"","entries":[], ... repeated, "magic":"keystore/v1"}` is accepted (err=nil) and costs 1.93 s and 786 MiB TotalAlloc (about 640 B of Decoder/Reader per occurrence; transient, not retained; peak RSS not measured). Repro: copy (scratch, not kept) into the repo and run `GOWORK=off go test -run TestL1Amplification -v ./internal/ringfile` (line "dup-entries-keys ... alloc=786.5 MiB ... err=<nil>"). Needs ring write access (outside the stated boundary). Fix sketch: reuse one decoder state or reject a second `entries` key (a counter in wireEntries.UnmarshalJSON; it already resets *es). ~5 lines.
2. LOW/INFO: agent allocates the full claimed frame length from a 5-byte header: 697 stalled same-uid connections = +698 MiB heap for up to IOTimeout (5 s); S1 refuted the connection cap, this is the per-connection amplification. Repro: `GOWORK=off go test -run TestL1Stalled -v ./pkg/agent` from (scratch, not kept) (line "697 stalled conns: +697 goroutines, HeapAlloc +698 MiB"). Fix sketch: read the body incrementally (io.CopyN into a growing bytes.Buffer, or cap by what arrives). ~6 lines in readFrame; FuzzReadFrame guards the contract.
3. INFO: ringfile.go:179-181 unreachable (see 1.2).
4. INFO: SIGHUP terminates keystore-agent without cleanup (socket and .lock stay; next start removes the stale socket). Repro: start the agent, `kill -HUP <pid>`; exit 129 and `ls` shows a.sock a.sock.lock. Fix: add SIGHUP to signal.Notify at cmd/keystore-agent/main.go:112, if desired.
5. INFO (known W1-07): failed first `keygen` leaves an empty ring.
6. Test gaps for L2: agent client invalid-signature and uid-mismatch refusals (client.go:61, 77), ringfile writeTemp failure cleanup, Listen error cleanup, no fuzz targets for PEM, base64 secret, passfile, signature-file readers, ErrNegativeLifetime matched by string only.
Scratch artefacts: (scratch, not kept) (repo copy with zz_* tests; leak.sh, claims.sh, container.out, race.txt, cover.txt, bench-*.txt, fuzz-*.txt).
