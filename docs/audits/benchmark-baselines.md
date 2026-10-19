# Benchmark baselines

Recorded for the L2 benchmark phase. All benchmarks live in new `bench_test.go` files
(no production code changed) and run with `-benchmem`. Each uses `b.ReportAllocs`,
`b.ResetTimer` after setup, no sleeps and no network.

## READ THIS FIRST: how far to trust the numbers

* **Allocation numbers (B/op, allocs/op, allocB/inB) are deterministic** and are the
  baselines to guard with a threshold. They agree across macOS and Linux to within a few
  percent (counts differ by a handful of runtime allocations).
* **Timing numbers on the macOS host below were recorded on a heavily loaded machine**:
  the load average was 50 to 75 on 8 cores for the whole run, because other agents were
  compiling and benchmarking at the same time (load recorded before and after each
  package in the run: 50 to 67). Medians there are inflated roughly 2x to 5x and spreads
  are 30% to 180%. Example: `Derive/production` median 592 ms, min 496 ms, against
  142 ms in an earlier, lightly loaded single run (below). **Do not set a timing
  threshold from the loaded host table.** Re-record it on an idle machine with the
  command in "Commands" before using it as a regression gate.
* The linux/arm64 numbers come from a container VM with its own 5 vCPUs; they were less
  disturbed (spreads 4% to 50%), but the VM shares the same physical host, so treat them
  as the better timing reference available today, not as a quiet-machine measurement.
* `benchstat` is not installed on this machine, so the tables report median and
  min..max per benchmark (spread = (max-min)/median) instead of a confidence interval.

## Machines

| | host | container |
|---|---|---|
| CPU | Apple M1 Pro (`sysctl -n machdep.cpu.brand_string`) | 5 vCPU arm64 VM on the same M1 Pro (Apple `container`, alpine:latest, kernel 6.18.15) |
| cores | 8 (`hw.ncpu`) | 5 (`nproc`), 1.1 GB RAM |
| OS | macOS, Darwin 25.6.0 | Linux aarch64 |
| Go | go1.27.2 darwin/arm64 | go1.27.2, cross-compiled `GOOS=linux GOARCH=arm64 CGO_ENABLED=0` |
| runs | `-count=10` | `-test.count=5` |

## Commands

```sh
# host (one package at a time so packages do not run their benchmarks concurrently)
GOWORK=off go test -p 1 -bench . -benchmem -count=10 -run '^$' ./...

# linux/arm64: cross-compile each test binary, run it in alpine
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o lbin/pkg_keystore.test ./pkg/keystore   # and the other five
container run --rm -v "$PWD/lbin:/b:ro" alpine:latest sh -c \
  '/b/pkg_keystore.test -test.bench . -test.benchmem -test.count=5 -test.run "^$"'

# real-cost end to end (hyperfine is not available): built binary, 20 runs, bash `time`
KEYSTORE_PASSPHRASE=... keystore keygen -keystore r.ks -id prod
for i in $(seq 20); do time keystore sign -keystore r.ks -in msg >/dev/null; done
```

Packages with benchmarks: `internal/kdf`, `internal/seal`, `internal/ringfile`,
`pkg/keystore`, `pkg/agent`, `cmd/keystore`. (The first host attempt with
`./...` was aborted when the machine load made it clear the run would be unusable; the
tables below are from the per-package rerun.)

## Lightly loaded reference (single sample, host, load average not recorded)

Taken early in the session, `-benchtime` 100 ms to 300 ms, one sample each. Indicative of
an unloaded M1 Pro; not a baseline. The headline figures:

| benchmark | ns/op |
|---|---|
| `kdf.Derive/production` (64 MiB, t=3, p=1) | 141.9 ms |
| `kdf.Derive/minimum` (8 MiB, t=1) | 5.18 ms |
| `kdf.Derive/high256MiB_t3_p1` | 650.8 ms |
| `keystore.Signer/production` | 138.2 ms (one KDF run) |
| `keystore.Add/production` | 284.8 ms (two KDF runs) |
| `keystore.ChangePassphrase/production/entries=2` | 554.2 ms |
| `keystore.ChangePassphrase/production/entries=8` | 2.344 s (ratio 4.23x) |
| `seal.Seal` / `Open` 32 B | 741 ns / 459 ns |
| `ringfile.Parse` 1000 entries | 5.0 ms (89 MB/s) |
| `ringfile.Save` 2 entries | 9.1 ms (APFS, fsync without F_FULLFSYNC) |
| `agent` sign round trip 64 B, 1 client | 112.6 us |
| `ed25519.Sign` 64 B in process | 20.1 us |
| `agent.Dial` | 41.6 us |
| `cmd` `run(sign)` at minimum KDF | 5.4 ms |

## Real-cost end to end: `keystore sign` on the built binary

Production KDF cost, 64-byte message, ring with one key, passphrase from
`KEYSTORE_PASSPHRASE`, 20 sequential runs, wall clock from bash `time`, on the
loaded host (load average 58 to 76):

mean 0.476 s, median 0.453 s, stdev 0.114 s, min 0.331 s, max 0.706 s.

The floor is the single KDF run (about 142 ms unloaded, from the table above) plus
process start and ring read; the observed values are inflated by the load and are not the
production latency of an idle machine. Re-run `e2e` on an idle machine for a citable figure.

The `cmd/keystore` benchmarks below run at the MINIMUM KDF cost. They are NOT production
latencies: at the shipped cost each unlock adds about 140 ms.

## Results: macOS arm64 host (count=10, LOADED, see above)

Columns: ns/op median and `min .. max (spread)`; B/op; allocs/op; `allocB/inB` is heap
bytes allocated per byte of input (ringfile only).

### internal/kdf

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| Derive/production | 10 | 592.16 ms | 495.71 ms .. 746.11 ms (42%) | 64.00 MiB (67111532) | 32 |
| Derive/minimum | 10 | 13.65 ms | 10.00 ms .. 34.35 ms (178%) | 8.00 MiB (8390566) | 15 |
| Derive/high256MiB_t3_p1 | 10 | 2.489 s | 2.236 s .. 2.943 s (28%) | 256.00 MiB (268437968) | 32 |
| New | 10 | 1.10 us | 649.1 ns .. 1.49 us (76%) | 16 B (16) | 1 |

### internal/seal

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| Seal/32B | 10 | 2.86 us | 2.62 us .. 3.62 us (35%) | 1.3 KiB (1344) | 4 |
| Seal/1KiB | 10 | 7.72 us | 4.45 us .. 15.56 us (144%) | 2.4 KiB (2448) | 4 |
| Seal/64KiB | 10 | 111.45 us | 85.18 us .. 152.01 us (60%) | 73.3 KiB (75025) | 4 |
| Open/32B | 10 | 2.30 us | 1.84 us .. 3.06 us (53%) | 1.3 KiB (1312) | 3 |
| Open/1KiB | 10 | 2.68 us | 2.35 us .. 3.06 us (26%) | 2.2 KiB (2304) | 3 |
| Open/64KiB | 10 | 77.16 us | 59.46 us .. 116.91 us (74%) | 65.3 KiB (66817) | 3 |
| AAD | 10 | 1.21 us | 739.0 ns .. 1.63 us (74%) | 504 B (504) | 6 |

### internal/ringfile

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op | allocB/inB |
|---|---|---|---|---|---|---|
| Parse/entries=1 | 10 | 27.04 us | 20.53 us .. 32.45 us (44%) | 4.8 KiB (4900) | 33 | 9.54 |
| Parse/entries=10 | 10 | 277.98 us | 203.76 us .. 467.86 us (95%) | 32.7 KiB (33518) | 136 | 7.43 |
| Parse/entries=100 | 10 | 2.27 ms | 1.77 ms .. 3.27 ms (66%) | 245.6 KiB (251501) | 1049 | 5.64 |
| Parse/entries=1000 | 10 | 19.72 ms | 16.70 ms .. 25.88 ms (47%) | 2.22 MiB (2329502) | 10089 | 5.22 |
| Parse/entries=10000 | 10 | 118.92 ms | 106.29 ms .. 174.56 ms (57%) | 31.03 MiB (32535830) | 109171 | 7.28 |
| ParseHostileEmptyObjects | 10 | 37.33 ms | 31.62 ms .. 55.74 ms (65%) | 4.00 MiB (4198301) | 40 | 4.00 |
| Marshal/entries=1 | 10 | 33.03 us | 22.23 us .. 58.26 us (109%) | 6.0 KiB (6192) | 39 | 12.05 |
| Marshal/entries=10 | 10 | 273.11 us | 182.73 us .. 346.89 us (60%) | 43.1 KiB (44127) | 151 | 9.78 |
| Marshal/entries=100 | 10 | 1.74 ms | 1.57 ms .. 2.83 ms (73%) | 358.1 KiB (366693) | 1156 | 8.23 |
| Marshal/entries=1000 | 10 | 17.23 ms | 12.76 ms .. 21.31 ms (50%) | 4.22 MiB (4422742) | 11106 | 9.92 |
| Marshal/entries=10000 | 10 | 132.00 ms | 111.49 ms .. 198.89 ms (66%) | 62.60 MiB (65643934) | 119231 | 14.69 |
| Save/entries=2 | 10 | 12.53 ms | 11.84 ms .. 16.80 ms (40%) | 9.5 KiB (9762) | 69 | |
| Save/entries=100 | 10 | 13.45 ms | 12.64 ms .. 15.74 ms (23%) | 364.5 KiB (373262) | 1174 | |
| Lock | 10 | 66.50 us | 43.78 us .. 112.00 us (103%) | 312 B (312) | 5 | |

### pkg/keystore

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| OpenList/entries=10 | 10 | 236.09 us | 199.68 us .. 376.25 us (75%) | 53.1 KiB (54370) | 222 |
| OpenList/entries=1000 | 10 | 24.24 ms | 16.47 ms .. 35.91 ms (80%) | 3.69 MiB (3870128) | 17121 |
| List | 10 | 2.49 ms | 2.20 ms .. 3.60 ms (57%) | 494.6 KiB (506511) | 7001 |
| Add/production | 10 | 1.155 s | 747.89 ms .. 1.599 s (74%) | 128.05 MiB (134267784) | 341 |
| Add/minimum | 10 | 52.10 ms | 45.91 ms .. 59.52 ms (26%) | 16.04 MiB (16824280) | 295 |
| Signer/production | 10 | 584.01 ms | 429.33 ms .. 902.89 ms (81%) | 64.01 MiB (67114313) | 67 |
| Signer/minimum | 10 | 19.89 ms | 15.77 ms .. 23.06 ms (37%) | 8.00 MiB (8393492) | 51 |
| ChangePassphrase/production/entries=2 | 10 | 2.419 s | 1.508 s .. 3.452 s (80%) | 256.05 MiB (268492416) | 382 |
| ChangePassphrase/production/entries=8 | 10 | 10.495 s | 8.833 s .. 15.943 s (68%) | 1024.15 MiB (1073903448) | 1030 |
| ChangePassphrase/minimum/entries=2 | 10 | 89.76 ms | 67.21 ms .. 97.20 ms (33%) | 32.06 MiB (33613102) | 320 |
| ChangePassphrase/minimum/entries=8 | 10 | 292.07 ms | 241.80 ms .. 519.99 ms (95%) | 128.15 MiB (134373148) | 772 |
| Fingerprint | 10 | 3.03 us | 2.57 us .. 3.62 us (34%) | 816 B (816) | 20 |

### pkg/agent

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| SignViaAgent/64B/clients=1 | 10 | 274.29 us | 233.07 us .. 322.20 us (32%) | 2.3 KiB (2312) | 35 |
| SignViaAgent/64B/clients=8 | 10 | 136.38 us | 94.65 us .. 180.05 us (63%) | 2.3 KiB (2312) | 35 |
| SignViaAgent/64B/clients=64 | 10 | 96.18 us | 82.82 us .. 126.96 us (46%) | 2.3 KiB (2314) | 35 |
| SignViaAgent/1MiB/clients=1 | 10 | 10.25 ms | 7.54 ms .. 13.33 ms (56%) | 2.01 MiB (2107586) | 35 |
| SignViaAgent/1MiB/clients=8 | 10 | 5.58 ms | 3.65 ms .. 7.50 ms (69%) | 2.01 MiB (2107552) | 35 |
| SignViaAgent/1MiB/clients=64 | 10 | 3.46 ms | 2.95 ms .. 4.34 ms (40%) | 2.01 MiB (2107552) | 35 |
| SignInProcess/64B | 10 | 90.98 us | 59.18 us .. 154.45 us (105%) | 0 B (0) | 0 |
| SignInProcess/1MiB | 10 | 10.77 ms | 8.64 ms .. 12.59 ms (37%) | 0 B (0) | 0 |
| VerifyInProcess/64B | 10 | 257.66 us | 222.65 us .. 301.22 us (30%) | 0 B (0) | 0 |
| VerifyInProcess/1MiB | 10 | 4.82 ms | 3.78 ms .. 5.78 ms (41%) | 0 B (0) | 0 |
| Dial | 10 | 52.84 us | 43.46 us .. 106.94 us (120%) | 2.0 KiB (2093) | 34 |
| ReadFrame/64B | 10 | 158.8 ns | 124.5 ns .. 284.0 ns (100%) | 69 B (69) | 2 |
| ReadFrame/64KiB | 10 | 21.84 us | 9.70 us .. 52.05 us (194%) | 64.0 KiB (65541) | 2 |
| ReadFrame/1MiB | 10 | 150.67 us | 129.15 us .. 183.79 us (36%) | 1.00 MiB (1048582) | 2 |
| WriteFrame/64B | 10 | 145.6 ns | 85.9 ns .. 207.8 ns (84%) | 80 B (80) | 1 |
| WriteFrame/64KiB | 10 | 27.10 us | 13.15 us .. 36.52 us (86%) | 72.0 KiB (73728) | 1 |
| WriteFrame/1MiB | 10 | 169.60 us | 118.36 us .. 268.13 us (88%) | 1.01 MiB (1056768) | 1 |

### cmd/keystore

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| RunSign | 10 | 18.72 ms | 11.36 ms .. 34.52 ms (124%) | 8.02 MiB (8410500) | 183 |
| RunList/entries=1 | 10 | 62.17 us | 48.95 us .. 79.31 us (49%) | 9.1 KiB (9294) | 87 |
| RunList/entries=20 | 10 | 655.03 us | 404.32 us .. 904.97 us (76%) | 114.8 KiB (117544) | 563 |

## Results: linux/arm64 (Apple container VM, 5 vCPU, count=5)

Same columns. This VM was less disturbed than the host; it is the better timing reference today.

### internal/kdf

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| Derive/production | 5 | 187.63 ms | 180.52 ms .. 214.31 ms (18%) | 64.00 MiB (67111522) | 31 |
| Derive/minimum | 5 | 10.30 ms | 9.99 ms .. 11.37 ms (13%) | 8.00 MiB (8390509) | 15 |
| Derive/high256MiB_t3_p1 | 5 | 749.88 ms | 695.20 ms .. 899.84 ms (27%) | 256.00 MiB (268438096) | 31 |
| New | 5 | 129.0 ns | 124.2 ns .. 137.3 ns (10%) | 16 B (16) | 1 |

### internal/seal

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| Seal/32B | 5 | 1.90 us | 1.50 us .. 2.15 us (35%) | 1.3 KiB (1344) | 4 |
| Seal/1KiB | 5 | 2.48 us | 2.26 us .. 2.77 us (21%) | 2.4 KiB (2448) | 4 |
| Seal/64KiB | 5 | 48.02 us | 44.33 us .. 72.20 us (58%) | 73.3 KiB (75024) | 4 |
| Open/32B | 5 | 1.66 us | 1.57 us .. 1.73 us (10%) | 1.3 KiB (1312) | 3 |
| Open/1KiB | 5 | 2.67 us | 2.28 us .. 3.18 us (34%) | 2.2 KiB (2304) | 3 |
| Open/64KiB | 5 | 56.28 us | 52.29 us .. 66.09 us (25%) | 65.2 KiB (66816) | 3 |
| AAD | 5 | 611.2 ns | 564.9 ns .. 683.0 ns (19%) | 504 B (504) | 6 |

### internal/ringfile

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op | allocB/inB |
|---|---|---|---|---|---|---|
| Parse/entries=1 | 5 | 19.78 us | 18.27 us .. 21.37 us (16%) | 4.8 KiB (4899) | 33 | 9.53 |
| Parse/entries=10 | 5 | 140.35 us | 124.51 us .. 152.21 us (20%) | 32.7 KiB (33504) | 136 | 7.43 |
| Parse/entries=100 | 5 | 1.37 ms | 1.26 ms .. 1.42 ms (12%) | 245.5 KiB (251415) | 1049 | 5.64 |
| Parse/entries=1000 | 5 | 14.95 ms | 12.58 ms .. 17.22 ms (31%) | 2.22 MiB (2327514) | 10085 | 5.22 |
| Parse/entries=10000 | 5 | 94.84 ms | 91.92 ms .. 100.66 ms (9%) | 31.03 MiB (32533294) | 109167 | 7.28 |
| ParseHostileEmptyObjects | 5 | 31.72 ms | 31.57 ms .. 32.71 ms (4%) | 4.00 MiB (4197130) | 38 | 4.00 |
| Marshal/entries=1 | 5 | 21.86 us | 19.11 us .. 22.85 us (17%) | 6.0 KiB (6190) | 39 | 12.04 |
| Marshal/entries=10 | 5 | 162.89 us | 155.32 us .. 192.75 us (23%) | 43.1 KiB (44094) | 151 | 9.78 |
| Marshal/entries=100 | 5 | 1.94 ms | 1.54 ms .. 2.21 ms (35%) | 353.9 KiB (362352) | 1155 | 8.13 |
| Marshal/entries=1000 | 5 | 16.88 ms | 15.75 ms .. 21.31 ms (33%) | 4.07 MiB (4265660) | 11103 | 9.56 |
| Marshal/entries=10000 | 5 | 142.74 ms | 133.73 ms .. 164.98 ms (22%) | 59.26 MiB (62140459) | 119220 | 13.90 |
| Save/entries=2 | 5 | 1.80 ms | 1.43 ms .. 2.40 ms (54%) | 8.9 KiB (9124) | 69 | |
| Save/entries=100 | 5 | 3.65 ms | 3.12 ms .. 4.77 ms (45%) | 366.3 KiB (375090) | 1174 | |
| Lock | 5 | 3.95 us | 3.84 us .. 4.36 us (13%) | 216 B (216) | 5 | |

### pkg/keystore

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| OpenList/entries=10 | 5 | 231.63 us | 219.03 us .. 257.40 us (17%) | 53.0 KiB (54284) | 222 |
| OpenList/entries=1000 | 5 | 19.10 ms | 17.33 ms .. 20.91 ms (19%) | 3.69 MiB (3867528) | 17117 |
| List | 5 | 2.91 ms | 2.74 ms .. 3.23 ms (17%) | 494.6 KiB (506498) | 7001 |
| Add/production | 5 | 583.59 ms | 560.86 ms .. 664.65 ms (18%) | 128.04 MiB (134262032) | 305 |
| Add/minimum | 5 | 49.69 ms | 43.88 ms .. 68.77 ms (50%) | 16.04 MiB (16819473) | 265 |
| Signer/production | 5 | 295.84 ms | 272.42 ms .. 318.68 ms (16%) | 64.01 MiB (67114192) | 67 |
| Signer/minimum | 5 | 16.35 ms | 14.80 ms .. 17.82 ms (18%) | 8.00 MiB (8393434) | 51 |
| ChangePassphrase/production/entries=2 | 5 | 1.157 s | 1.057 s .. 1.265 s (18%) | 256.05 MiB (268487552) | 353 |
| ChangePassphrase/production/entries=8 | 5 | 4.176 s | 4.012 s .. 4.554 s (13%) | 1024.15 MiB (1073898488) | 989 |
| ChangePassphrase/minimum/entries=2 | 5 | 55.76 ms | 50.74 ms .. 58.18 ms (13%) | 32.05 MiB (33604507) | 287 |
| ChangePassphrase/minimum/entries=8 | 5 | 212.91 ms | 199.81 ms .. 256.86 ms (27%) | 128.14 MiB (134364880) | 732 |
| Fingerprint | 5 | 3.01 us | 2.44 us .. 3.28 us (28%) | 816 B (816) | 20 |

### pkg/agent

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| SignViaAgent/64B/clients=1 | 5 | 322.25 us | 297.20 us .. 327.02 us (9%) | 2.1 KiB (2184) | 35 |
| SignViaAgent/64B/clients=8 | 5 | 78.08 us | 74.70 us .. 94.67 us (26%) | 2.1 KiB (2184) | 35 |
| SignViaAgent/64B/clients=64 | 5 | 65.17 us | 58.08 us .. 76.82 us (29%) | 2.1 KiB (2185) | 35 |
| SignViaAgent/1MiB/clients=1 | 5 | 10.19 ms | 8.07 ms .. 12.01 ms (39%) | 2.01 MiB (2107422) | 35 |
| SignViaAgent/1MiB/clients=8 | 5 | 3.61 ms | 3.29 ms .. 4.25 ms (27%) | 2.01 MiB (2107410) | 35 |
| SignViaAgent/1MiB/clients=64 | 5 | 2.31 ms | 2.10 ms .. 2.93 ms (36%) | 2.01 MiB (2107419) | 35 |
| SignInProcess/64B | 5 | 41.92 us | 41.26 us .. 42.97 us (4%) | 0 B (0) | 0 |
| SignInProcess/1MiB | 5 | 2.90 ms | 2.85 ms .. 3.09 ms (8%) | 0 B (0) | 0 |
| VerifyInProcess/64B | 5 | 89.81 us | 86.34 us .. 95.49 us (10%) | 0 B (0) | 0 |
| VerifyInProcess/1MiB | 5 | 1.50 ms | 1.47 ms .. 1.54 ms (5%) | 0 B (0) | 0 |
| Dial | 5 | 54.67 us | 47.84 us .. 70.43 us (41%) | 1.9 KiB (1965) | 34 |
| ReadFrame/64B | 5 | 166.3 ns | 155.4 ns .. 192.6 ns (22%) | 69 B (69) | 2 |
| ReadFrame/64KiB | 5 | 44.30 us | 24.39 us .. 46.84 us (51%) | 64.0 KiB (65542) | 2 |
| ReadFrame/1MiB | 5 | 364.13 us | 271.81 us .. 480.36 us (57%) | 1.00 MiB (1048586) | 2 |
| WriteFrame/64B | 5 | 69.9 ns | 53.2 ns .. 80.7 ns (39%) | 80 B (80) | 1 |
| WriteFrame/64KiB | 5 | 26.11 us | 19.41 us .. 39.25 us (76%) | 72.0 KiB (73728) | 1 |
| WriteFrame/1MiB | 5 | 526.41 us | 316.08 us .. 864.15 us (104%) | 1.01 MiB (1056774) | 1 |

### cmd/keystore

| benchmark | runs | ns/op median | min .. max (spread) | B/op | allocs/op |
|---|---|---|---|---|---|
| RunSign | 5 | 16.90 ms | 15.11 ms .. 19.16 ms (24%) | 8.02 MiB (8407736) | 179 |
| RunList/entries=1 | 5 | 47.17 us | 41.46 us .. 53.21 us (25%) | 9.0 KiB (9251) | 87 |
| RunList/entries=20 | 5 | 467.93 us | 423.01 us .. 537.58 us (24%) | 114.6 KiB (117376) | 562 |

## Notes

**KDF dominates.** One argon2id run at the production cost is about 142 ms unloaded
(macOS), 188 ms in the Linux VM. Every unlock is one run (`Signer`, `Secret`), `Add` to a
non-empty ring is two (`checkPassphrase` unlocks the first entry, `encrypt` derives the new
key; measured 284.8 ms against 138.2 ms for one run: ratio 2.06), and
`ChangePassphrase` is 2N. Everything else is small next to it: AEAD open of 32 B is 0.5 us,
parsing a 1000-entry ring is 5 ms, and the durable `Save` is about 9 ms (6% of one run). The cost is
deliberate and the `high256MiB_t3_p1` row exists only so that a change is visible; nothing
here suggests lowering it.

**What scales linearly.**
* `ChangePassphrase`: N=8 over N=2 is 4.23x (host, light load), 4.34x (host, loaded),
  3.61x (Linux). At the minimum cost the ratio is lower (3.2x to 3.8x) because a constant
  `Save` of about 9 ms is a larger share; (94.2 - 9) / (29.6 - 9) = 4.1x after removing it
  (light-load sample). Linear in N, as designed.
* `ringfile.Parse`: 1000 to 10000 entries costs 9.3x (5.0 ms to 46.3 ms, light-load
  sample) and 31 MiB to 2.2 MiB of allocation is 13.9x for 10x the entries. Per entry
  time is flat (about 4.6 us to 5 us), so no quadratic term was found.
  `allocB/inB` is 5.2 to 9.5 and rises at 10000 entries (7.3) from slice growth of the
  result; it is bounded.
* `Marshal` costs about Parse plus an encode, because it re-Parses its own output
  (the "refuse to write an invalid ring" check): 8 to 15 allocated bytes per output byte.
* `agent` 1 MiB sign allocates 2.0 MiB, independent of the number of clients.

**Allocation hot spots, and what is surprising.** Nothing is a defect; each is listed so
that a change is noticed.
* `ParseHostileEmptyObjects` (1 MiB of `{}`): 4.00 allocB/inB, 4.2 MB, 38 to 48 allocs, and
  the number does not grow with the element count. The streaming decode fails at the first
  element; the 4x is the json decoder buffering the one top-level value with doubling.
  Worst case at MaxSize (16 MiB) is therefore about 64 MiB (inferred by scaling, not run).
* 1 MiB agent sign allocates 2 MiB: the server's `readFrame` (1 MiB) plus the client's
  `writeFrame` copying the payload to prepend the 5-byte header (1 MiB). A two-part write
  would avoid the copy at the cost of a second syscall; not changed here.
* `agent` sign at 64 B allocates 35 times (2.3 KiB), almost all in the net/unix-socket path
  and `peercred`, per connection: the client dials a new connection per request.
* `keystore.List` allocates 7 times per signing entry (SPKI parse, fingerprint
  base64); 1000 entries cost 0.77 ms.
* `Parse` of one entry allocates 4.9 KiB / 33 times: fixed json decoder overhead (inferred from the code: a magic
  peek decode, then the streaming decode).
* Peak resident memory per KDF run is the `B/op` of `Derive` (64 MiB at production); it is
  freed between runs. Peak RSS was not measured (inferred from B/op).

**Agent overhead against in-process signing.** `SignViaAgent` includes the client's own
`Verify` of the reply. Using single-client medians: macOS (light-load sample) 64 B:
112.6 us total, of which sign 20.1 us and verify 42.5 us, so about 50 us is transport
(dial, two peer-credential checks, two frames, goroutine hand-off). 1 MiB: 3.02 ms, of
which sign 1.53 ms and verify 0.80 ms, so about 0.7 ms is transport and copies. Linux VM
(medians): 64 B 322 us against sign 42 us + verify 90 us, so about 190 us transport; 1 MiB
10.2 ms against 2.9 + 1.5 ms, so about 5.8 ms transport. Concurrency scales: 64 B at 64
clients costs 0.35x per op of the single client on the host (wall time per op, 8 cores).
The `ed25519.Sign` baseline allocates nothing; the agent path allocates 35 times per sign.

**Method note: client counts.** `SignViaAgent/.../clients=N` runs exactly N goroutines that
split b.N between them. `b.RunParallel` cannot run fewer goroutines than GOMAXPROCS, so "1
client" could not be expressed with it.

**Not benchmarked, deliberately.** Nothing sleeps or touches the network. The Keychain and
terminal-prompt paths are interactive/OS calls and are excluded. `Save` and `Lock` numbers
are properties of the filesystem (APFS and the VM's ext4/virtiofs), compare within one
machine only.

## Regression notes: what a change of more than 20% in each means

Allocation figures are exact: any change in B/op or allocs/op is real and worth a look; a
change above 20% is a code change, never noise. Timing figures need an idle machine; on
this one the spread alone exceeded 20%.

| benchmark | a change above 20% means |
|---|---|
| `kdf.Derive/*` | the cost constants or `x/crypto/argon2` changed. Production slower by more than 20% (without a deliberate cost change) is a dependency or toolchain regression; faster means the cost was lowered, which weakens brute-force resistance and needs a decision, not a celebration. `B/op` must equal Mem (64 MiB) plus small constants. |
| `seal.Seal/Open` | AEAD path changed (cipher construction per call, extra copies). `allocs/op` 4 and 3 should not move. |
| `seal.AAD` | AAD construction changed; its bytes are golden-tested, so this is performance only. 6 allocs. |
| `ringfile.Parse` | the decode strategy changed. `allocB/inB` is the guard: about 5 to 10 for valid rings and a constant 4.0 for the hostile `{}` array; a jump (the old whole-array decode measured 378.6 in the sensitivity demo) is the amplification bug returning. Time per entry going up with ring size means a quadratic term. |
| `ringfile.Marshal` | encode or the self-check Parse changed; if it falls to about Parse alone, the self-check was dropped (a safety regression). |
| `ringfile.Save` | an fsync was added or removed, or a temp-file/rename step changed. A big drop is suspicious (durability); a rise is more fsyncs. |
| `ringfile.Lock` | the lock protocol changed (retry sleep, extra syscalls). |
| `keystore.Open+List` | parse or per-entry SPKI work changed; linear in entries. |
| `keystore.Add` | should be 2 x `Derive/production` plus Save; materially different means KDF runs were added or removed (1 would drop the passphrase check, 3 doubles the latency). |
| `keystore.Signer` | should be 1 x `Derive` plus about 1% overhead. |
| `keystore.ChangePassphrase` | must stay 2N KDF runs; N=8 / N=2 should stay about 4 (3.5 to 4.4). A ratio near 16 would be a quadratic bug. |
| `agent.SignViaAgent` | transport or server loop changed. Compare with `SignInProcess + VerifyInProcess`; the gap is the agent's overhead. An allocation rise per sign is a copy added per request (1 MiB rows make it obvious: 2.01 MiB today). Throughput not improving from 1 to 8 clients means a lock was introduced. |
| `agent.Dial` | handshake path changed (peer-credential check, public-key fetch). |
| `agent.ReadFrame/WriteFrame` | framing allocations changed (2 and 1 allocs); the 1 MiB row should stay one payload-sized allocation. |
| `cmd` `RunSign/RunList` (minimum KDF) | CLI overhead other than the KDF (flag parsing, output). `RunSign` is dominated by the 8 MiB argon2 buffer even at the minimum cost, so its B/op tracks `Derive/minimum`. |

## Sensitivity demonstrations

Each benchmark must move when the code regresses. These were done on a throwaway copy of
the module (`/private/tmp/.../scratchpad/sens`, never the repository), reverting between
runs. The machine was loaded, so the timing columns are rough; the decisive column is
named in each row.

| deliberate regression (on the copy) | benchmark | before | after |
|---|---|---|---|
| `wireEntries.UnmarshalJSON` decodes the whole array into `[]wireEntry` before validating (the old behaviour) | `ringfile.ParseHostileEmptyObjects` | 4.00 allocB/inB, 4.2 MB/op, 38 to 48 allocs/op | **378.6 allocB/inB, 397 MB/op, 349,660 allocs/op** |
| same | `ringfile.Parse/entries=1000` | 5.22 allocB/inB, 2.33 MB/op | 6.59 allocB/inB, 2.94 MB/op (moves; this is why the hostile benchmark is the real guard) |
| one 4 KiB allocation added per sign in `Server.handle` | `agent.SignViaAgent/64B/clients=1` | 2.31 to 2.33 KiB/op, 35 allocs | **6.41 to 6.43 KiB/op, 36 allocs** (time was noise-dominated: 387 to 486 us before, 340 to 445 us after) |
| `time.Sleep(2ms)` per sign in `Server.handle` | `agent.SignViaAgent/64B/clients=1` | 387 to 486 us/op | **2.56 to 2.76 ms/op** |
| one extra argon2 pass (`Time+1`) in `Params.Derive` | `kdf.Derive/minimum` | 21.8 to 26.1 ms/op, 15 allocs | **55.4 to 64.7 ms/op, 23 allocs** |
| same | `kdf.Derive/production` | 737 to 874 ms/op, 32 allocs | **965 ms to 1.27 s/op, 41 allocs** (loaded; ratio inflated by contention) |

The "before" values in this table are from the same session and load as "after"; the
loaded timings are therefore comparable with each other only.

## Findings

No real defect and no O(n^2) was found: `Parse`, `Marshal`, `List` and `ChangePassphrase`
are linear at the sizes measured (1 to 10,000 entries; N=2 to 8). The Parse amplification
fix is holding (4.0 allocB/inB on the hostile ring against 378.6 for the old decode).
No fix branch was created.
