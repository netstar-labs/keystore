# Audit A6: format and version-skew compatibility

Scope: every encoded artifact keystore reads or writes whose bytes outlive the process or
cross a version boundary. Method: handbook prompt A6. Goldens are independent of the code
under test: the AAD, ring-writer and PEM expectations were built by separate Python scripts
from `docs/format.md` and RFC 8410; the PEM, SPKI hash and a signature were cross-checked
with OpenSSL 3.5.9 in an Alpine container; the agent frames were written from
`docs/agent-protocol.md`. Where a literal could not be derived independently it is labelled.

## Skew verdict

- **Ring.** Versioned (`magic`). A newer tag is refused as `ErrFutureVersion`; the tag is
  also inside the AAD, so a v2 entry cannot unlock under v1 even if parsed. KDF parameters
  are per entry, so raising the cost does not break old entries. Safe to change: adding an
  optional field is NOT safe (unknown fields are rejected whole, by design); raising KDF
  cost is safe; adding a kind is rejected by old readers (loud). Unsafe: anything inside
  the AAD layout, the plaintext encodings, base64 variant, or timestamp form. Those make
  old entries fail as "wrong passphrase or corrupt entry", the same message as a typo
  (loud but misleading), or are read as a different value.
- **Agent protocol.** No version field anywhere. Adding an op is safe (unknown op gets an
  error reply). Changing the layout inside P or S is unsafe: an old peer reads a wrong
  length or status. The reference client re-verifies every S signature against the
  public key, which turns a corrupted S reply into an error; it does NOT re-verify the
  P reply beyond `len == 32`, so a changed P payload is accepted as a different key
  (inferred from `client.go`, not exercised). Mixed versions are realistic here: a
  long-lived `keystore-agent -ttl` outlives an upgrade of the `keystore` CLI.
- **Hashes/placement.** None. Fingerprint is derived identity (see table).

## Inventory

"Pinned before" is what existed on `main` (43655ff). "Golden" is what this branch adds.
All mutations below were applied one at a time to a copy of the source, the named test
run, then the file restored (`git status` clean of source changes afterwards); the script
and raw output are in the session scratchpad (`a6/mutate.py`, `a6/mutation.out`).

| # | Artifact (encoder) | Versioned? | Pinned before | Silent-change cost | Golden added | Mutation (all KILLED = test failed) |
|---|---|---|---|---|---|---|
| 1 | Ring file bytes (`ringfile.marshal`) | `magic` | `TestGolden` reads `golden.ks`; `TestMarshalParseRoundTrip` only checks Marshal(Parse(Marshal)) is stable, no fixed bytes | Readers are order/whitespace-insensitive, so key order and indent are a tripwire for diff stability and third-party writers' byte compare, not a compatibility break. Base64 variant, `created` form, `pub` omitted vs empty, `current`/`entries` always present ARE read-side relevant | `TestMarshalGoldenBytes` (two entries incl. max KDF 1048576/64/16, non-UTC created, secret without `pub`, current marker; empty ring) against `testdata/ring-two-entries.ks`, `ring-empty.ks` rendered by Python `json.dumps(indent=2)`. `TestMarshalReproducesGoldenRing`: Parse then Marshal of `golden.ks` is byte-identical | nonce/ct field swap, drop `omitempty` on pub, indent to tab, drop `.UTC()`, `entries` nil, drop trailing LF, magic/current swap: all KILLED |
| 2 | Ring read side, edge rings | | `golden.ks` only | A parser change that rejects a ring older builds wrote | `TestParseEdgeFixtures`, `TestEdgeRingFixturesOpen` (pkg/keystore): `ring-minimal.ks` (`{"magic":"keystore/v1"}`), `ring-empty.ks`, `ring-secret-only.ks` (derived from golden.ks; secret unlocks, `Signer("")` is ErrNoKey) | absent entries -> nil, `current` required non-empty: KILLED |
| 3 | AEAD AAD (`seal.AAD`) | tag inside AAD | `TestAADBindsEveryField` (distinctness only), `TestGolden` (implicit: opening golden.ks proves the exact bytes for one ed25519 and one secret entry at one parameter set) | Every old entry stops unlocking as ErrBadPass | `TestAADGolden`: ed25519 and secret entry, mem/time/par all distinct so a swap shows; hex derived from format.md by an independent script. **Code and doc agree** | pub/algo order swap, mem/time swap, 4-byte length prefix to 2 bytes: KILLED |
| 4 | Entry plaintext (PKCS#8 v1 DER inside the ciphertext) | no | none (golden.ks only proves the key survives) | Toolchain emitting v2 / different DER changes new entries silently | `TestEntryPlaintextIsPKCS8V1`: decrypts golden.ks entry to `302e0201...` + seed, and `x509.MarshalPKCS8PrivateKey` equals it. Labelled: the second half pins the stdlib, not repo code | not mutated (it pins the toolchain; I did not change the stdlib) |
| 5 | KDF default cost | `kdf.Params` per entry | none: every package's TestMain lowers it | A lowered default weakens every new ring | `TestProductionDefaultCost` (captures `Default` at init, before TestMain) | Time 3 to 2: KILLED |
| 6 | Agent frame (`writeFrame`/`readFrame`) | none | `FuzzReadFrame` (round-trip only), `TestOversizeFrameRejected`, `TestUnknownOpRejected` (status only) | Old/new peers misread length or status | `TestWriteFrameGolden`: P, S, ok, error frames; 1 MiB boundary header `5300100000`, 1 MiB+1 refused; `TestServerWireGolden`: raw bytes on a real socket for P, P with ignored payload, S (signature from OpenSSL), unknown op, oversize header, `ffffffff`, 1 MiB sign, connection closes after error | BE to LE, StatusErr 1 to 2, MaxPayload+1, header 5 to 6, op `P` to `Q`, unknown-op text: all KILLED |
| 7 | Agent lock file name | no | none | Two builds with different lock names both own one socket | `TestAgentLockFileName` | rename to `.lck`: KILLED |
| 8 | PEM outputs (`MarshalPrivateKeyPEM`, `MarshalPublicKeyPEM`) | PEM type labels | round-trip tests only | Other tools / `import` of exported backups | `TestPEMGolden` (RFC 8032 seed 9d61b19d...): exact text; OpenSSL 3.5.9: `pkey -pubout` reproduced the public PEM byte for byte, `pkey` re-emitted the private PEM byte for byte | private label change: KILLED |
| 9 | Fingerprint (`SHA256:` + unpadded b64 of SHA-256(SPKI)) | no | substring check in list test | Pinned `-expect-fp` values stop matching: signing refuses (loud, but locks operators out) | `TestFingerprintGolden`, `TestCLIOutputGoldens`; value matched OpenSSL `dgst -sha256` over the SPKI DER | padded base64, lowercase prefix: KILLED |
| 10 | `sign` output | no | round-trip via verify | A verifier splitting on newline or decoding with another alphabet | `TestCLIOutputGoldens`: base64 + `\n` (the signature contains `+` and `/` so URL vs std shows), `-raw` 64 bytes, stderr `signing with <fp>`, `export-pub`, `export-priv -o`, `list` fingerprint column; signature produced by OpenSSL | drop newline, std to URL alphabet: KILLED |
| 11 | `docs/reference.md` | generated | `TestReference` byte-compares the generated text with the file (**confirmed**, reads and compares exactly) | Doc drift | none needed | verb summary edit: KILLED (existing test) |
| 12 | Keychain argv to `/usr/bin/security` | no | `TestArgsNeverCarryTheSecret` asserted only: set ends with bare `-w`, contains `-U` and the account, get starts `find-generic-password` and ends `-w` (shape, not exact; a reordered `-s`/`-a`, or a changed account name, passed) | A changed service/account pair finds no item: ring unlockable only by re-entering the passphrase | `TestKeychainArgvGolden` (darwin only): every element and the program path | swap `-s`/`-a`; account renamed: KILLED |

## What `golden.ks` pins (and does not)

Pins: the reader accepts it; `current`, two entries in order; the AAD bytes for one ed25519
and one secret entry at 64 MiB/3/1 (opening is decryption); PKCS#8 plaintext parseable; the
signature. Does NOT pin: writer output (a build could write something old builds cannot
read and `TestGolden` would still pass, because it only reads); AAD at other parameter
shapes; an empty ring; a secret-only ring; maximal KDF parameters; the production KDF default.
All are now covered by the rows above. `golden.ks` itself is untouched
(sha256 bf2462491e501a051e81f5a73ea4687eba30567dfdd2f6e12cd81352938d03f6, checked in the gate).

## Gaps and findings

1. **No disagreement between `format.md` and the code on the AAD**; the independent derivation matched on the first run.
2. **`format.md` does not specify the writer's layout**: key order, 2-space indent, trailing LF, `current` always written (even `""`), `entries` written as `[]` never null, padded standard base64, `created` UTC whole seconds `Z`. It says only "writers emit UTC whole seconds" and "writers omit" `pub`. Because readers accept any order and whitespace this is documentation debt, not a bug; the fixtures now record it. (Not edited: the contract limits doc changes to behaviour changes.)
3. **`format.md` has no AAD test vector.** `TestAADGolden` is one; a pointer to it from the doc would let another implementer check themselves. Not added.
4. **`agent-protocol.md` underspecifies error replies.** It says "a short ASCII message"; the code sends fixed strings `unknown operation`, `frame too large`, `sign failed`. A sign failure also closes the connection (undocumented; doc lists only unknown-op and oversize). An unknown op with a payload over 1 MiB is answered `frame too large`, not `unknown operation` (the payload is read first). The error texts are now pinned for the first two; the client prints them with `%q` so a change is cosmetic. `sign failed` is not reachable with an Ed25519 signer, so unpinned.
5. **P reply is not authenticated by the client beyond length** (see verdict). The protocol has no version, so a future P payload change would be accepted by an old client as a different key. Fixing means a new op, not a new shape for P.
6. **Doc: "any payload sent is ignored" for P** is verified by `TestServerWireGolden` (P with 4 payload bytes).
7. Per-field base64 variant cannot be mutated in place: `encoding/json` hardwires `StdEncoding` for `[]byte`. The fixtures contain `+`, `/` and `=` so a change to a custom type would show; this is inferred, not mutation-tested. Signature output and fingerprint base64 variants were mutated (rows 9, 10).
8. Phase 3 of the handbook (merge/pin calls): the AAD builder, ring marshaller, frame writer and PEM encoders each exist exactly once; there are no duplicate encoders and no name collisions. **Nothing to merge or rename.** The two `rfc*`-style constant sets in `pkg/keystore` and `cmd/keystore` tests are deliberately separate copies (a persisted-format golden must not share a definition with a sibling test), as are the two PEM literals.

## Not pinned, and why

- `TestMarshalGoldenBytes` etc. run on every platform; `TestKeychainArgvGolden` is darwin-only by file suffix (the functions are).
- The agent socket path/mode rules and the lock file's flock semantics are behaviour, not byte layout; the name only is pinned.
- Read-side acceptance rules in `format.md` (case folding, duplicate keys, number forms, offsets) were not re-audited here; `ringfile_test.go` covers many (inferred from test names, not re-run per rule).
- `golden.ks` regeneration (`-update`) is not blocked by a hash check: that flag is the documented way to rewrite it and the contract forbids changing it; the gate compares the sha256 manually.
