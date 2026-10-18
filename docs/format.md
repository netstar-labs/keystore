# Ring format `keystore/v1` (normative)

A ring is one UTF-8 JSON document, file mode 0600. The format tag in `magic` is versioned
independently of the software; a reader rejects any other tag, and reports a newer
`keystore/vN` as "upgrade this binary". "Newer" means the text after `keystore/v`, read as
a decimal integer (Go `strconv.Atoi`), is greater than 1: `v2`, `v10`, `v02` and `v+2` are
newer; `v0`, `v01`, `v-1`, `v1.0`, `V2`, an overflowing number and a non-string `magic` are
simply "not a keystore file".

```json
{
  "magic": "keystore/v1",
  "current": "2026-prod",
  "entries": [
    {
      "id": "2026-prod",
      "kind": "ed25519",
      "pub": "<base64 SPKI DER>",
      "kdf": { "algo": "argon2id", "mem": 65536, "time": 3, "par": 1, "salt": "<base64, 16 bytes>" },
      "nonce": "<base64, 12 bytes>",
      "ct": "<base64 AES-256-GCM ciphertext + tag>",
      "created": "2026-10-18T12:00:00Z"
    }
  ]
}
```

## Reading rules

A reader is Go's `encoding/json` plus the checks below; a file that fails any of them is
rejected whole as "not a keystore file" (`ErrBadFormat`), at parse, before any passphrase is
used. Another implementation must match these to read the same ring the same way.

- **Size.** At most 16 MiB (16 777 216 bytes) is accepted; one byte more is rejected.
- **Document.** Exactly one JSON document. Trailing whitespace is allowed, any other
  trailing data is rejected, and a UTF-8 byte-order mark is rejected.
- **Keys** match case-insensitively (`Magic` and `CURRENT` are read as `magic` and
  `current`); values are case-sensitive. A duplicate key silently takes the last value,
  at the top level and inside an entry or `kdf`, except `entries`: a second `entries` key
  (any case, even `[]` or `null`) rejects the ring, since each occurrence costs a decoder
  and a crafted ring of repeats was a cheap amplifier. Entries are validated as they are
  read, so the first invalid one is reported. Unknown fields are rejected (after that case folding).
- **`null`** is the same as absent. `current` null or missing is `""`; `entries` null or
  missing is an empty ring, so `{"magic":"keystore/v1"}` is a valid empty ring.
- **Numbers** must be JSON integers in range: `mem` and `time` fit uint32, `par` fits
  uint8 (then the bounds below apply). Floats (even `65536.0` or `6.5536e4`), strings,
  negatives and out-of-range values are rejected.
- **Binary fields** are Go `encoding/base64` `StdEncoding`: padding is required; CR and LF
  inside a value are ignored; spaces, the URL-safe alphabet and missing padding are
  rejected. The trailing padding bits need not be zero, so two different files can decode
  to the same bytes.

## Fields

| Field | Rule |
|---|---|
| `magic` | exactly `keystore/v1` |
| `current` | `""` or the id of an `ed25519` entry; anything else (a `secret`, an id not in the ring) is rejected at parse. `""` is valid: the default key lookup then fails "no such entry" |
| `id` | 1–64 bytes of `[A-Za-z0-9._-]`, first byte alphanumeric (non-ASCII, NUL and invalid UTF-8 are rejected); unique in the ring, a duplicate is rejected at parse |
| `kind` | `ed25519` (plaintext: PKCS#8 DER of an Ed25519 private key) or `secret` (plaintext: opaque bytes) |
| `pub` | `ed25519`: SPKI DER that must parse as an Ed25519 public key, checked at read time. `secret`: absent, `""` or `null` are all accepted (writers omit it); anything else is rejected |
| `kdf.algo` | `argon2id` |
| `kdf.mem` | KiB, 8192 … 1048576 |
| `kdf.time` | passes, 1 … 64 |
| `kdf.par` | lanes, 1 … 16 |
| `kdf.salt` | 16 bytes |
| `nonce` | 12 bytes |
| `ct` | at least 16 bytes (15 is rejected, 16 accepted at parse) |
| `created` | RFC 3339 with an uppercase `T` and `Z` or a numeric offset. Offsets are accepted and converted to UTC, fractional seconds are accepted and dropped, and the year after conversion must be 0000–9999 (`0001-01-01T00:00:00+23:59` is accepted, `9999-12-31T23:59:59-23:59` is not). Writers emit UTC whole seconds and rewrite the field. Metadata, not authenticated |

Values outside these ranges are rejected at parse, never clamped. The `ed25519` plaintext is
read with Go's `x509.ParsePKCS8PrivateKey`, which ignores trailing bytes and ignores the
public key embedded in an RFC 8410 v2 key; both matter only after authentication succeeds.

## Encryption

```
key = argon2id(passphrase, salt, time, mem, par, 32)
ct  = AES-256-GCM-Seal(key, nonce, plaintext, aad)
```

Writers use a fresh random salt and nonce for every entry they write, and the current
default cost (64 MiB, t=3, p=1).

## Associated data

The concatenation of these fields, each encoded as a 4-byte big-endian length followed by
its bytes:

```
"keystore/v1" ‖ kind ‖ id ‖ pub ‖ kdf.algo ‖ BE32(mem) ‖ BE32(time) ‖ BE32(par) ‖ salt
```

`pub` is empty for `secret` entries. Numeric fields are themselves 4-byte big-endian values,
so each is encoded as length `00000004` followed by the value.

## What is authenticated

AES-GCM authenticates the ciphertext and exactly the associated data above, one entry at a
time. A change to any of these makes that entry fail to unlock with `ErrBadPass` ("wrong
passphrase or corrupt entry", the same as a wrong passphrase): the format tag (which a
reader also requires to be `keystore/v1`), `kind`, `id`, `pub`, `kdf.algo`, `kdf.mem`,
`kdf.time`, `kdf.par`, `kdf.salt`, `nonce`, `ct`.

Not authenticated:

- `created`.
- `current`, the default signing key. Editing it makes `keystore sign` without `-id` (and an
  agent started without `-id`) use another of the ring's keys, with no error; `-id` is
  unaffected.
- Entry order, and the set of entries. Deleting or reordering entries is accepted (deleting
  the entry `current` names also needs `current` edited, or the ring is rejected at parse).
- The ring as a whole. An older copy of the file is accepted and brings back removed keys
  and the passphrase in force when it was taken. An entry copied from another ring over the
  entry of the same `id` and `kind` unlocks if both rings share a passphrase; moving it to
  another `id` or `kind` fails.

So a party that can write the ring but does not know the passphrase cannot read a key or
forge a signature under a key the ring's owner did not choose, but can make a command use
a different key of theirs, bring back a retired key, publish a different `pub` through
`export-pub` (signing then fails), or make the ring unreadable. Writers of scripts should
pass `-id` (or `sign -expect-fp`) and verifiers should pin public keys. See
[SECURITY.md](../SECURITY.md).

## Invariants

- **One passphrase per ring.** Writers verify the supplied passphrase against an existing
  entry before adding a new one.
- **Writes are atomic and durable.** Write a temp file in the same directory (mode 0600,
  fsync), rename it over the ring, fsync the directory, all while holding an exclusive
  `flock` on `<ring>.lock`. Re-read the ring after taking the lock.
- **Creation never replaces.** A new ring is linked into place, which fails if the path
  exists.

## Fixture

[`testdata/golden.ks`](../testdata/golden.ks) (described in [`testdata/golden.md`](../testdata/golden.md)) is a v1 ring every build must open.
