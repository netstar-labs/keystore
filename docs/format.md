# Ring format `keystore/v1` (normative)

A ring is one UTF-8 JSON document, file mode 0600. The format tag in `magic` is versioned
independently of the software; a reader rejects any other tag, and reports a newer
`keystore/vN` (N > 1) as "upgrade this binary".

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

All binary fields are standard base64 with padding. Unknown fields, trailing data after the
document, and files larger than 16 MiB are rejected.

## Fields

| Field | Rule |
|---|---|
| `magic` | exactly `keystore/v1` |
| `current` | `""` or the id of an `ed25519` entry |
| `id` | 1–64 bytes of `[A-Za-z0-9._-]`, first byte alphanumeric; unique in the ring |
| `kind` | `ed25519` (plaintext: PKCS#8 DER of an Ed25519 private key) or `secret` (plaintext: opaque bytes) |
| `pub` | `ed25519`: SPKI DER of the entry's Ed25519 public key. `secret`: absent |
| `kdf.algo` | `argon2id` |
| `kdf.mem` | KiB, 8192 … 1048576 |
| `kdf.time` | passes, 1 … 64 |
| `kdf.par` | lanes, 1 … 16 |
| `kdf.salt` | 16 bytes |
| `nonce` | 12 bytes |
| `ct` | at least 16 bytes |
| `created` | RFC 3339 UTC; metadata, not authenticated |

Values outside these ranges are rejected, never clamped.

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

## Invariants

- **One passphrase per ring.** Writers verify the supplied passphrase against an existing
  entry before adding a new one.
- **Writes are atomic and durable.** Write a temp file in the same directory (mode 0600,
  fsync), rename it over the ring, fsync the directory, all while holding an exclusive
  `flock` on `<ring>.lock`. Re-read the ring after taking the lock.
- **Creation never replaces.** A new ring is linked into place, which fails if the path
  exists.

## Fixture

[`testdata/golden.ks`](../testdata/golden.md) is a v1 ring every build must open.
