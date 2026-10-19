# Golden fixtures

`golden.ks` pins ring format `keystore/v1`. It was written at the production KDF cost
(argon2id, 64 MiB, t=3, p=1) and must keep opening with every future build.

| Field | Value |
|---|---|
| passphrase | `golden ring passphrase` |
| entries | `golden-ed25519` (current), `golden-secret` |
| Ed25519 seed | bytes `0x00`..`0x1f` |
| public key | `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8` |
| secret value | bytes `0x20`..`0x3f` |
| signature over `keystore golden` | `e59248bf…ee75a30c` (full value in `pkg/keystore/golden_test.go`) |

Regenerate only on a deliberate format change:
`go test ./pkg/keystore -run TestGolden -args -update`.

Every value above is published test material (the passphrase, the seed and secret bytes, the RFC 8032-style keys in the fixtures), not a credential for anything.
