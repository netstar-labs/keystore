# rotation — zero-downtime key rotation by overlap

**Threat addressed:** a key that is never rotated because rotating it would break every
verifier at once. Verifiers pin public keys, so the safe rotation is an overlap, not a cliff.

**Steps:**

1. `keystore add -id prod-2027 > prod-2027.pub` — mint the next key beside the current one;
   `add` prints its public key.
2. Publish that file; verifiers add it to their trusted set. (Take the key `add` printed, not a
   later `export-pub`: that reads the ring's stored copy, which is checked only when the entry
   is unlocked.)
3. `keystore use -id prod-2027` — new signatures use it; old signatures still verify.
4. `keystore rm -id prod-2026` and drop its public key from verifiers, once nothing signed
   under it is still needed.

The script checks every transition: `current` does not move early, both keys verify during
the overlap, and after retirement a 2026 signature is no longer accepted. It also shows that
the last signing key cannot be removed without `-force`. Signing is pinned with `-expect-fp`
(the ring's `current` marker is unauthenticated), and a pin naming the wrong key is refused.

**Does not protect against:** a verifier that is never updated (it rejects new signatures at
step 3 — publish before you switch). Revoking a *compromised* key is not rotation: remove it
from every trusted set immediately rather than waiting out an overlap.

```sh
examples/rotation/run.sh
```
