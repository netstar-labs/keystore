# rotation — zero-downtime key rotation by overlap

**Threat addressed:** a key that is never rotated because rotating it would break every
verifier at once. Verifiers pin public keys, so the safe rotation is an overlap, not a cliff.

**Steps:**

1. `keystore add -id prod-2027` — mint the next key beside the current one.
2. `keystore export-pub -id prod-2027` — publish it; verifiers add it to their trusted set.
3. `keystore use -id prod-2027` — new signatures use it; old signatures still verify.
4. `keystore rm -id prod-2026` and drop its public key from verifiers, once nothing signed
   under it is still needed.

The script checks every transition: `current` does not move early, both keys verify during
the overlap, and after retirement a 2026 signature is no longer accepted. It also shows that
the last signing key cannot be removed without `-force`.

**Does not protect against:** a verifier that is never updated (it rejects new signatures at
step 3 — publish before you switch). Revoking a *compromised* key is not rotation: remove it
from every trusted set immediately rather than waiting out an overlap.

```sh
examples/rotation/run.sh
```
