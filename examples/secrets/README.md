# secrets — load an opaque secret at start-up, then drop it

**Threat addressed:** secrets passed in environment variables. An env var lives for the
whole process, is inherited by every child, is readable to the same user on Linux via
`/proc/PID/environ`, and routinely leaks into crash reports and debug dumps. Here the
secret sits encrypted in the ring; the workload unlocks it once at start-up, derives what it
needs, and clears its copy.

**Flow:** the operator stores an HMAC key with `import-secret` (base64 on stdin — never
argv). The workload ([main.go](main.go)) opens the ring with a 0600 passfile, reads the
secret with `keystore.Secret`, tags a message with HMAC-SHA256, and clears the key. The
script checks the tag against `openssl` when available; the tests pin HMAC to RFC 4231.

**Failure modes shown:** wrong passphrase, missing secret, a world-readable passfile, and a
ring entry modified on disk (refused, never decrypted to a wrong value).

**Does not protect against:** the workload itself being compromised while it holds the key
(the window is start-up, but a derived key or session may live longer). Clearing a Go slice
is best effort — the runtime may have copied it. If the secret is a *signing* key, use the
agent instead so the workload never holds it at all.

```sh
examples/secrets/run.sh
```
