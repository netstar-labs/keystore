# ci-release — CI signs through the agent; deploy hosts verify before install

**Threat addressed:** a release-signing key stored as a CI secret is readable by every job,
every log line that echoes it, and every compromised build dependency. Here the key stays in
the agent on the runner host; the CI job sees only a socket path, and deploy hosts pin only
the public key.

**Flow:** the CI job (run with an empty environment to prove it needs no passphrase or ring)
builds `app-1.2.3.tgz`, writes `SHA256SUMS`, and runs `keystore sign -agent` over the
manifest. The deploy host runs `keystore verify` on the manifest, then checks the digest,
and installs only if both pass. Signing the manifest instead of the artifact keeps the
signed message small (the agent accepts up to 1 MiB) and lets one signature cover many files.

A well-formed signature that does not verify exits 3; an input or signature file that cannot be read or parsed exits 1, so a deploy
script can tell a forgery from a broken check.

**The deploy host refuses:** an artifact replaced after signing; a manifest rewritten to
match a replaced artifact; a release signed by any other key. With the agent stopped, the CI
job cannot sign at all.

**Does not protect against:** a malicious *build* — the agent signs whatever the job hands
it; protect the pipeline itself. Any process running as the runner's user can request
signatures. Use a dedicated release key; do not reuse it for other protocols.

```sh
examples/ci-release/run.sh
```
