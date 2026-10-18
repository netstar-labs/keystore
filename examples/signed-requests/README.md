# signed-requests — service-to-service request signing through the agent

**Threat addressed:** a shared secret (API key, HMAC key) copied to both services can be
stolen from either and used to forge requests. Here service A signs with a private key that
only the agent holds; service B holds only A's **public** key, so compromising B yields
nothing that can sign.

**What is signed** (one per line): the scheme tag `keystore-example-request/v1`, method,
path and query, Unix timestamp, a random 128-bit nonce, and SHA-256 of the body. The tag is
domain separation — a signature made here is useless in any other protocol.

**Service B rejects:** a changed body, a changed path, a signature by any other key, a
replay of an accepted request (nonce cache), a timestamp outside ±30 s, and unsigned requests.
Only a verified request consumes a nonce, so forged traffic cannot fill the cache.

**Files:** [main.go](main.go) (`Sign`, `Verifier`, and a demo that runs both services),
[main_test.go](main_test.go), [run.sh](run.sh).

**Does not protect against:** any process running as A's user can ask the agent to sign
arbitrary requests. TLS is still needed for confidentiality. The nonce cache here is in
memory; several B replicas need a shared one.

```sh
examples/signed-requests/run.sh
```
