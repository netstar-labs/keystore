# Examples — machine-to-machine integration

Unattended use: no prompts, no humans, no plaintext private key on any disk the workload can
read. Each folder has a `README.md` (the threat it addresses and what it does not protect
against) and a `run.sh` that stands the scenario up in a temporary directory and removes it.

Each run builds the binaries into a private `/tmp` directory and leaves nothing behind.
The service definitions in `agent-service/` are provided but never installed or loaded.

| Example | Shows | Run |
|---|---|---|
| [provision](provision/) | one-time operator setup: ring, key, passfile, public key published | `examples/provision/run.sh` |
| [agent-service](agent-service/) | `keystore-agent` as a systemd / launchd service | `examples/agent-service/run.sh` |
| [signed-requests](signed-requests/) | service A signs HTTP requests via the agent; service B verifies with the public key | `examples/signed-requests/run.sh` |
| [ci-release](ci-release/) | CI signs an artifact via the agent; the deploy host verifies before install | `examples/ci-release/run.sh` |
| [rotation](rotation/) | zero-downtime key rotation by overlap | `examples/rotation/run.sh` |
| [secrets](secrets/) | a workload loads an opaque secret at start-up, then drops it | `examples/secrets/run.sh` |

All are exercised by `go test ./examples/...` (the shell examples run their `run.sh`;
`signed-requests` and `secrets` also have unit tests). Each covers the happy path and the
refusals: tampered input, the wrong key, and an absent or expired agent where an agent is
involved.
