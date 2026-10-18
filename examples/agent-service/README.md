# agent-service — `keystore-agent` as a long-running service

**Threat addressed:** services that sign need the key *available*, but every process that
holds a key or its passphrase is one more place to steal it from. The agent unlocks the key
once, holds it only in memory, and signs for clients over an owner-only unix socket; the
clients need neither the key nor the passphrase.

**What the script shows:** the agent started from a passfile; a client with an empty
environment signing through the socket; a second agent refused on a live socket; a 0755
socket directory refused; clean exit and socket removal on `-ttl` and on `-idle`.

**Service definitions** (provided, never installed or loaded by the script):

| File | For |
|---|---|
| [keystore-agent.service](keystore-agent.service) | systemd user unit: runtime dir 0700, no core dumps, no network, read-only home |
| [local.keystore-agent.plist](local.keystore-agent.plist) | launchd user agent: restart on crash, no core dumps (edit `/Users/YOU`) |

Under a service manager, `-ttl 0 -idle 0` is typical (the manager owns the lifetime). On
a workstation, prefer a TTL so an unlocked key does not outlive the session.

**Does not protect against:** any process running as the same user can ask the agent to
sign — it checks *who*, not *what*. Root. A memory dump of the agent process (core dumps
are disabled in both definitions, but a debugger as the same user can still attach).

```sh
examples/agent-service/run.sh
```
