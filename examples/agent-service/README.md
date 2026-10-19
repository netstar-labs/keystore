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

**Operating it under a manager:**

- *Expiry is a clean exit.* With a nonzero `-ttl` or `-idle` the agent exits 0, which
  `Restart=on-failure` and launchd's `SuccessfulExit=false` do not restart, so every client
  then fails until you start it again. That is why both definitions use `-ttl 0 -idle 0`.
- *A lost socket is a failure.* If the socket file is removed or replaced the agent logs it and
  exits 1, and the manager restarts it.
- *A start that keeps failing* (a wrong passphrase, a missing ring) exits 1 with one line; the
  definitions rate-limit the retries (`StartLimitBurst`, `ThrottleInterval`), and the line is in
  the journal or in `~/Library/Logs/keystore-agent.log`. Nothing here alerts you.
- *The agent loads its key once.* After `keystore rm` or `passwd`, restart it: until then it
  keeps signing with the key it loaded.
- *A unit that fails with status 218/CAPABILITIES or 226/NAMESPACE* (inferred, not reproduced:
  `systemd-analyze verify` passes on systemd 257 but the unit was never started under a real
  systemd): the sandbox lines (`PrivateNetwork`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
  ...) in a `--user` unit need unprivileged user namespaces. On such a host drop those lines.
- *A laptop that sleeps:* the agent's timers are not known to count sleep time (see
  SECURITY.md); prefer stopping the agent when you close the lid over relying on `-ttl`.

**Does not protect against:** any process running as the same user can ask the agent to
sign — it checks *who*, not *what*. Root. A memory dump of the agent process (core dumps
are disabled in both definitions, but a debugger as the same user can still attach).

```sh
examples/agent-service/run.sh
```
