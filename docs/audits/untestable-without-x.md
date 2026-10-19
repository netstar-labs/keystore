# Untestable without X

Things this audit could not run, what each needs, and the exact command for a human to run.

| Needs | Why not here | Command |
|---|---|---|
| The real macOS login keychain via `/usr/bin/security` | the owner has not confirmed writes to their keychain; a `keystore` item may already exist and is not to be touched. The test is written, double-gated, and **unexecuted**. It uses a unique service `keystore-l3-throwaway-<rand>` (never `keystore`), deletes it in `t.Cleanup`, and macOS may show an access prompt | `cd keystore && GOWORK=off KEYSTORE_LIVE=1 KEYSTORE_LIVE_KEYCHAIN=1 go test -tags integration -count=1 -v ./integration/keychain/` |
| `keystore keychain-set` interactively (security prompts on the terminal) | needs a human at a terminal | `keystore keychain-set -service my-test-svc`, then `KEYSTORE_KEYCHAIN=my-test-svc keystore list`; remove with `security delete-generic-password -s my-test-svc -a keystore` |
| A second real uid on macOS (LOCAL_PEERCRED across users) | needs another login or `sudo -u` user | as user A: `keystore-agent -keystore R -sock /tmp/a/s -passfile P` in a 0700 dir; as root: `sudo keystore sign -agent /tmp/a/s -in msg` must say "served by uid" |
| systemd on a real host | the containers have no init | `examples/agent-service/keystore-agent.service` copied to a host: `systemd-analyze verify keystore-agent.service`, then `systemctl start` and a `keystore sign -agent` |
| launchd | not loaded on purpose | `plutil -lint examples/agent-service/local.keystore-agent.plist`; load under a throwaway label with `launchctl bootstrap gui/$(id -u) FILE` |
| Linux `-race` | static build has cgo off; `-race` needs a C toolchain on linux | on a Linux host: `go test -race -count=1 ./...` |
| linux/amd64 | only arm64 was run | `GOOS=linux GOARCH=amd64 go vet ./...` (cheap) and the suite on an amd64 host |
| OpenSSL other than 3.5.x, or LibreSSL 3.7+ | only 3.5.7 and 3.5.9 were available | `KEYSTORE_LIVE=1 go test -tags integration -count=1 -v ./integration/interop/` on that machine (skips if no Ed25519) |
| Package mirrors offline | the Linux tier installs bash/openssl/setpriv at run time | rerun `integration/run.sh` with network; a skip says so |
| Cross-process contention, SIGKILL loops, agent chaos | wave 7 | not yet built |
