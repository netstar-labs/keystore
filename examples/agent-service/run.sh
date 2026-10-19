#!/usr/bin/env bash
# The agent as a long-running service: unlock once, sign for clients that hold neither
# the key nor the passphrase, refuse to share a socket, and stop on TTL / idle.
. "$(dirname "$0")/../_lib/common.sh"
HERE=$(cd "$(dirname "$0")" && pwd)

RING=$WORK/prod.ks
PASS=$WORK/pass
RUN=$WORK/run
SOCK=$RUN/agent.sock
passfile 'agent service example passphrase' "$PASS"
keystore keygen -keystore "$RING" -passfile "$PASS" -id prod-2026 > "$WORK/prod.pub"
mkdir -m 700 "$RUN"

step "service manager starts the agent (passfile, short TTL for the demo)"
start_agent -keystore "$RING" -id prod-2026 -sock "$SOCK" -passfile "$PASS" -ttl 4s -idle 0
[ "$(mode "$SOCK")" = 600 ] || fail "socket mode $(mode "$SOCK")"
ok "socket is 0600 in a 0700 directory"

step "a client with an empty environment (no passphrase, no ring path) signs through the socket"
printf 'payload' > "$WORK/msg"
env -i PATH="$PATH" HOME="$WORK" keystore sign -agent "$SOCK" -in "$WORK/msg" > "$WORK/msg.sig"
keystore verify -pub "$WORK/prod.pub" -sig "$WORK/msg.sig" -in "$WORK/msg"
ok "signature verifies under the published key"

step "a second agent cannot take over a live socket"
expect_refusal "second agent on a live socket" "already listening" env KEYSTORE_PASSPHRASE='agent service example passphrase' \
    keystore-agent -keystore "$RING" -sock "$SOCK" -ttl 1s

step "socket directory must be private"
mkdir -m 755 "$WORK/open"
expect_refusal "agent in a 0755 directory" "must be 0700" env KEYSTORE_PASSPHRASE='agent service example passphrase' \
    keystore-agent -keystore "$RING" -sock "$WORK/open/agent.sock" -ttl 1s

step "TTL reached: the agent exits 0 and removes its socket"
wait "$AGENT_PID" || fail "agent exited non-zero after TTL"
AGENT_PID=
[ ! -e "$SOCK" ] || fail "socket left behind"
ok "agent stopped cleanly; socket removed"
expect_refusal "signing through an expired agent" "no such file|connection refused" keystore sign -agent "$SOCK" -in "$WORK/msg"

step "idle limit: an unused agent stops by itself"
start_agent -keystore "$RING" -sock "$SOCK" -passfile "$PASS" -ttl 0 -idle 1s
wait "$AGENT_PID" || fail "agent exited non-zero after idle"
AGENT_PID=
[ ! -e "$SOCK" ] || fail "socket left behind after idle"
ok "idle agent stopped; socket removed"

step "service definitions: lint (informational here; CI gates the systemd check)"
if command -v plutil >/dev/null; then plutil -lint "$HERE/local.keystore-agent.plist"; else echo "plutil not available; skipped plist lint"; fi
if command -v systemd-analyze >/dev/null; then
    systemd-analyze verify --user "$HERE/keystore-agent.service" 2>&1 | grep -v 'Executable path' || true
else
    echo "systemd-analyze not available; skipped unit verification"
fi

done_ok
