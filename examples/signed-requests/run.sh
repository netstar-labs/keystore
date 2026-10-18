#!/usr/bin/env bash
# Service A signs HTTP requests through the agent; service B verifies with A's public key.
. "$(dirname "$0")/../_lib/common.sh"

RING=$WORK/svc-a.ks
PASS=$WORK/pass
SOCK=$WORK/run/agent.sock
passfile 'signed requests example passphrase' "$PASS"
keystore keygen -keystore "$RING" -passfile "$PASS" -id svc-a > "$WORK/svc-a.pub"
mkdir -m 700 "$WORK/run"

step "service A's host runs the agent"
start_agent -keystore "$RING" -sock "$SOCK" -passfile "$PASS" -ttl 2m

step "service A signs requests; service B verifies with only svc-a.pub"
(cd "$ROOT" && go run ./examples/signed-requests -sock "$SOCK" -pub "$WORK/svc-a.pub")

step "with the agent gone, service A cannot sign at all"
stop_agent
expect_refusal "signing with no agent" "cannot reach its signer" \
    bash -c "cd '$ROOT' && go run ./examples/signed-requests -sock '$SOCK' -pub '$WORK/svc-a.pub'"

done_ok
