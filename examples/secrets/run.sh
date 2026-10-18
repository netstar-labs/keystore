#!/usr/bin/env bash
# A workload loads an opaque secret from the ring at start-up, uses it, and drops it.
. "$(dirname "$0")/../_lib/common.sh"

RING=$WORK/app.ks
PASS=$WORK/pass
KEY='example-hmac-key-0123456789abcdef'
passfile 'secrets example passphrase' "$PASS"

step "operator: create the ring and store the HMAC key (base64 on stdin, never on argv)"
keystore init -keystore "$RING"
printf %s "$KEY" | base64 | keystore import-secret -keystore "$RING" -passfile "$PASS" -id hmac

step "workload: unlock at start-up, tag a message, drop the key"
TAG=$(cd "$ROOT" && go run ./examples/secrets -keystore "$RING" -id hmac -passfile "$PASS" -msg "order 42")
echo "tag: $TAG"

# Demo-only test oracle: this puts the HMAC key on openssl's argv, where other users can read
# it in ps. Never copy this into real code; real secrets never go on a command line.
if command -v openssl >/dev/null; then
    WANT=$(printf %s "order 42" | openssl dgst -sha256 -hmac "$KEY" | awk '{print $NF}')
    [ "$TAG" = "$WANT" ] || fail "tag $TAG, openssl says $WANT"
    ok "matches an independent HMAC-SHA256 (openssl)"
else
    echo "openssl not available; skipped the independent check"
fi

step "failure modes"
passfile 'not the right passphrase' "$WORK/bad"
expect_refusal "wrong passphrase" "wrong passphrase" \
    bash -c "cd '$ROOT' && go run ./examples/secrets -keystore '$RING' -id hmac -passfile '$WORK/bad' -msg m"
expect_refusal "missing secret" "no such entry" \
    bash -c "cd '$ROOT' && go run ./examples/secrets -keystore '$RING' -id nope -passfile '$PASS' -msg m"

done_ok
