#!/usr/bin/env bash
# A CI job signs a release through the agent; a deploy host verifies before installing.
. "$(dirname "$0")/../_lib/common.sh"

RING=$WORK/release.ks
PASS=$WORK/pass
SOCK=$WORK/run/agent.sock
CI=$WORK/ci            # the CI job's workspace
DEPLOY=$WORK/deploy    # the deploy host
mkdir -p "$CI" "$DEPLOY/trust"
mkdir -m 700 "$WORK/run"

step "one-time: release key in a ring; its public half pinned on deploy hosts"
passfile 'ci release example passphrase' "$PASS"
keystore keygen -keystore "$RING" -passfile "$PASS" -id release-2026 > "$DEPLOY/trust/release.pub"

step "runner host: the agent is the only thing that ever unlocks the key"
start_agent -keystore "$RING" -sock "$SOCK" -passfile "$PASS" -ttl 10m

step "CI job (empty environment: no passphrase, no ring path — only the socket)"
env -i PATH="$PATH" HOME="$CI" SOCK="$SOCK" bash -euo pipefail -c '
    cd "$HOME"
    [ -z "${KEYSTORE_PASSPHRASE:-}" ] && [ -z "${KEYSTORE_FILE:-}" ]
    mkdir -p app && echo "binary v1.2.3" > app/app.bin && echo "config" > app/app.conf
    tar -czf app-1.2.3.tgz app
    # Artifacts can be large; sign a digest manifest, not the artifact.
    if command -v sha256sum >/dev/null; then sha256sum app-1.2.3.tgz; else shasum -a 256 app-1.2.3.tgz; fi > SHA256SUMS
    keystore sign -agent "$SOCK" -in SHA256SUMS -o SHA256SUMS.sig
'
ok "CI produced app-1.2.3.tgz, SHA256SUMS, SHA256SUMS.sig"

# deploy DIR: what a deploy host runs before installing.
deploy() {
    (cd "$1" &&
        keystore verify -pub "$DEPLOY/trust/release.pub" -sig SHA256SUMS.sig -in SHA256SUMS &&
        sha256 -c SHA256SUMS)
}

step "deploy host: verify the manifest signature, then the artifact digest"
cp "$CI"/app-1.2.3.tgz "$CI"/SHA256SUMS "$CI"/SHA256SUMS.sig "$DEPLOY/"
deploy "$DEPLOY"
ok "release verified; safe to install"

step "attacks the deploy host must refuse"
T=$WORK/t1; mkdir "$T"; cp "$DEPLOY"/{app-1.2.3.tgz,SHA256SUMS,SHA256SUMS.sig} "$T/"
echo "backdoor" >> "$T/app-1.2.3.tgz"
expect_refusal "artifact replaced after signing" "FAILED|did NOT match" deploy "$T"

T=$WORK/t2; mkdir "$T"; cp "$DEPLOY"/{app-1.2.3.tgz,SHA256SUMS,SHA256SUMS.sig} "$T/"
echo "backdoor" >> "$T/app-1.2.3.tgz"
sha256 "$T/app-1.2.3.tgz" | sed "s|$T/||" > "$T/SHA256SUMS"
expect_refusal "manifest rewritten to match a replaced artifact" "does not verify" deploy "$T"

T=$WORK/t3; mkdir "$T"; cp "$DEPLOY"/{app-1.2.3.tgz,SHA256SUMS} "$T/"
keystore keygen -keystore "$WORK/attacker.ks" -passfile "$PASS" -id evil >/dev/null
keystore sign -keystore "$WORK/attacker.ks" -passfile "$PASS" -in "$T/SHA256SUMS" -o "$T/SHA256SUMS.sig"
expect_refusal "release signed by another key" "does not verify" deploy "$T"

step "a well-formed signature that does not verify is exit 3, distinct from a check that could not be made (exit 1)"
set +e; (cd "$T" && keystore verify -pub "$DEPLOY/trust/release.pub" -sig SHA256SUMS.sig -in SHA256SUMS) >/dev/null 2>&1; rc=$?
(cd "$T" && keystore verify -pub "$DEPLOY/trust/release.pub" -sig SHA256SUMS.sig -in /nonexistent) >/dev/null 2>&1; rc2=$?; set -e
[ "$rc" = 3 ] || fail "a bad signature exited $rc, want 3"
[ "$rc2" = 1 ] || fail "an unreadable input exited $rc2, want 1"
ok "bad signature: exit 3; unreadable input: exit 1"

step "agent down: the CI job cannot sign, so nothing unsigned ships"
stop_agent
expect_refusal "signing with the agent stopped" "no such file|connection refused" \
    keystore sign -agent "$SOCK" -in "$CI/SHA256SUMS"

done_ok
