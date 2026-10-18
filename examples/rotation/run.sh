#!/usr/bin/env bash
# Zero-downtime rotation by overlap: verifiers trust old and new keys while signing moves
# to the new one; the old key is retired only after nothing needs it.
. "$(dirname "$0")/../_lib/common.sh"

RING=$WORK/prod.ks
PASS=$WORK/pass
TRUST=$WORK/trust        # a verifier's pinned keys: one PEM per key
mkdir -p "$TRUST"
passfile 'rotation example passphrase' "$PASS"
K() { keystore "$1" -keystore "$RING" -passfile "$PASS" "${@:2}"; }   # verbs that unlock
R() { keystore "$1" -keystore "$RING" "${@:2}"; }                       # verbs that never need the passphrase

# verify_any SIG MSG: what a verifier does — accept a signature from any trusted key.
verify_any() {
    for pub in "$TRUST"/*.pub; do
        keystore verify -pub "$pub" -sig "$1" -in "$2" 2>/dev/null && return 0
    done
    echo "no trusted key verifies $1"; return 1
}
sign_now() { printf '%s' "$1" > "$WORK/$2.msg"; K sign -in "$WORK/$2.msg" -o "$WORK/$2.sig" 2>/dev/null; }

step "1. steady state: 2026 key signs; verifiers trust it"
K keygen -id prod-2026 > "$TRUST/prod-2026.pub"
sign_now "made under 2026" old
verify_any "$WORK/old.sig" "$WORK/old.msg"; ok "2026 signature accepted"

step "2. mint the 2027 key beside it (signing does not change yet)"
K add -id prod-2027 > "$WORK/prod-2027.pub"   # add prints the new public key: publish THAT
[ "$(keystore list -keystore "$RING" | awk '$1=="*"{print $2}')" = prod-2026 ] || fail "current moved early"
ok "current is still prod-2026"

step "3. publish 2027's public key; verifiers now trust both"
cp "$WORK/prod-2027.pub" "$TRUST/prod-2027.pub"   # not export-pub: it reads the ring's unauthenticated copy
ls "$TRUST"

step "4. switch signing to 2027 — no verifier notices"
R use -id prod-2027
sign_now "made under 2027" new
verify_any "$WORK/new.sig" "$WORK/new.msg"; ok "2027 signature accepted"
verify_any "$WORK/old.sig" "$WORK/old.msg"; ok "2026 signatures still accepted during the overlap"

step "5. overlap over: retire 2026 everywhere"
R rm -id prod-2026
rm "$TRUST/prod-2026.pub"
keystore list -keystore "$RING"
verify_any "$WORK/new.sig" "$WORK/new.msg"; ok "2027 signatures unaffected"
expect_refusal "a 2026 signature after retirement" "no trusted key" verify_any "$WORK/old.sig" "$WORK/old.msg"
expect_refusal "removing the last signing key without -force" "last signing key" R rm -id prod-2027

done_ok
