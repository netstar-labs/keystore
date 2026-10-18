#!/usr/bin/env bash
# One-time operator setup: a ring, a signing key, a secret, a passfile; the public key
# published to verifiers. Everything after this runs unattended.
. "$(dirname "$0")/../_lib/common.sh"

RING=$WORK/prod.ks
PASS=$WORK/pass

step "operator: write the passfile (0600) — the ring's ceiling; never back it up with the ring"
passfile 'provision example passphrase' "$PASS"
[ "$(mode "$PASS")" = 600 ] || fail "passfile mode $(mode "$PASS")"
ok "passfile is 0600"

step "operator: mint the signing key straight into an encrypted ring"
keystore keygen -keystore "$RING" -passfile "$PASS" -id prod-2026 > "$WORK/prod-2026.pub"
[ "$(mode "$RING")" = 600 ] || fail "ring mode $(mode "$RING")"
ok "ring is 0600; the private key never touched disk in plaintext"

step "publish the public half (this is what verifiers pin)"
cat "$WORK/prod-2026.pub"

step "mint a secret for the workload (32 random bytes, never printed)"
keystore add-secret -keystore "$RING" -passfile "$PASS" -id hmac-2026

step "inventory — no passphrase needed"
keystore list -keystore "$RING"

step "the ring holds no plaintext"
grep -q 'PRIVATE KEY' "$RING" && fail "plaintext key in the ring"
ok "no PEM, no raw key material in prod.ks"

step "guard rails"
cp "$PASS" "$WORK/loose-pass"; chmod 644 "$WORK/loose-pass"
expect_refusal "a world-readable passfile" "must be 0600" keystore add -keystore "$RING" -passfile "$WORK/loose-pass" -id x
expect_refusal "a short passphrase for a new ring" "at least 12" env KEYSTORE_PASSPHRASE=short keystore keygen -keystore "$WORK/other.ks" -id x
expect_refusal "a second passphrase in the same ring" "does not match this ring" env KEYSTORE_PASSPHRASE='some other passphrase' keystore add -keystore "$RING" -id y
expect_refusal "re-initialising an existing ring" "already exists" keystore init -keystore "$RING"

done_ok
