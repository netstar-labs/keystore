#!/usr/bin/env bash
# Runs the live-integration tier (audit L3). Never part of the gate or `go test ./...`:
# it needs the `integration` build tag AND KEYSTORE_LIVE=1, and the Linux tier needs Apple
# `container` with the alpine:latest and debian:trixie-slim images already pulled (it
# never pulls) and network access inside the container to install bash/openssl/setpriv.
# An unavailable runtime, image or package mirror SKIPs with a reason; a failure is keystore's.
#
#   integration/run.sh            Linux containers + OpenSSL interop (host openssl if OpenSSL 3)
#
# The login-keychain test is NOT run by this script. See docs/audits/untestable-without-x.md.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off KEYSTORE_LIVE=1
exec go test -tags integration -count=1 -v -timeout 60m ./integration/ ./integration/interop/
