# Shared prelude for the example scripts. Source it; do not run it.
#
# Builds keystore and keystore-agent into a private temp dir, puts them first on PATH,
# and removes everything (and stops any agent it started) on exit.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[1]}")/../.." && pwd)
# Short path under /tmp: unix socket paths are limited to ~104 bytes on macOS.
WORK=$(mktemp -d /tmp/keystore-example.XXXXXX)
chmod 700 "$WORK"
AGENT_PID=
cleanup() {
    if [ -n "$AGENT_PID" ]; then kill "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/bin"
(cd "$ROOT" && go build -o "$WORK/bin/" ./cmd/keystore ./cmd/keystore-agent)
PATH="$WORK/bin:$PATH"
# Never inherit a passphrase, keychain or ring from the caller's environment.
unset KEYSTORE_PASSPHRASE KEYSTORE_NEW_PASSPHRASE KEYSTORE_KEYCHAIN KEYSTORE_FILE

step() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; exit 1; }

# expect_fail DESCRIPTION CMD...: the command must fail.
expect_fail() {
    local what=$1; shift
    if "$@" >/dev/null 2>&1; then fail "expected a refusal: $what"; fi
    ok "refused: $what"
}

# expect_refusal DESCRIPTION PATTERN CMD...: the command must fail with stderr/stdout
# matching PATTERN, so a refusal for the wrong reason does not pass.
expect_refusal() {
    local what=$1 pattern=$2; shift 2
    local out
    if out=$("$@" 2>&1); then fail "expected a refusal: $what"; fi
    printf '%s' "$out" | grep -Eq "$pattern" || fail "$what: refused for the wrong reason: $out"
    ok "refused: $what ($pattern)"
}

# passfile PASSPHRASE PATH: write a 0600 passfile.
passfile() { (umask 077; printf '%s\n' "$1" > "$2"); }

# mode PATH: octal permission bits (GNU or BSD stat).
mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

# start_agent ARGS...: run keystore-agent in the background; waits for its socket.
start_agent() {
    local sock=
    local prev=
    for a in "$@"; do [ "$prev" = "-sock" ] && sock=$a; prev=$a; done
    keystore-agent "$@" 2>>"$WORK/agent.log" &
    AGENT_PID=$!
    for _ in $(seq 200); do [ -S "$sock" ] && return 0; sleep 0.05; done
    cat "$WORK/agent.log"; fail "agent socket never appeared"
}

stop_agent() {
    if [ -n "$AGENT_PID" ]; then kill "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; AGENT_PID=; fi
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

done_ok() { printf '\nALL CHECKS PASSED\n'; }
