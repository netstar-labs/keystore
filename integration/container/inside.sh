#!/bin/sh
# Runs INSIDE the Linux container (as root), started by integration/linux_test.go.
# /opt/ks (read-only): bin/ (keystore, keystore-agent, example binaries), shim/go, tests/*.test,
# manifest ("name<TAB>pkg dir"). /src (read-only): the repository, for testdata and run.sh.
# Prints KSL3 markers that the host-side classifier reads; exit 77 means "environment, skip".
KS=/opt/ks
echo "KSL3 BEGIN $(. /etc/os-release; echo "$PRETTY_NAME") $(uname -m) kernel $(uname -r)"

prep() {
    if command -v apk >/dev/null; then
        apk add --no-cache bash openssl setpriv >/tmp/prep.log 2>&1
    elif command -v apt-get >/dev/null; then
        { apt-get update -qq && apt-get install -y -qq --no-install-recommends openssl; } >/tmp/prep.log 2>&1
    fi
}
if ! prep || ! command -v bash >/dev/null || ! command -v setpriv >/dev/null || ! command -v openssl >/dev/null; then
    echo "KSL3 SKIP cannot install bash/setpriv/openssl (network?): $(tail -n 2 /tmp/prep.log | tr '\n' ' ')"
    exit 77
fi
# busybox ships a setpriv that lacks --reuid and can shadow util-linux's; find one that works.
SETPRIV=
for c in /usr/bin/setpriv /bin/setpriv /usr/sbin/setpriv; do
    if [ -x "$c" ] && "$c" --reuid=0 true 2>/dev/null; then SETPRIV=$c; break; fi
done
[ -n "$SETPRIV" ] || { echo "KSL3 SKIP no setpriv with --reuid available"; exit 77; }
echo "KSL3 INFO $(openssl version) setpriv=$SETPRIV"

leg() {
    uid=$1
    home=/tmp/home-$uid
    mkdir -p "$home" && chown "$uid:$uid" "$home" && chmod 700 "$home"
    if [ "$uid" = 0 ]; then pre=""; else pre="$SETPRIV --reuid=$uid --regid=$uid --clear-groups"; fi
    # The manifest is read on fd 3 and every test binary gets /dev/null as stdin: a test that
    # reads stdin must not be able to eat the remaining manifest lines and so shorten the run.
    while IFS='	' read -r name dir <&3; do
        out=$(cd "/src/$dir" && $pre env HOME="$home" TMPDIR=/tmp \
            PATH="$KS/shim:$KS/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
            KEYSTORE_LIVE=1 KEYSTORE_BIN="$KS/bin" \
            "$KS/tests/$name.test" -test.count=1 -test.v -test.timeout=15m </dev/null 2>&1)
        rc=$?
        echo "KSL3 RESULT uid=$uid pkg=$dir rc=$rc"
        echo "KSL3 COUNTS uid=$uid pkg=$dir pass=$(printf '%s\n' "$out" | grep -c -- '^--- PASS') skip=$(printf '%s\n' "$out" | grep -c -- '^--- SKIP') fail=$(printf '%s\n' "$out" | grep -c -- '^--- FAIL')"
        if [ "$rc" -ne 0 ]; then printf '%s\n' "$out" | tail -n 80; fi
        # skip reasons are evidence too: a skipped test is not a passed one
        printf '%s\n' "$out" | grep -E -- '^\s+.*_test.go:[0-9]+: ' | grep -i skip | sed "s#^#KSL3 SKIPPED uid=$uid pkg=$dir #" | head -n 40
    done 3<"$KS/manifest"
}

leg 0
leg 1000
echo "KSL3 DONE"
