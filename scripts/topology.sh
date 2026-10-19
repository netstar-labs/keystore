#!/bin/sh
# Driver for the real-topology tier (docs/audits/topology-integration.md).
#
#   scripts/topology.sh mac        build the binaries and run the tier on this machine's filesystem
#   scripts/topology.sh container  cross-build for linux/arm64 and run the same tier inside an
#                                  Apple `container` (alpine; the container's own ext4 root
#                                  filesystem, not the host mount, holds every ring and socket)
#   scripts/topology.sh all        both
#
# Knobs (environment): TOPO_RUN (a go test -run regexp, default all), TOPO_OUTDIR (where the
# binaries and results.jsonl go, default a fresh temp dir), and the scale variables read by
# the tests: TOPO_WORKERS, TOPO_OPS, TOPO_ITERS, TOPO_LANES, TOPO_SEED, TOPO_TTL_ROUNDS,
# TOPO_RACE_ROUNDS, TOPO_RACERS, TOPO_STALE_ROUNDS, TOPO_CLIENTS, TOPO_FLEET.
#
# Nothing here touches the macOS login keychain: the tests give every child a clean
# environment (no KEYSTORE_KEYCHAIN) and only ever use KEYSTORE_PASSPHRASE.
set -eu
cd "$(dirname "$0")/.."
export GOWORK=off
mode=${1:-mac}
out=${TOPO_OUTDIR:-$(mktemp -d)}
run=${TOPO_RUN:-.}
mkdir -p "$out"
echo "topology: results in $out" >&2

mac() {
	mkdir -p "$out/mac"
	go build -o "$out/mac/keystore" ./cmd/keystore
	go build -o "$out/mac/keystore-agent" ./cmd/keystore-agent
	KEYSTORE_TOPOLOGY=1 TOPO_BIN="$out/mac" TOPO_OUT="$out/results-mac.jsonl" \
		go test -tags topology -count=1 -timeout 4h -v -run "$run" ./integration/topology
}

container_run() {
	mkdir -p "$out/linux"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "$out/linux/keystore" ./cmd/keystore
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "$out/linux/keystore-agent" ./cmd/keystore-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -tags topology -o "$out/linux/topology.test" ./integration/topology
	name="topo-$$"
	trap 'container rm -f "$name" >/dev/null 2>&1 || true' EXIT INT TERM
	envs=""
	for v in $(env | sed -n 's/^\(TOPO_[A-Z_]*\)=.*/\1/p' | grep -vE '^TOPO_(BIN|DIR|OUT|OUTDIR|RUN)$'); do
		eval "val=\${$v}"
		envs="$envs -e $v=$val"
	done
	# Binaries are copied off the virtiofs mount onto the container's own filesystem; the
	# work directory /work is on that ext4 root filesystem too.
	# shellcheck disable=SC2086
	container run --rm --name "$name" -c 5 -m 4G $envs -v "$out/linux:/topo" alpine:latest sh -c '
		set -e
		cp /topo/keystore /topo/keystore-agent /topo/topology.test /usr/local/bin/
		chmod 755 /usr/local/bin/keystore /usr/local/bin/keystore-agent /usr/local/bin/topology.test
		mkdir -p /work && chmod 755 /work
		echo "container: $(uname -srm); work fs: $(mount | grep " / " | cut -d" " -f1,5)" >&2
		cd /work
		KEYSTORE_TOPOLOGY=1 TOPO_BIN=/usr/local/bin TOPO_DIR=/work TOPO_OUT=/topo/results-linux.jsonl \
			/usr/local/bin/topology.test -test.v -test.count=1 -test.timeout 4h -test.run "'"$run"'"
	'
	cp "$out/linux/results-linux.jsonl" "$out/" 2>/dev/null || true
}

case "$mode" in
mac) mac ;;
container) container_run ;;
all) mac; container_run ;;
*) echo "usage: $0 mac|container|all" >&2; exit 2 ;;
esac
