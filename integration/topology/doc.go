// Package topology is the real-topology test tier (audit wave L3b). keystore is not a
// cluster, but it is many real processes sharing one ring file and one agent socket, and
// an in-process test stubs exactly what matters there: the disk, the process boundary and
// the kernel's peer credentials. This tier runs the built `keystore` and `keystore-agent`
// binaries as real processes on a real filesystem, kills them with a real SIGKILL, and
// connects over real unix sockets, on macOS and inside a Linux container.
//
// Every file in the package is guarded by the `topology` build tag and by
// KEYSTORE_TOPOLOGY=1, so a plain `go test ./...` does not see it. See
// docs/audits/topology-integration.md and scripts/topology.sh.
package topology
