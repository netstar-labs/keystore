# Agent protocol (normative)

`keystore-agent` serves one Ed25519 key over a unix stream socket.

## Socket

- Created mode 0600 (under `umask 0177`, then `chmod`) in a directory owned by the agent's
  user with no group or other permissions; the agent refuses any other directory.
- The socket's directory must already exist (the agent does not create it), and the whole
  socket path must fit the OS limit for a unix socket address: at most 103 bytes on macOS, 107
  on Linux. A longer path is refused with an error naming the limit, before anything is
  created.
- The agent owns the path through an exclusive `flock` on `<socket>.lock`, held for its
  whole life. A second agent — even one starting at the same instant — refuses to start and
  never touches the socket. Without the lock held, a socket something still answers on is
  also refused; a stale one is removed; any non-socket file at the path is refused.
- The socket is removed when the agent stops: SIGINT, SIGTERM, SIGHUP (a closed terminal; there is no reload; ignored if inherited as ignored, as under `nohup`), `-ttl` or `-idle` expiry.

## Peer check

On every accepted connection the agent reads the peer's uid from the kernel
(`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on Darwin) and closes the connection without a
reply unless it equals its own. Clients perform the same check on the agent.

## Framing

Both directions use the same frame:

```
[b0 : 1 byte][len : 4 bytes, big-endian][payload : len bytes]      len ≤ 1 MiB (1048576)
```

A frame with `len` over the limit is answered with an error status and the connection is
closed. Each request has a per-request read/write deadline (default 5 s). A connection may
carry several requests in sequence; clients use one per connection.

## Requests

| `b0` | Payload | Reply payload on success |
|---|---|---|
| `'P'` (0x50) | none; any payload sent is ignored | the 32-byte Ed25519 public key |
| `'S'` (0x53) | the message (≤ 1 MiB) | the 64-byte pure-Ed25519 signature over the message (RFC 8032, no prehash, no context) |

## Replies

| `b0` | Meaning | Payload |
|---|---|---|
| `0x00` | ok | as above |
| `0x01` | error | a short ASCII message; never secret material |

An unknown operation gets an error reply and the connection is closed.

## Lifetime

`-ttl D` stops the agent `D` after start; `-idle D` stops it after `D` with no successful
request (every successful request counts, `'P'` included; `-ttl` is the hard stop). `0`
disables either; a negative value is refused (exit 1). Omitting the flags is not "no limit":
`keystore-agent` defaults to `-ttl 8h -idle 30m`, so an agent started without them stops, exit 0,
after 8 hours or after 30 minutes without a request (`keystore-agent -h` shows the defaults). On expiry, SIGINT, SIGTERM, or SIGHUP (not if SIGHUP was inherited as ignored) the
agent closes the listener (removing the socket) **and every open connection**, so a client
holding a connection open cannot extend its life; it then waits for handlers to return
(bounded by the deadline), clears the key, and exits 0.

Running out of file descriptors (EMFILE/ENFILE) on `accept` is logged and retried. Any
other accept error stops the agent the same way (socket removed, connections closed, key
cleared) and it exits 1.

Every 10 seconds the agent checks that the file at its socket path is still the socket it
created. If it was removed or replaced (a temp-file cleaner, a stray `rm`) nothing can reach
the agent any more, so it logs that, stops the same way and exits 1, instead of holding the
key indefinitely (the shipped service units run with `-ttl 0 -idle 0`). A file that replaced
its socket is left alone.

## Client obligations

The reference client (`pkg/agent.Dial`) verifies every returned signature against the
agent's public key before returning it, and refuses prehash or context options.

`Dial` does not pin the agent's key: it trusts whatever 32-byte key the agent returns for
`'P'` and checks signatures only against it. A caller that wants a specific key compares
`Public()` with the key it expects.
