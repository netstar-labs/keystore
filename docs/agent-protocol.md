# Agent protocol (normative)

`keystore-agent` serves one Ed25519 key over a unix stream socket.

## Socket

- Created mode 0600 (under `umask 0177`, then `chmod`) in a directory owned by the agent's
  user with no group or other permissions; the agent refuses any other directory.
- The agent owns the path through an exclusive `flock` on `<socket>.lock`, held for its
  whole life. A second agent — even one starting at the same instant — refuses to start and
  never touches the socket. Without the lock held, a socket something still answers on is
  also refused; a stale one is removed; any non-socket file at the path is refused.
- The socket is removed when the agent stops: SIGINT, SIGTERM, `-ttl` or `-idle` expiry.

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
| `'P'` (0x50) | empty | the 32-byte Ed25519 public key |
| `'S'` (0x53) | the message (≤ 1 MiB) | the 64-byte pure-Ed25519 signature over the message (RFC 8032, no prehash, no context) |

## Replies

| `b0` | Meaning | Payload |
|---|---|---|
| `0x00` | ok | as above |
| `0x01` | error | a short ASCII message; never secret material |

An unknown operation gets an error reply and the connection is closed.

## Lifetime

`-ttl D` stops the agent `D` after start; `-idle D` stops it after `D` with no successful
request. `0` disables either. On expiry, SIGINT or SIGTERM the agent closes the listener
(removing the socket) **and every open connection**, so a client holding a connection open
cannot extend its life; it then waits for handlers to return (bounded by the deadline),
clears the key, and exits 0.

## Client obligations

The reference client (`pkg/agent.Dial`) verifies every returned signature against the
agent's public key before returning it, and refuses prehash or context options.
