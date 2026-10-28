# Official core observation client

This package independently implements the public sing-box 1.14.0/1.14.3
gRPC-Web observation wire contract using only the Go standard library. It does
not link sing-box, vendor its generated protobuf files, or expose a control API.

The server configuration is a top-level `services` item:

```json
{"type":"api","tag":"qingnode-api","listen":"127.0.0.1","listen_port":18088,"secret":"a-locally-generated-nonempty-secret"}
```

The official API is an HTTP listener with native gRPC and gRPC-Web support.
Clients send `Authorization: Bearer <secret>`. An empty upstream secret disables
authentication; this client rejects empty secrets. Endpoint URLs require a
literal loopback IP and explicit port. Environment proxies and HTTP redirects
are disabled. The client sends binary `application/grpc-web+proto` requests to:

| Method | Purpose |
| --- | --- |
| `/daemon.StartedService/SubscribeStatus` | Global status, cumulative upload/download |
| `/daemon.StartedService/SubscribeConnections` | Reset snapshot and unsequenced lifecycle/traffic events |
| `/daemon.StartedService/GetStartedAt` | Attached API service start time in Unix milliseconds |

Subscription interval fields are durations in nanoseconds. Streams have an
absolute timeout, frame limit, frame size limit, and total byte limit. Unknown
protobuf fields are skipped; malformed or compressed frames are rejected.
Unavailable statistics and authentication rejection are distinct errors. A
false `trafficAvailable` is never converted into a zero measurement.

Configuring the official API service enables the upstream traffic manager;
neither a Clash listener nor a V2Ray API listener is needed. Global totals retain
closed-connection traffic even after the bounded closed history is evicted.
They are observations of one core lifetime, not durable billing data.

`StatusCounter` takes an explicit lifetime identity supplied by the caller.
Combine process PID/start identity with `StartedAt` when persistence matters.
The first sample and every new lifetime establish a baseline; historical bytes
are not counted again. Same-lifetime reconnects can recover a cumulative global
difference. Repeated samples add nothing. Counter regression retains the old
high-water baseline and reports an error until the caller can prove a new core
lifetime. Epoch changes and transport gaps remain explicit.

Connection reset snapshots replace the current observation and can include
active connections plus at most 1,000 recently closed connections. UPDATE
events contain deltas without sequence numbers. Disconnects, loss, duplicates,
and limited history prevent accurate reconstruction of per-user accounting.
`ConnectionView` deliberately never adds UPDATE deltas to absolute byte totals.
Map `inbound` and scoped `user` labels only through a locally managed exact
mapping; missing labels or mappings resolve to `unknown`.

The source contract was checked against these official fixed commits:

- [1.14.0](https://github.com/SagerNet/sing-box/tree/0b8995879f29a9b98ee027bc17b75e101445b238)
- [1.14.3](https://github.com/SagerNet/sing-box/tree/7054cac5124465ffdb145870d7c01885566711b1)

Relevant files are `option/api.go`, `docs/configuration/service/api.md`,
`daemon/started_service.proto`, `daemon/started_service.go`, `daemon/server.go`,
`daemon/attached_service.go`, `daemon/instance.go`, `service/api/server.go`,
`service/api/web_bridge.go`, `box.go`, and `common/trafficcontrol/manager.go`.
Upstream source remains GPL-3.0-or-later and is reference material outside this
repository; this package incorporates no upstream source or generated code.

`go test ./internal/coreapi` uses controlled loopback HTTP fixtures. The opt-in
`TestOfficialCoreGRPCWebObservation` additionally runs a separately verified
official binary named by `SING_BOX_BIN`. It checks the official parser, absent
and incorrect auth rejection, real status capability, local proxy transfer
counts, inbound/user labels, and reset/reconnect behavior. Without that variable
the real-core test explicitly skips. A version string by itself does not prove
the executable's provenance. The test starts an isolated loopback process and
does not change the host service, network configuration, firewall, or VM state.
