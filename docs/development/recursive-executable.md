# Explicit recursive executable startup

The Application executable accepts exactly `--recursive-config <absolute-private-file>`
as a separate startup mode. Existing controller and authoritative-replica argument
parsing remains separate. The new Application dependency includes the Recursive
library; Gateway and Operator keep their existing narrow dependencies.

The file is a bounded, owner-only Linux regular JSON file. Every field below is
required; unknown and duplicate fields refuse startup. There are no deployment
addresses, account names, zones, key values or paths supplied by tracked defaults.
Keep deployment configuration outside the tracked tree or in a correctly ignored,
untracked private location. This mode does not authenticate file provisioning,
parent-directory custody or the independently supplied key/floor authority.
Endpoint objects contain `address` and `port`; network objects contain canonical
`address` and `prefix`. Numeric addresses must be unmapped and have no interface
scope. Arrays contain at most sixteen distinct roots or sixty-four distinct
canonical networks. Empty client networks deny everyone.

| Fields | Caller contract |
| --- | --- |
| `storeDirectory`, `storeIdentity`, `origin`, `minimumRevision`, `retention` | Existing authenticated journal, exact nonempty N-format GUID and origin, independently trusted positive revision floor, explicit legacy/retention format selection. |
| `keyFile` | Absolute owner-only regular file containing exactly 32 raw authentication-key bytes. Input bytes are cleared after the store clones them. |
| `listen` | Specific numeric bind address and explicit port 1–65535. Wildcards and ephemeral port allocation are refused by this startup profile. |
| `roots`, `refreshServer`, `authorityPort`, `egressNetworks` | Explicit upstream endpoints and canonical destination-network grants. Every root/refresh endpoint must be granted and use the explicit authority port. Each iterative exchange rechecks this destination policy. |
| `clientNetworks`, `allowAuthenticatedData` | Explicit peer-prefix grants and AD permission. IP membership does not authenticate a peer, authorize names or enforce private networking. A /0 is an explicitly broad caller grant. |
| `maximumRequests`, `udpWorkers`, `maximumTcpConnections`, `maximumTcpMessages` | Request 1–256, UDP worker 1–16, connection 1–64 and per-connection message 1–256 bounds. |
| `maximumWorkers`, `maximumWaiters`, `resolutionTimeoutMilliseconds`, `upstreamTimeoutMilliseconds` | Worker 1–256, waiter 1–65536, resolution 50–120000ms and upstream 50–10000ms work policies. |

Startup validates configuration before reading the key or acquiring a journal
lease. It opens existing storage only: no initialization, anchor selection,
independent floor writer, automatic retention, legacy migration or provisioning.
The one owned refresher supplies its acknowledged checkpoint; this mode does not
schedule refreshes. All proof and coalescing clocks use `TimeProvider.System`.
The concrete verifier supports algorithms 8, 13 and 14 under inherited contracts.
The client listener retains its accepted finite authenticated-query profile;
unchecked CD bypass and full security-state/general RFC interoperability remain
outside this startup mode.

SIGTERM or SIGINT requests cancellation. Shutdown joins the listener, processor
and detached epoch work before closing the refresher and journal lease. Actual
CancelAsync dispatch is retained and observed. The signal-registration source can
dispatch a previously captured callback after registration removal; the shutdown
gate makes that late callback avoid the disposed cancellation source. This is not
an all-callback/native-signal race or hard shutdown-time certificate. Initiating
execution and cleanup failures remain non-successful process outcomes.

Providers, clocks, timers, callbacks, storage and I/O may stall shutdown
indefinitely. Software quotas are not hard CPU, heap, time, capacity or progress
guarantees. Binding and returned/written packets are historical observations;
current delivery access, transport, epoch and freshness obligations remain.
Loopback/reserved values in maintained controls are finite test fixtures, not
allocated deployment inputs.

This source mode does not authorize installation or operation. Public addresses,
secondary authority, provisioning, custodian, certificate and topology decisions
remain unconfirmed. Monday 12 October 2026 at noon Europe/Zagreb (10:00 UTC) is a
deadline and earliest gated window, never a readiness or operational waiver.
