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
The one owned refresher supplies its acknowledged checkpoint; `--recursive-config`
does not schedule refreshes. All proof and coalescing clocks use `TimeProvider.System`.
The concrete verifier supports algorithms 8, 13 and 14 under inherited contracts.
The client listener retains its accepted finite authenticated-query profile;
unchecked CD bypass and full security-state/general RFC interoperability remain
outside this startup mode.

## Explicit finite authenticated refresh

`--recursive-refresh-config <absolute-private-file>` is a separate opt-in mode.
It requires all fields above plus a closed `refreshPolicy` object with three
required integer fields: `refreshIntervalSeconds` (3600–1296000),
`retryIntervalSeconds` (3600–86400, no greater than the refresh interval), and
`maximumAttempts` (1–256). Unknown, duplicate, missing or out-of-range fields
refuse startup. The original mode continues to reject `refreshPolicy`.

After opening the existing journal, this mode conservatively checks logical
generation headroom for every configured attempt to commit. The
legacy 256-total-generation cap and the retention format's 256-live-generation
cap remain. Revision overflow also refuses. The check does not certify physical
capacity or pending retention cleanup, reserve against an independent writer,
prove external floor custody, prune generations or perform retention cleanup.
Exclusive logical ownership and an independently
trusted floor remain caller obligations.

The executable owns one finite authenticated-timing poller over the same
refresher used by serving. With no retained acknowledged timing, the explicit
bootstrap policy governs; later acknowledged timing drives the existing adaptive
schedule. The initial interval and independent one-hour spacing remain; there is
no immediate refresh, shortened clock interval or catch-up burst. Refused and
busy attempts count toward the finite cap. Recovered journals invent no timing
receipt. This is finite scheduling, not indefinite RFC5011 service or a refresh
availability SLA.

Completion of the poller's attempt cap ends serving as well. Listener completion,
signal stop, refresh failure or timer failure begins closure of both host and
poller before awaiting either. Actual admitted listener/processor/epoch work and
poller acquisition/commit/timer/cancellation callbacks are joined before the
startup owner closes the refresher and journal. Initiating and cleanup failures
remain non-successful; later teardown cannot turn an unsolicited cancellation
into successful completion. An acknowledged commit remains acknowledged even
if shutdown starts during its return. A borrowed provider ignoring cancellation
can keep this scope and the journal lease alive indefinitely. This mode does not
add provisioning, a floor writer, automatic retention or a perpetual service.

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

Explicit checking-disabled startup uses exactly `--recursive-checking-disabled-config <private-config-path>` and the same required base fields plus a required boolean `checkingDisabledDnssecMaterial`. Existing startup modes reject this field. This mode is separate from finite refresh startup; it does not schedule refreshes.

`false` admits CD1/DO0 with ordinary unvalidated acquisition and refuses CD1/DO1 before upstream work. `true` additionally admits selected unvalidated DNSSEC material for CD1/DO1. Both use the configured roots, authority port, egress predicate and timeout. Their name scope is independent of the validating anchor; CD0 still uses the authenticated acknowledged-epoch path. Unvalidated replies have AD/AA clear, no validation revision/receipt/lease, and no authenticated cache or failure-storage effect. This is not full security-state or general RFC compliance. The same complete-TCP refusal and caller delivery freshness/access/transport obligations apply.

The host owns native admission, processor calls and validating epoch drains. It borrows the ordinary resolver; actual unchecked provider work is joined through the admitted processor call before host closure completes. Ignored provider/clock/I/O cancellation may stall closure indefinitely. No upstream, verifier, refresher, store or clock is disposed by this host, and no key/floor provisioning or retention maintenance is implied.

The unchecked resolver retains its existing finite exchange/alias/dependency limits (64/16/8). `maximumWorkers` and `maximumWaiters` govern the validating coalescer; unchecked work instead remains under shared `maximumRequests` admission and actual call settlement. These counts are software admission limits, not measured CPU, memory, latency or capacity bounds.
