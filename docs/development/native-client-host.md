# Native authenticated client host composition

`DnssecClientHost.CreateAsync` explicitly composes a proof-aware acknowledged
trust-epoch resolver, complete-TCP request processor and native UDP/TCP listener.
All roots, bind endpoints, authority ports, access grants and software budgets
come from caller inputs. The factory opens no listener; `RunAsync` starts the
one-use lifetime. `WaitForBoundAsync` returns a cloned historical bind observation.
It does not certify readiness, routing or peer identity.

The host owns the three newly constructed components. Construction failure
closes every acquired component. Run completion and repeated disposal include
listener calls, processor requests and independent coalesced epoch workers.
Cleanup attempts every owner even after an earlier fault and preserves those
failures. A borrowed provider that ignores cancellation can hold shutdown
indefinitely. These quotas are admission policies, not physical capacity or hard
CPU, heap or progress bounds.

The caller retains the refresher, checkpoint store, verifier, upstream transport
and clocks. The caller must provide coherent clocks, exclusive refresh/store
ownership, acknowledged current anchors, trusted external rollback floors and
independent key custody, and must keep those dependencies alive until host
closure settles. This factory does not schedule anchor refresh, maintain an
external floor, migrate storage, provision keys or dispose borrowed resources.

Only the accepted authenticated query profile is composed here. Ordinary
checking-disabled serving, general DNSSEC security states, production executable
startup/configuration and signal handling remain separate work. IP grants are
not cryptographic peer authentication or name authorization. Selected signature
candidates are not individual successful-signature certificates.

Returned or acknowledged bytes remain historical observations. Current epoch,
access, transport and freshness requirements still apply at actual delivery;
delayed writes and later acknowledgements do not establish atomic fresh delivery
or peer receipt. This library composition does not install, publish or allocate a
service.
