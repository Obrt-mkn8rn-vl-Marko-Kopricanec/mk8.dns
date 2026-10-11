# Interpreting owned host-process evidence

Integration-test outcomes, owned child exit records and host output describe
separate events. Preserve each original outcome when investigating a failure;
a later exit observation or passing run does not repair that failure.

## What the current fixture records

[HostProcess](../../mk8.dns.IntegrationTests/HostProcess.cs) samples `StartedUtc`
in its field initializer, before `Process.Start`. It samples `CompletedUtc`
during diagnostic serialization after joining process exit and capturing both
output streams. Neither field is an independently recorded native process
start or exit instant. The JSON write itself finishes after that latter sample.

`StopAsync` sends termination to its owned process when it is still running,
then awaits process exit with the supplied token. If that wait is canceled,
the original test failed even if cleanup later captures exit code zero.
Conversely, a shutdown announcement describes entry into shutdown; it does not
establish successful disposal, drain, resource release or process exit.
A forced-cleanup exit must retain its own classification.

The [management restart scenario](../../mk8.dns.IntegrationTests/ManagementGatewayTests.cs)
uses one cancellation guard across startup, readiness, requests, controller
stop/restart and gateway stop/restart. A canceled process-stop wait does not
identify how much of that guard earlier phases consumed, whether cancellation
was already requested at stop entry, or which work delayed exit. Completed
request durations are narrower observations, not total phase durations or a
whole-scenario timeline.

## Correlating observations

Bind the exact source, raw test result and child output bytes before deriving
an association. A shared test-generated socket root, overlapping constructor
samples and the source's role order can identify a candidate child set. State
that basis explicitly: timestamps alone are insufficient, and this association
does not authenticate custody or establish causation.

Keep process-wait completion, later cleanup, output capture and test assertion
results separate. Preserve failed, incomplete and unknown dispositions. Do not
turn absence of a logged exception into a successful drain or infer universal
reaping, stability, performance, capacity or regression exclusion.

## Still-missing attribution

A prospective diagnostic would need distinct observations for phase entry and
completion, cancellation state at entry, signal request and signal-child exit,
owned host exit, and actual callback/work cleanup. It would also need bounded,
non-secret retention tied to the original execution identity. These observations
are not implemented by the current fixture and cannot be reconstructed merely
from its completion timestamp.

Investigate without widening assertions, guards or budgets, automatically
retrying to green, changing unrelated workers or signaling foreign processes.
Documentation-only successors do not change archived build identities: retain
the exact source/artifact pins and original classifications separately.
