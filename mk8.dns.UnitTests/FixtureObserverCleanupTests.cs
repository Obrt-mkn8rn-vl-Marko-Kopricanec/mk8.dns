using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class FixtureObserverCleanupTests
{
    [Fact]
    public async Task PublicationObserverFaultStillReleasesAndJoinsTheAdmittedActivation()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fixture = new PublicationFixture(async _ =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(true);
        });
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var publisherLifetime = publisher.ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        var activation = publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).AsTask();
        var observerFault = new InvalidOperationException("Owned observation fault.");
        var observed = await Assert.ThrowsAsync<InvalidOperationException>(() => TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
            throw observerFault;
        }, async () =>
        {
            release.TrySetResult();
            var disposal = publisher.DisposeAsync().AsTask();
            Assert.Equal("activated", (await activation.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true)).State);
            await disposal.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
        })).ConfigureAwait(true);
        Assert.Same(observerFault, observed);
        Assert.True(activation.IsCompletedSuccessfully);
        Assert.Equal(1, (await fixture.Store.ReadActiveAsync(PublicationFixture.ZoneId, CancellationToken.None).ConfigureAwait(true))!.Revision);
    }

    [Fact]
    public async Task RefreshObserverFaultJoinsSourceAndSessionBeforeBorrowedKeysRetire()
    {
        using var fixture = new AnchorRefreshFixture();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reply = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Upstream.Override = (_, _, _) => { entered.TrySetResult(); return new(reply.Task); };
        await using var session = fixture.Create();
        var refresh = session.RefreshAsync(CancellationToken.None).AsTask();
        var observerFault = new InvalidOperationException("Owned refresh observation fault.");
        var observed = await Assert.ThrowsAsync<InvalidOperationException>(() => TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, fixture.Keys.Clock).ConfigureAwait(true);
            throw observerFault;
        }, async () =>
        {
            reply.TrySetResult(fixture.Reply());
            var disposal = session.DisposeAsync().AsTask();
            Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await refresh.WaitAsync(AnchorRefreshFixture.Timeout, fixture.Keys.Clock).ConfigureAwait(true));
            await disposal.WaitAsync(AnchorRefreshFixture.Timeout, fixture.Keys.Clock).ConfigureAwait(true);
        })).ConfigureAwait(true);
        Assert.Same(observerFault, observed);
        Assert.True(refresh.IsCompletedSuccessfully);
        Assert.Equal(0, fixture.Store.Commits);
    }
}
