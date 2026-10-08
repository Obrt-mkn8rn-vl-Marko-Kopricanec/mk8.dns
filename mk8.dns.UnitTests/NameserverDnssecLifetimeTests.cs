using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NameserverDnssecLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RoutingExpiryWhileFetchingChildKeysFailsClosed(bool wall)
    {
        using var fixture = new NameserverDnssecFixture { AddressWindow = new DnssecSignatureWindow(99, 101) };
        fixture.Override = (question, server, _) =>
        {
            if (server.Equals(fixture.ChildServer) && question.Type == 48)
            {
                if (wall) fixture.Clock.SetWall(102);
                else fixture.Clock.Advance(301);
            }
            return ValueTask.FromResult(fixture.Default(question, server));
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Fact]
    public async Task RoutingDataAgesAcrossChildQueries()
    {
        using var fixture = new NameserverDnssecFixture { AddressTtl = 7 };
        fixture.Override = (question, server, _) =>
        {
            if (server.Equals(fixture.ChildServer) && question.Type == 48) fixture.Clock.Advance(2);
            return ValueTask.FromResult(fixture.Default(question, server));
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(5U, result.AuthenticatedTtl); Assert.Equal(5U, Assert.Single(result.Answers).Ttl);
    }

    [Fact]
    public async Task CancellationDoesNotDetachAnIgnoringAddressProvider()
    {
        using var fixture = new NameserverDnssecFixture(); using var cancellation = new CancellationTokenSource();
        var admitted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (question, server, _) =>
        {
            if (question.Name.Equals(fixture.Target) && server.Equals(NameserverDnssecFixture.ProviderServer))
            {
                admitted.SetResult(); return new ValueTask<DnsUpstreamEvidence>(finish.Task);
            }
            return ValueTask.FromResult(fixture.Default(question, server));
        };
        var resolving = fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, cancellation.Token).AsTask();
        try
        {
            await admitted.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true);
            await cancellation.CancelAsync().ConfigureAwait(true); Assert.False(resolving.IsCompleted);
        }
        finally
        {
            finish.TrySetResult(fixture.Default(new DnsQuestion(fixture.Target, 1, 1), NameserverDnssecFixture.ProviderServer));
            OperationCanceledException? terminal = null;
            try { await resolving.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true); }
            catch (OperationCanceledException error) { terminal = error; }
            Assert.IsAssignableFrom<OperationCanceledException>(terminal);
        }
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(fixture.ChildServer));
    }
}
