using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustEpochAdmissionTests
{
    [Fact]
    public async Task ExplicitMinimisationPolicyCannotFallBackFromUnprovedNsDiscovery()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true);
        var resolver = f.Create(new DnssecTrustEpochPolicy(minimisation: new DnsQnameMinimisationPolicy()));
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Collection(f.Calls, q => Assert.Equal((ushort)48, q.Type), q => Assert.Equal((ushort)2, q.Type));
        Assert.Equal(0, resolver.Statistics.Entries);
    }

    [Fact]
    public async Task BootstrapEndpointCollectionIsOwnedBeforeCallerMutation()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true);
        DnsServerEndpoint[] endpoints = [AnchorRefreshFixture.Server];
        var resolver = new DnssecTrustEpochResolver(f.Refresh, f.Anchors.Upstream, f.Verifier, endpoints, new DnssecTrustEpochPolicy());
        await using var resolverLifetime = resolver.ConfigureAwait(false);
        endpoints[0] = new DnsServerEndpoint([127, 0, 0, 2], 5300);
        f.Anchors.Upstream.Override = (question, server, _) =>
        {
            Assert.Equal(AnchorRefreshFixture.Server, server);
            return ValueTask.FromResult(f.Default(question, server));
        };
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(2, f.Anchors.Upstream.Calls);
    }

    [Theory]
    [InlineData(0, 4096, 16777216, 86400u, 3600u, 64, 16, 512)]
    [InlineData(257, 4096, 16777216, 86400u, 3600u, 64, 16, 512)]
    [InlineData(64, 0, 16777216, 86400u, 3600u, 64, 16, 512)]
    [InlineData(64, 65537, 16777216, 86400u, 3600u, 64, 16, 512)]
    [InlineData(64, 4096, 0, 86400u, 3600u, 64, 16, 512)]
    [InlineData(64, 4096, 536870913, 86400u, 3600u, 64, 16, 512)]
    [InlineData(64, 4096, 16777216, 0u, 3600u, 64, 16, 512)]
    [InlineData(64, 4096, 16777216, 604801u, 3600u, 64, 16, 512)]
    [InlineData(64, 4096, 16777216, 86400u, 86401u, 64, 16, 512)]
    [InlineData(64, 4096, 16777216, 1u, 2u, 64, 16, 512)]
    [InlineData(64, 4096, 16777216, 86400u, 3600u, 0, 16, 512)]
    [InlineData(64, 4096, 16777216, 86400u, 3600u, 257, 16, 512)]
    [InlineData(64, 4096, 16777216, 86400u, 3600u, 64, 0, 512)]
    [InlineData(64, 4096, 16777216, 86400u, 3600u, 64, 33, 512)]
    [InlineData(64, 4096, 16777216, 86400u, 3600u, 64, 16, 0)]
    [InlineData(64, 4096, 16777216, 86400u, 3600u, 64, 16, 4097)]
    public void InvalidPolicyCannotAdmitAnUnboundedCohort(int active, int entries, long bytes, uint positive,
        uint negative, int exchanges, int aliases, int attempts)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecTrustEpochPolicy(active, entries, bytes,
            positive, negative, exchanges, aliases, attempts));

    [Theory]
    [InlineData("www.foreign.", 1, 1)]
    [InlineData("www.example.", 46, 1)]
    [InlineData("www.example.", 1, 3)]
    [InlineData("*.example.", 1, 1)]
    public async Task UnsupportedQuestionsNeitherFetchNorCreateFailureState(string owner, ushort type, ushort dnsClass)
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create(new DnssecTrustEpochPolicy(failureCache: new DnssecFailureCachePolicy()));
        var result = await resolver.ResolveDnssecAsync(new(DnsName.Parse(owner), type, dnsClass), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(f.Calls);
        Assert.Equal(0, resolver.Statistics.FailureEntries); Assert.Equal(0, resolver.Statistics.ActiveRequests);
    }

    [Fact]
    public async Task ClosedAdmissionDoesNoSourceWorkAndRepeatedDisposalSharesCompletion()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        var disposal = resolver.DisposeAsync().AsTask();
        Assert.Same(disposal, resolver.DisposeAsync().AsTask()); await disposal.ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Throws<ObjectDisposedException>(resolver.Clear); Assert.Empty(f.Calls);
        Assert.Equal(0, resolver.Statistics.OwnedProfiles); Assert.Single(f.Refresh.Current.Anchors);
    }
}
