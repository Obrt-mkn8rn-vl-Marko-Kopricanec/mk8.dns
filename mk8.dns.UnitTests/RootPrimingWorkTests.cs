using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RootPrimingWorkTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedFirstAttemptVisitsDifferentConfiguredEndpoint(bool nsFailure)
    {
        using var fixture = new RootPrimingFixture();
        var first = new DnsServerEndpoint([127, 0, 0, 2], 5300);
        var failed = false;
        fixture.Override = (question, server, _) =>
        {
            if (!failed && question.Type == (nsFailure ? 2 : 48))
            {
                failed = true;
                return ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException("Controlled failed bootstrap attempt."));
            }
            return ValueTask.FromResult(fixture.Default(question, server));
        };
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer(bootstrap: [first, RootPrimingFixture.Server]).PrimeAsync(CancellationToken.None));
        Assert.NotEqual(fixture.Calls.First().Server, result.Source);
        Assert.Equal(nsFailure ? 4 : 3, fixture.Calls.Count);
        Assert.Equal(fixture.Calls.Last().Server, result.Source);
    }

    [Theory]
    [InlineData(1, 512)]
    [InlineData(128, 1)]
    [InlineData(3, 512)]
    public async Task SharedWorkBudgetRefusesWithoutPartialSnapshot(int exchanges, int attempts)
    {
        using var fixture = new RootPrimingFixture(1) { Additional = [] };
        var verifier = new DnssecChainFixture.CountingVerifier();
        Assert.Null(await fixture.Primer(exchanges: exchanges, attempts: attempts, verifier: verifier).PrimeAsync(CancellationToken.None));
        Assert.True(fixture.Calls.Count <= exchanges);
        Assert.True(verifier.Calls <= attempts);
    }

    [Fact]
    public async Task CancellationRetainsActualIgnoringUpstreamUntilCompletion()
    {
        using var fixture = new RootPrimingFixture();
        using var cancellation = new CancellationTokenSource();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (_, _, _) => new ValueTask<DnsUpstreamEvidence>(held.Task);
        var operation = fixture.Primer().PrimeAsync(cancellation.Token).AsTask();
        try
        {
            Assert.Single(fixture.Calls);
            await cancellation.CancelAsync().ConfigureAwait(true);
            Assert.False(operation.IsCompleted);
        }
        finally
        {
            held.TrySetResult(fixture.Default(new DnsQuestion(RootPrimingFixture.Root, 48, 1), RootPrimingFixture.Server));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5))).ConfigureAwait(true);
        }
        Assert.Single(fixture.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public void InvalidBoundsOrBootstrapRefuseBeforeAnyQuery(int invalid)
    {
        using var fixture = new RootPrimingFixture();
        if (invalid < 5)
            Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecRootPrimer(fixture, DnssecFixture.Verifier,
                new DnssecTrustAnchor(fixture.Dnskey), [RootPrimingFixture.Server], authorityPort: invalid == 0 ? (ushort)0 : (ushort)53,
                maximumExchanges: invalid == 1 ? 0 : invalid == 2 ? 257 : 128,
                maximumVerificationAttempts: invalid == 3 ? 0 : invalid == 4 ? 4097 : 512));
        else
            Assert.Throws<ArgumentException>(() => fixture.Primer(bootstrap: invalid == 5 ? [] : invalid == 6
                ? [RootPrimingFixture.Server, RootPrimingFixture.Server]
                : Enumerable.Range(1, 33).Select(index => new DnsServerEndpoint([127, 0, 0, (byte)index], 5300)).ToArray()));
        Assert.Empty(fixture.Calls);
    }

    [Fact]
    public void NonRootAnchorCannotPrimeRoot()
    {
        using var fixture = new RootPrimingFixture();
        Assert.Throws<ArgumentException>(() => new DnssecRootPrimer(fixture, DnssecFixture.Verifier,
            new DnssecTrustAnchor(fixture.Dnskey.WithOwner(DnsName.Parse("example."))), [RootPrimingFixture.Server]));
        Assert.Empty(fixture.Calls);
    }
}
