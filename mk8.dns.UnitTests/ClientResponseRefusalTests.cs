using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientResponseRefusalTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task CompleteQuestionIdentityMustMatch(int difference)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        var expected = difference switch
        {
            0 => ClientProofFixture.Question("other.example."),
            1 => ClientProofFixture.Question(type: 28),
            _ => new DnsQuestion(question.Name, question.Type, 3),
        };
        Assert.False(DnssecClientResponseProjection.TryPrepare(result, expected, dnssecOk: true, out var snapshot));
        Assert.Null(snapshot);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OrdinaryDirectAndCachedResultsCannotBePromoted(bool cached)
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(ClientProofFixture.Resolver(fixture));
        await using var lifetime = cache.ConfigureAwait(true);
        var question = ClientProofFixture.Question();
        var result = cached ? await cache.ResolveDnssecAsync(question, CancellationToken.None)
            : await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Null(result.ClientProof);
        Assert.False(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk: false, out var snapshot));
        Assert.Null(snapshot);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailureAndUnsignedMarkerCannotSupplyDeliveryMaterial(bool delegationUnsigned)
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = delegationUnsigned };
        var question = ClientProofFixture.Question("www.child.example.");
        var resolver = ClientProofFixture.Resolver(fixture, attempts: delegationUnsigned ? 512 : 1);
        var result = await resolver.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(delegationUnsigned ? DnssecResolutionOutcome.UnsignedDelegation : DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.False(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk: true, out var snapshot));
        Assert.Null(snapshot);
    }
}
