using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofCacheDenialTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CachedWildcardAndNegativeRetainSelectedDenialWithoutNewAcquisition(bool nsec3, bool wildcard)
    {
        using var fixture = new OnlineDnssecFixture();
        using var hashed = new OnlineNsec3Fixture { Wildcard = wildcard };
        var question = ClientProofFixture.Question(wildcard ? "new.example." : "missing.example.");
        var literal = DnssecFixture.A("*.example.");
        DnsRecord[] denial = nsec3 ? hashed.Ring()
            : [OnlineDnssecFixture.Nsec(wildcard ? literal.Owner : fixture.Root, DnsName.Parse("z.example."), wildcard ? [1] : [2, 6, 48])];
        fixture.Transform = reply => reply.Question.Equals(question)
            ? OnlineDnssecFixture.Reply(question, reply.Server,
                wildcard ? [literal.WithOwner(question.Name), fixture.Sign([literal]).WithOwner(question.Name)] : [],
                wildcard ? [.. denial, .. denial.Select(record => fixture.Sign([record]))]
                    : [fixture.RootSoa, fixture.Sign([fixture.RootSoa]), .. denial, .. denial.Select(record => fixture.Sign([record]))],
                code: wildcard ? (ushort)0 : (ushort)3) : reply;
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture));
        await using var lifetime = cache.ConfigureAwait(true);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var calls = fixture.Calls.Count;
        fixture.Clock.Advance(2);
        var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(1, cache.Statistics.Hits);
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk: true, out _));
        var proof = ClientProofFixture.Proof(result);
        Assert.Equal(wildcard ? 0 : 3, result.ResponseCode);
        Assert.Equal(wildcard ? 1 : 0, proof.AnswerSignatures.Count);
        var type = nsec3 ? 50 : 47;
        Assert.Equal(denial.Length, proof.Authority.Count(record => record.Type == type));
        Assert.Equal(denial.Length, proof.Authority.Count(record => record.Type == 46 && ClientProofProjectionTests.Covered(record) == type));
        Assert.Equal(wildcard ? 0 : 1, proof.Authority.Count(record => record.Type == 46 && ClientProofProjectionTests.Covered(record) == 6));
        Assert.DoesNotContain(proof.Authority, record => record.Type is 2 or 43 or 48);
    }

}
