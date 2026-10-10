using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofProjectionTests
{
    [Theory]
    [InlineData("www.example.", 1, 0, false)]
    [InlineData("www.child.example.", 1, 0, false)]
    [InlineData("www.example.", 28, 0, true)]
    [InlineData("missing.example.", 1, 3, true)]
    [InlineData("missing.child.example.", 1, 3, true)]
    public async Task SelectedAnswerAndNegativeProofsExcludeBootstrapAndRouting(string name, int type, int code, bool negative)
    {
        ArgumentNullException.ThrowIfNull(name);
        using var fixture = new OnlineDnssecFixture();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(ClientProofFixture.Question(name, (ushort)type), CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        Assert.Equal(code, result.ResponseCode);
        Assert.DoesNotContain(proof.AnswerSignatures.Concat(proof.Authority), record => record.Type is 2 or 43 or 48);
        if (negative)
        {
            Assert.Empty(proof.AnswerSignatures);
            Assert.Contains(proof.Authority, record => record.Type == 47);
            Assert.Contains(proof.Authority, record => record.Type == 46 && Covered(record) == 6);
            Assert.Contains(proof.Authority, record => record.Type == 46 && Covered(record) == 47);
            Assert.Equal(6, Assert.Single(result.Authority).Type);
        }
        else
        {
            var signature = Assert.Single(proof.AnswerSignatures);
            Assert.Equal(result.Question.Name, signature.Owner);
            Assert.Equal(type, Covered(signature));
            Assert.Empty(proof.Authority);
        }
    }

    [Fact]
    public async Task CnameTargetRestartsKeepBothAnswerSignaturesWithoutInfrastructure()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question("alias.example.");
        fixture.RootRecords.Add(new DnsRecord(question.Name, 5, 3, DnsName.Parse("www.child.example.").ToWire()));
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        Assert.Equal(3U, result.AuthenticatedTtl);
        Assert.Equal(2, proof.AnswerSignatures.Count);
        Assert.Contains(proof.AnswerSignatures, record => record.Owner.Equals(question.Name) && Covered(record) == 5);
        Assert.Contains(proof.AnswerSignatures, record => record.Owner.Equals(DnsName.Parse("www.child.example.")) && Covered(record) == 1);
        Assert.Empty(proof.Authority);
        Assert.All(result.Answers, record => Assert.Equal(3U, record.Ttl));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    public async Task DnameSynthesisExportsOnlyActualDnameAndTargetSignatures(int type)
    {
        using var fixture = new OnlineDnssecDnameFixture();
        var result = await ClientProofFixture.Resolver(fixture.Zones).ResolveDnssecAsync(OnlineDnssecDnameFixture.Question((ushort)type), CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        Assert.Contains(proof.AnswerSignatures, record => record.Owner.Equals(fixture.Dname.Owner) && Covered(record) == 39);
        Assert.DoesNotContain(proof.AnswerSignatures, record => Covered(record) == 5);
        Assert.Equal(type == 5 ? 1 : 2, proof.AnswerSignatures.Count);
    }

    [Fact]
    public async Task ReadOnlyCollectionsAndOwnedRecordBytesCannotBeMutatedByConsumer()
    {
        using var fixture = new OnlineDnssecFixture();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        var signature = Assert.Single(proof.AnswerSignatures);
        var original = signature.GetData(); var changed = signature.GetData(); changed[^1] ^= 1;
        Assert.Equal(original, signature.GetData());
        Assert.Throws<NotSupportedException>(() => ((IList<DnsRecord>)proof.AnswerSignatures).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<DnsRecord>)proof.Authority).Clear());
    }

    [Fact]
    public async Task LegacyResolutionAndOrdinaryCacheDoNotExposeOrStoreOptionalMaterial()
    {
        using var fixture = new OnlineDnssecFixture();
        Assert.Null((await fixture.Resolver().ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None)).ClientProof);
        var cache = new CachingDnssecResolver(ClientProofFixture.Resolver(fixture));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var fresh = await cache.ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None);
        var calls = fixture.Calls.Count;
        var hit = await cache.ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, hit.Outcome);
        Assert.Null(fresh.ClientProof); Assert.Null(hit.ClientProof);
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(1, cache.Statistics.Entries);
    }

    internal static ushort Covered(DnsRecord signature) => BinaryPrimitives.ReadUInt16BigEndian(signature.GetData());

    [Fact]
    public async Task ExplicitMinimisationDoesNotExportDiscoveryOrCutInfrastructure()
    {
        using var fixture = new OnlineDnssecFixture();
        var resolver = ClientProofFixture.Resolver(fixture, minimisation: new DnsQnameMinimisationPolicy());
        var result = await resolver.ResolveDnssecAsync(ClientProofFixture.Question("www.child.example."), CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        Assert.Equal(1, Covered(Assert.Single(proof.AnswerSignatures)));
        Assert.Empty(proof.Authority);
        Assert.Contains(fixture.Calls, call => call.Question.Type == 2);
    }
}
