using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofDenialTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task WildcardAndNegativeSelectedDenialFamilyIsExported(bool nsec3, bool wildcard)
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
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        Assert.Equal(wildcard ? 0 : 3, result.ResponseCode);
        Assert.Equal(wildcard ? 1 : 0, proof.AnswerSignatures.Count);
        var type = nsec3 ? 50 : 47;
        Assert.Equal(denial.Length, proof.Authority.Count(record => record.Type == type));
        Assert.Equal(denial.Length, proof.Authority.Count(record => record.Type == 46 && ClientProofProjectionTests.Covered(record) == type));
        Assert.Equal(wildcard ? 0 : 1, proof.Authority.Count(record => record.Type == 46 && ClientProofProjectionTests.Covered(record) == 6));
        Assert.DoesNotContain(proof.Authority, record => record.Type is 2 or 43 or 48);
    }

    [Fact]
    public async Task CandidateSignatureMaterialDoesNotAssertEveryCandidateVerified()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question();
        fixture.Transform = reply =>
        {
            if (!reply.Question.Equals(question)) return reply;
            var signature = Assert.Single(reply.Answers, record => record.Type == 46);
            var corrupted = signature.GetData(); corrupted[^1] ^= 1;
            return OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers, new DnsRecord(signature.Owner, 46, signature.Ttl, corrupted)]);
        };
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        Assert.Equal(2, proof.AnswerSignatures.Count);
        Assert.NotEqual(proof.AnswerSignatures[0].GetData(), proof.AnswerSignatures[1].GetData());
    }
}
