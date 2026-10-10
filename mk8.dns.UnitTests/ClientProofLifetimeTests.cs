using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignatureRefusalAndUnsignedDelegationExportNoPartialMaterial(bool delegationUnsigned)
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = delegationUnsigned };
        if (!delegationUnsigned)
        {
            fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers.Select(record =>
            {
                if (record.Type != 46) return record;
                var bytes = record.GetData(); bytes[^1] ^= 1; return new DnsRecord(record.Owner, record.Type, record.Ttl, bytes);
            })]);
        }
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(ClientProofFixture.Question("www.child.example."), CancellationToken.None);
        Assert.Equal(delegationUnsigned ? DnssecResolutionOutcome.UnsignedDelegation : DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Null(result.ClientProof); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public async Task ReceiptAgeAndZeroDataLifetimeCapEveryCandidate(int advance)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type == 48) return reply;
            fixture.Clock.Advance(advance);
            return OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers.Select(record => record.WithTtl(advance == 0 ? 0U : 20U))]);
        };
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        Assert.Equal(advance == 0 ? 0U : 15U, result.AuthenticatedTtl);
        Assert.Equal(result.AuthenticatedTtl, Assert.Single(proof.AnswerSignatures).Ttl);
    }

    [Fact]
    public async Task FinalProviderExpiryDiscardsDataAndProofTogether()
    {
        using var fixture = new OnlineDnssecFixture();
        var calls = 0;
        var verifier = new DnssecChainFixture.CountingVerifier { AfterVerify = () => { if (++calls == 3) fixture.Clock.Advance(301); } };
        var result = await ClientProofFixture.Resolver(fixture, verifier).ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Null(result.ClientProof); Assert.Empty(result.Answers);
        Assert.Equal(3, verifier.Calls);
    }

    [Fact]
    public async Task VerificationBudgetRefusalCannotExportEarlierProof()
    {
        using var fixture = new OnlineDnssecFixture();
        var result = await ClientProofFixture.Resolver(fixture, attempts: 2).ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Null(result.ClientProof);
    }
}
