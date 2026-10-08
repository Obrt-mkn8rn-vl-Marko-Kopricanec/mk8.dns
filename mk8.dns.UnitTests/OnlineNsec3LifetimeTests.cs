using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineNsec3LifetimeTests
{
    [Fact]
    public async Task Nsec3ProofsAgeFromBeforeAwaitedProviderReceipt()
    {
        using var fixture = new OnlineNsec3Fixture();
        fixture.Transform = reply => { fixture.Clock.Advance(5); return reply; };
        var result = await fixture.Resolver().ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question("missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.InRange(result.AuthenticatedTtl, 1U, 290U);
        Assert.InRange(Assert.Single(result.Authority).Ttl, 1U, 295U);
    }

    [Fact]
    public async Task ZeroTtlProofCanAuthenticateWithoutCacheLifetime()
    {
        using var fixture = new OnlineNsec3Fixture();
        fixture.Transform = reply => reply.Question.Type == 48 ? reply
            : OnlineDnssecFixture.Copy(reply, authority: reply.Authority.Select(record => record.WithTtl(0)).ToArray());
        var result = await fixture.Resolver().ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question("missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(0U, result.AuthenticatedTtl); Assert.Equal(0U, Assert.Single(result.Authority).Ttl);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NetworkExpiryCannotPromoteNegativeOrDelegationProof(bool isUnsigned)
    {
        using var fixture = new OnlineNsec3Fixture { Unsigned = isUnsigned, OptOut = isUnsigned };
        fixture.Transform = reply => { if (reply.Question.Type != 48) fixture.Clock.Advance(301); return reply; };
        var result = await fixture.Resolver().ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question(isUnsigned ? "www.child.example." : "missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Fact]
    public async Task LastFinalVerificationMustRecheckEveryEarlierProofWindow()
    {
        using var fixture = new OnlineNsec3Fixture();
        var finalSignatureChecks = 0;
        fixture.Transform = reply => reply.Question.Type == 48 ? reply : OnlineDnssecFixture.Copy(reply,
            authority: reply.Authority.Select(record => record.Type == 46
                ? fixture.Sign(reply.Authority.Single(data => data.Owner.Equals(record.Owner) && data.Type == BinaryPrimitives.ReadUInt16BigEndian(record.GetData())),
                    window: new DnssecSignatureWindow(100, 101)) : record).ToArray());
        var provider = new DnssecChainFixture.CountingVerifier
        {
            AfterVerify = () =>
        {
            if (++finalSignatureChecks == 15) fixture.Clock.Advance(2); // key +7 first proofs +7 final proofs
        }
        };
        var result = await fixture.Resolver(verifier: provider).ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question("missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Authority);
        Assert.Equal(15, provider.Calls);
    }

    [Fact]
    public async Task FinalNsec3ProofReauthenticationConsumesTheSharedWorkBudget()
    {
        using var fixture = new OnlineNsec3Fixture();
        var provider = new DnssecChainFixture.CountingVerifier();
        var result = await fixture.Resolver(attempts: 8, verifier: provider).ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question("missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Equal(8, provider.Calls); Assert.Empty(result.Authority);
    }
}
