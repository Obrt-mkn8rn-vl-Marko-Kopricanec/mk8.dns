using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

internal static class ClientProofFixture
{
    internal static DnsQuestion Question(string name = "www.example.", ushort type = 1)
        => new(DnsName.Parse(name), type, 1);

    internal static DnssecIterativeResolver Resolver(OnlineDnssecFixture fixture, IDnssecSignatureVerifier? verifier = null,
        int attempts = 512, DnsQnameMinimisationPolicy? minimisation = null)
        => DnssecIterativeResolver.CreateWithClientProof(fixture, verifier ?? DnssecFixture.Verifier, fixture.Anchor(),
            [OnlineDnssecFixture.RootServer], OnlineDnssecFixture.ChildServer.Port,
            maximumVerificationAttempts: attempts, time: fixture.Clock, minimisation: minimisation);

    internal static DnssecResponseProof Proof(DnssecResolutionResult result)
    {
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        var proof = Assert.IsType<DnssecResponseProof>(result.ClientProof);
        Assert.All(result.Answers.Concat(result.Authority).Concat(proof.AnswerSignatures).Concat(proof.Authority),
            record => Assert.InRange(record.Ttl, 0U, result.AuthenticatedTtl));
        return proof;
    }
}
