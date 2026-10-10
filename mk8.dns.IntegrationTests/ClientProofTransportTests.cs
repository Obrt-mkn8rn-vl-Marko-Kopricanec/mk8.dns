using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ClientProofTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task NativeCorrelatedEvidenceProjectsSelectedProofsForAliasAndNegative(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = DnssecIterativeResolver.CreateWithClientProof(upstream, OnlineDnssecWireFixture.Verifier,
            zones.Anchor, [root.Server], child.Server.Port, time: zones.Clock);
        foreach (var name in new[] { "alias.example.", "missing.child.example." })
        {
            var result = await resolver.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse(name), 1, 1), deadline.Token).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
            var proof = Assert.IsType<DnssecResponseProof>(result.ClientProof);
            if (name.StartsWith("alias", StringComparison.Ordinal))
            {
                Assert.Equal(2, proof.AnswerSignatures.Count);
            }
            else
            {
                Assert.Empty(proof.AnswerSignatures);
                Assert.Contains(proof.Authority, record => record.Type == 47);
                Assert.Contains(proof.Authority, record => record.Type == 46 && BinaryPrimitives.ReadUInt16BigEndian(record.GetData()) == 6);
            }
            Assert.DoesNotContain(proof.Authority.Concat(proof.AnswerSignatures), record => record.Type is 2 or 43 or 48);
            Assert.All(result.Answers.Concat(result.Authority).Concat(proof.AnswerSignatures).Concat(proof.Authority),
                record => Assert.InRange(record.Ttl, 0U, result.AuthenticatedTtl));
        }
        Assert.Contains(root.Requests, request => request.Question.Type == 43 && request.Tcp == tcp);
        Assert.Contains(child.Requests, request => request.Question.Type == 48 && request.Tcp == tcp);
    }
}
