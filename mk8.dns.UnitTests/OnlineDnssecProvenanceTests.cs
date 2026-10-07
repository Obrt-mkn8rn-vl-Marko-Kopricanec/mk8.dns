using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecProvenanceTests
{
    [Fact]
    public async Task ChildSignedDsCannotAuthorizeItsOwnDelegation()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type != 43) return reply;
            var ds = reply.Answers.Where(record => record.Type == 43).ToArray();
            return OnlineDnssecFixture.Copy(reply, answers: [.. ds, fixture.Sign(ds, child: true)]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task SignedButUnmatchedOrUnsupportedDsDoesNotBecomeInsecurity(int offset)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type != 43) return reply;
            var original = reply.Answers.Single(record => record.Type == 43);
            var data = original.GetData(); data[offset] ^= 1;
            var ds = new DnsRecord(original.GetOwnerWire(), 43, original.Ttl, data);
            return OnlineDnssecFixture.Copy(reply, answers: [ds, fixture.Sign([ds])]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Null(result.UnsignedDelegation);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer) && call.Question.Type == 1);
    }

    [Fact]
    public async Task NegativeRcodeCannotTurnExactExistingNameProofIntoNxDomain()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = new DnsQuestion(DnsName.Parse("www.example."), 28, 1);
        fixture.Transform = reply => reply.Question.Equals(question)
            ? new DnsUpstreamEvidence(reply.Question, reply.Server, reply.Id, (ushort)(reply.Flags | 3), 3,
                reply.HasEdns, reply.UdpPayloadSize, reply.EdnsVersion, reply.EdnsFlags, reply.Answers, reply.Authority, reply.Additional) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
    }

    [Fact]
    public async Task AlreadyReceivedNegativeMinimumIsAgedBeforeProviderWorkCompletes()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = new DnsQuestion(DnsName.Parse("www.example."), 28, 1);
        fixture.Transform = reply =>
        {
            if (!reply.Question.Equals(question)) return reply;
            var original = reply.Authority.Single(record => record.Type == 6);
            var bytes = original.GetData(); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(bytes.Length - 4), 10);
            var soa = new DnsRecord(original.GetOwnerWire(), 6, 300, bytes);
            var authority = reply.Authority.Where(record => record.Type != 6 && !(record.Type == 46 && DnssecFixture.CoveredType(record) == 6))
                .Append(soa).Append(fixture.Sign([soa])).ToArray();
            fixture.Clock.Advance(7);
            return OnlineDnssecFixture.Copy(reply, authority: authority);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(3U, result.AuthenticatedTtl);
        Assert.Equal(3U, Assert.Single(result.Authority).Ttl);
    }

    [Fact]
    public async Task CnameAndOrdinaryDataAtSameOwnerAreNotAdmittedTogether()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = new DnsQuestion(DnsName.Parse("alias.example."), 1, 1);
        fixture.RootRecords.Add(new DnsRecord(question.Name, 5, 300, DnsName.Parse("www.example.").ToWire()));
        fixture.Transform = reply =>
        {
            if (!reply.Question.Equals(question)) return reply;
            var data = DnssecFixture.A("alias.example.");
            return OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers, data, fixture.Sign([data])]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Equal(2, fixture.Calls.Count);
    }

    private static DnsQuestion Question() => new(DnsName.Parse("www.child.example."), 1, 1);
}
