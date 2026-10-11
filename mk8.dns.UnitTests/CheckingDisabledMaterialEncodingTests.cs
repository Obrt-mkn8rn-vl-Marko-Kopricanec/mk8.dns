using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CheckingDisabledMaterialEncodingTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ExplicitSourceReturnsRawCandidatesOnlyWhenDoSetWithoutAdRevisionVerificationOrStorage(bool dnssecOk, bool tcp)
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        for (var i = 0; i < 2; i++)
        {
            var reply = await f.Processor.ProcessAsync(CheckingDisabledMaterialFixture.Request(dnssecOk: dnssecOk),
                ClientRequestFixture.Peer(), tcp, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, reply.Outcome); Assert.Null(reply.Revision);
            Assert.Equal(0x8190, BinaryPrimitives.ReadUInt16BigEndian(reply.GetMessage().AsSpan(2)));
            var parsed = UpstreamMessageCodec.DecodeResponse(reply.GetMessage(), 0xabcd, f.Epoch.Question).Answer;
            Assert.Equal(dnssecOk ? 2 : 1, parsed.Answers.Count);
            Assert.Contains(parsed.Answers, record => record.Type == 1 && record.Ttl == 300);
            if (dnssecOk) Assert.Equal(253, Assert.Single(parsed.Answers, record => record.Type == 46).GetData()[2]);
        }
        Assert.Equal(2, f.Upstream.Calls.Count); Assert.Empty(f.Epoch.Calls); Assert.Equal(0, f.Epoch.Verifier.Calls);
        Assert.Equal(0, f.Epoch.Resolver.Statistics.Entries); Assert.Equal(0, f.Epoch.Resolver.Statistics.FailureEntries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OriginalAcquisitionAgesDataAndSignaturesOnBothClocksAndNewAcquisitionRemainsSeparate(bool wallOnly)
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, server, _) =>
        {
            if (wallOnly) f.Epoch.Anchors.Keys.Clock.SetWall(103); else f.Epoch.Advance(2.1);
            var record = new DnsRecord(question.Name, 1, 2, [192, 0, 2, 42]);
            return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, [record, f.Signature(record)]));
        };
        var answer = await f.Resolver.ResolveAsync(f.Epoch.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, answer.Answers.Count); Assert.All(answer.Answers, record => Assert.Equal(0U, record.Ttl));
        f.Epoch.Anchors.Keys.Clock.SetWall(100); f.Epoch.Anchors.Keys.Clock.SetMonotonic(0);
        f.Override = null;
        var packet = await f.Processor.ProcessAsync(CheckingDisabledMaterialFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, packet.Outcome);
        Assert.All(UpstreamMessageCodec.DecodeResponse(packet.GetMessage(), 0xabcd, f.Epoch.Question).Answer.Answers, record => Assert.Equal(300U, record.Ttl));
    }

    [Theory]
    [InlineData(43)]
    [InlineData(48)]
    [InlineData(47)]
    [InlineData(50)]
    public async Task ExplicitDnssecOrdinaryQuestionSurvivesDoClearWithoutAccompanyingSignatures(int type)
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, server, _) =>
        {
            byte[] bytes = type == 43 ? [0, 1, 253, 253, 1] : type == 47 ? [0, 0, 1, 64] : [1, 2, 3, 4];
            var record = new DnsRecord(question.Name, (ushort)type, 300, bytes);
            return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, [record, f.Signature(record)]));
        };
        var reply = await f.Processor.ProcessAsync(CheckingDisabledMaterialFixture.Request((ushort)type, dnssecOk: false),
            ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, reply.Outcome);
        Assert.Equal((ushort)type, Assert.Single(UpstreamMessageCodec.DecodeResponse(reply.GetMessage(), 0xabcd, f.Epoch.Question with { Type = (ushort)type }).Answer.Answers).Type);
    }
    [Fact]
    public async Task WholeResolutionChargesForwardWallBetweenAliasAndTargetWithoutMonotonicProgress()
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, server, _) =>
        {
            var alias = question.Name.Equals(f.Epoch.Question.Name);
            if (!alias) f.Epoch.Anchors.Keys.Clock.SetWall(103);
            var record = alias ? new DnsRecord(question.Name, 5, 10, DnsName.Parse("target.example.").ToWire())
                : new DnsRecord(question.Name, 1, 10, [192, 0, 2, 42]);
            return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, [record, f.Signature(record)]));
        };
        var answer = await f.Resolver.ResolveAsync(f.Epoch.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, answer.ResponseCode); Assert.Equal(2, f.Upstream.Calls.Count);
        Assert.Equal(0, f.Epoch.Anchors.Keys.Clock.GetTimestamp());
        Assert.All(answer.Answers, record => Assert.InRange(record.Ttl, 1U, 7U));
        Assert.Contains(answer.Answers, record => record.Type == 5);
        Assert.Contains(answer.Answers, record => record.Type == 1);
    }

}
