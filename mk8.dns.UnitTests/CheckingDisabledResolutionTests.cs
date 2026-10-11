using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CheckingDisabledResolutionTests
{
    [Fact]
    public async Task ContainedOrdinaryIoFailureIsEmptyServfailWithoutCachedSecurityClassification()
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (_, _) => throw new IOException("Controlled ordinary upstream refusal.");
        var request = CheckingDisabledFixture.Request();
        var reply = await f.Processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Failure, reply.Outcome); Assert.Null(reply.Revision);
        ClientRequestFixture.AssertError(request, reply.GetMessage(), 2);
        Assert.Equal(0, f.Epoch.Resolver.Statistics.FailureEntries); Assert.Empty(f.Epoch.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AliasRestartsUnvalidatedSourceAndFiltersForeignInlineData(bool dname)
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        var target = DnsName.Parse("target.other.example.");
        f.Override = (question, _) => ValueTask.FromResult(question.Name.Equals(f.Epoch.Question.Name)
            ? new DnsAnswer(0, authoritative: true, [AuthorityFixture.Record(dname ? "example." : "www.example.", dname ? (ushort)39 : (ushort)5,
                DnsName.Parse(dname ? "other.example." : "target.other.example.").ToWire()), AuthorityFixture.Record("target.other.example.", 1, [192, 0, 2, 99])], [], [])
            : f.Answer(question));
        // DNAME synthesis replaces its suffix, retaining the original first label.
        var expected = dname ? DnsName.Parse("www.other.example.") : target;
        var reply = await f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        var parsed = UpstreamMessageCodec.DecodeResponse(reply.GetMessage(), 0xabcd, f.Epoch.Question).Answer;
        Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, reply.Outcome); Assert.Null(reply.Revision);
        Assert.Equal(expected, parsed.Answers[^1].Owner); Assert.Equal((byte)42, parsed.Answers[^1].GetData()[3]);
        ushort[] types = dname ? [39, 5, 1] : [5, 1];
        Assert.Equal(types, parsed.Answers.Select(record => record.Type));
        Assert.Equal([f.Epoch.Question.Name, expected], f.Upstream.Calls.Select(question => question.Name));
        Assert.Empty(f.Epoch.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public async Task NegativeSoaIsOrdinaryUnvalidatedAndDoesNotEstablishFailureHistory(int code)
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        var soa = new DnsRecord(DnsName.Parse("."), 6, 300,
            [.. DnsName.Parse("ns.example.").ToWire(), .. DnsName.Parse("hostmaster.example.").ToWire(), .. new byte[20]]);
        f.Override = (_, _) => ValueTask.FromResult(new DnsAnswer((byte)code, authoritative: true, [], [soa], []));
        var reply = await f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        var parsed = UpstreamMessageCodec.DecodeResponse(reply.GetMessage(), 0xabcd, f.Epoch.Question).Answer;
        Assert.Equal(code, parsed.ResponseCode); Assert.Equal((ushort)6, Assert.Single(parsed.Authority).Type); Assert.Empty(parsed.Answers);
        Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, reply.Outcome); Assert.Equal(0, f.Epoch.Resolver.Statistics.FailureEntries);
    }

    [Fact]
    public async Task ValidationRefusalCannotPopulateOrBlockTheSeparateCdPath()
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Epoch.Override = (question, server, _) => ValueTask.FromResult(question.Type == 48 ? f.Epoch.Default(question, server)
            : f.Epoch.Anchors.Reply(question, server, answers: [new DnsRecord(question.Name, 1, 300, [192, 0, 2, 99])]));
        var rejected = await f.Processor.ProcessAsync(ClientRequestFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Failure, rejected.Outcome); var validatedCalls = f.Epoch.Calls.Count;
        var bypass = await f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, bypass.Outcome); Assert.Null(bypass.Revision);
        Assert.Equal(validatedCalls, f.Epoch.Calls.Count); Assert.Single(f.Upstream.Calls);
        Assert.Equal(0, f.Epoch.Resolver.Statistics.Entries); Assert.Equal(0, f.Epoch.Resolver.Statistics.FailureEntries);
    }
}
