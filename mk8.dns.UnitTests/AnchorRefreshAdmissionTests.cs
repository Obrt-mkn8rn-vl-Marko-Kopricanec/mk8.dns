using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRefreshAdmissionTests
{
    [Theory]
    [InlineData("question")]
    [InlineData("server")]
    [InlineData("rcode")]
    [InlineData("authority")]
    [InlineData("non-authoritative")]
    [InlineData("edns-version")]
    [InlineData("foreign-owner")]
    [InlineData("foreign-type")]
    [InlineData("empty")]
    [InlineData("signature")]
    [InlineData("short-signature")]
    [InlineData("zero-ttl")]
    public async Task UnusableAcquisitionCannotMutateCommittedStateOrTrust(string kind)
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        var current = session.Current;
        f.Upstream.Override = (_, _, _) => ValueTask.FromResult(Reply(f, kind));
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Same(current, session.Current); Assert.Equal(0, f.Store.Commits); Assert.Equal(1, f.Upstream.Calls);
    }

    [Theory]
    [InlineData("io")]
    [InlineData("timeout")]
    [InlineData("format")]
    public async Task ContainedAcquisitionFaultRefusesOnceWithoutRetryOrPoisoningSession(string kind)
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        f.Upstream.Override = (_, _, _) => throw kind switch
        {
            "io" => new IOException("Controlled transport error."),
            "timeout" => new TimeoutException("Controlled transport timeout."),
            _ => new FormatException("Controlled malformed packet."),
        };
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(1, f.Upstream.Calls); Assert.Equal(0, f.Store.Commits);
        f.Upstream.Override = null;
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task PropagatedProviderFaultDoesNotCommitOrInventFailureState()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        f.Upstream.Override = (_, _, _) => throw new InvalidOperationException("Controlled provider failure.");
        await Assert.ThrowsAsync<InvalidOperationException>(() => session.RefreshAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(1, session.Current.Revision); Assert.Equal(0, f.Store.Commits);
        f.Upstream.Override = null;
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
    }

    private static DnsUpstreamEvidence Reply(AnchorRefreshFixture f, string kind)
    {
        return kind switch
        {
            "question" => f.Reply(question: new DnsQuestion(f.Keys.Origin, 2, 1)),
            "server" => f.Reply(server: new DnsServerEndpoint([127, 0, 0, 2], 5300)),
            "rcode" => f.Reply(flags: 0x8433),
            "authority" => f.Reply(authority: [f.Keys.Key(f.Keys.A)]),
            "non-authoritative" => f.Reply(flags: 0x8030),
            "edns-version" => f.Reply(version: 1),
            "foreign-owner" => f.Reply(answers: [new DnsRecord(DnsName.Parse("other.example."), 48, 300, f.Records[0].GetData())]),
            "foreign-type" => f.Reply(answers: [new DnsRecord(f.Keys.Origin, 1, 300, [192, 0, 2, 1])]),
            "empty" => f.Reply(answers: []),
            "zero-ttl" => f.Reply(answers: [.. f.Records.Select(record => record.WithTtl(0)), f.Keys.Sign(f.Records, f.Keys.A).WithTtl(0)]),
            "short-signature" => f.Reply(answers: [.. f.Records, new DnsRecord(f.Keys.Origin, 46, 3600, [0])]),
            _ => Corrupt(f),
        };
    }

    private static DnsUpstreamEvidence Corrupt(AnchorRefreshFixture f)
    {
        var signature = f.Keys.Sign(f.Records, f.Keys.A); var data = signature.GetData(); data[^1] ^= 1;
        return f.Reply(answers: [.. f.Records, new DnsRecord(signature.Owner, 46, signature.Ttl, data)]);
    }
}
