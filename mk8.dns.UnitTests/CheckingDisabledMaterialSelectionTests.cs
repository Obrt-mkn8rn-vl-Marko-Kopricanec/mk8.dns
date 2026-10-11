using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CheckingDisabledMaterialSelectionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AliasReacquiresTargetAndRetainsOnlyActualCoveredSignatures(bool dname)
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        var original = f.Epoch.Question;
        var target = DnsName.Parse(dname ? "www.other.example." : "answer.example.");
        f.Override = (question, server, _) =>
        {
            if (question.Name.Equals(original.Name))
            {
                var alias = new DnsRecord(dname ? DnsName.Parse("example.") : question.Name, dname ? (ushort)39 : (ushort)5, 300,
                    DnsName.Parse(dname ? "other.example." : "answer.example.").ToWire());
                var inline = new DnsRecord(target, 1, 300, [192, 0, 2, 99]);
                var synthetic = new DnsRecord(question.Name, 5, 300, target.ToWire());
                return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, dname
                    ? [alias, f.Signature(alias), inline, f.Signature(inline), synthetic, f.Signature(synthetic)]
                    : [alias, f.Signature(alias), inline, f.Signature(inline)]));
            }
            f.Epoch.Advance(2);
            var value = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 42]);
            return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, [value, f.Signature(value)]));
        };
        var answer = await f.Resolver.ResolveAsync(original, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, answer.ResponseCode); Assert.Equal(2, f.Upstream.Calls.Count);
        Assert.Equal(42, Assert.Single(answer.Answers, record => record.Type == 1).GetData()[3]);
        Assert.Equal(2, answer.Answers.Count(record => record.Type == 46));
        Assert.All(answer.Answers.Where(record => record.Type is 5 or 39), record => Assert.Equal(296U, record.Ttl));
        if (dname) Assert.DoesNotContain(answer.Answers, record => record.Type == 46 && record.Owner.Equals(original.Name));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public async Task NegativeMaterialKeepsSoaDenialAndTheirCandidatesWithoutRoutingRecords(int code)
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, server, _) =>
        {
            var soa = new DnsRecord(DnsName.Parse("."), 6, 300, [0, 0, .. new byte[20]]);
            var denial = new DnsRecord(DnsName.Parse("example."), 47, 300, [0, 0, 1, 64]);
            var ns = new DnsRecord(DnsName.Parse("."), 2, 300, DnsName.Parse("ns.example.").ToWire());
            return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, [], [soa, f.Signature(soa), denial, f.Signature(denial), ns, f.Signature(ns)],
                [new DnsRecord(DnsName.Parse("ns.example."), 1, 300, [192, 0, 2, 99])], (byte)code));
        };
        var answer = await f.Resolver.ResolveAsync(f.Epoch.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(code, answer.ResponseCode); Assert.Empty(answer.Answers); Assert.Empty(answer.Additional);
        Assert.Equal(4, answer.Authority.Count); Assert.DoesNotContain(answer.Authority, record => record.Type == 2);
    }
}
