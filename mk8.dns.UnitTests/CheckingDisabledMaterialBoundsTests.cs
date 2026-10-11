using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CheckingDisabledMaterialBoundsTests
{
    [Theory]
    [InlineData(255, 0)]
    [InlineData(256, 2)]
    public async Task CombinedAliasAndTerminalMaterialEnforcesCompleteRecordBound(int terminalRecords, int code)
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, server, _) =>
        {
            if (question.Name.Equals(f.Epoch.Question.Name))
            {
                var alias = new DnsRecord(question.Name, 5, 300, DnsName.Parse("target.example.").ToWire());
                return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, new[] { alias }.Concat(Enumerable.Repeat(f.Signature(alias), 255))));
            }
            var values = Enumerable.Range(0, terminalRecords).Select(i => new DnsRecord(question.Name, 1, 300, [192, 0, (byte)(i >> 8), (byte)i])).ToArray();
            return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, values.Concat([f.Signature(values[0])])));
        };
        var answer = await f.Resolver.ResolveAsync(f.Epoch.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(code, answer.ResponseCode); Assert.Equal(2, f.Upstream.Calls.Count);
        if (code == 0) Assert.Equal(512, answer.Answers.Count); else Assert.Empty(answer.Answers);
    }

    [Fact]
    public async Task CombinedExpandedBytesRefuseDespiteEachAcquisitionBeingWithinItsBound()
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, server, _) =>
        {
            var alias = question.Name.Equals(f.Epoch.Question.Name);
            var value = alias ? new DnsRecord(question.Name, 5, 300, DnsName.Parse("target.example.").ToWire())
                : new DnsRecord(question.Name, 1, 300, [192, 0, 2, 42]);
            var signature = new byte[60000]; signature[1] = (byte)value.Type;
            var raw = new DnsRecord(question.Name, 46, 300, signature);
            return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, new[] { value }.Concat(Enumerable.Repeat(raw, alias ? 17 : 1))));
        };
        var answer = await f.Resolver.ResolveAsync(f.Epoch.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, answer.ResponseCode); Assert.Empty(answer.Answers); Assert.Equal(2, f.Upstream.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WildcardAliasKeepsSameStepDenialMaterialWhileReacquiringTarget(bool nsec3)
    {
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, server, _) =>
        {
            var alias = question.Name.Equals(f.Epoch.Question.Name);
            var value = alias ? new DnsRecord(question.Name, 5, 300, DnsName.Parse("target.example.").ToWire())
                : new DnsRecord(question.Name, 1, 300, [192, 0, 2, 42]);
            var sig = f.Signature(value); var data = sig.GetData(); data[3] = 1;
            var denial = new DnsRecord(DnsName.Parse("example."), nsec3 ? (ushort)50 : (ushort)47, 300, [0, 0, 1, 64]);
            return ValueTask.FromResult(CheckingDisabledMaterialFixture.Reply(question, server, [value, new DnsRecord(sig.Owner, 46, 300, data)],
                alias ? [denial, f.Signature(denial)] : []));
        };
        var answer = await f.Resolver.ResolveAsync(f.Epoch.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, answer.ResponseCode); Assert.Equal(2, answer.Authority.Count);
        Assert.Contains(answer.Authority, record => record.Type == (nsec3 ? 50 : 47));
        Assert.Equal(2, f.Upstream.Calls.Count);
    }
}
