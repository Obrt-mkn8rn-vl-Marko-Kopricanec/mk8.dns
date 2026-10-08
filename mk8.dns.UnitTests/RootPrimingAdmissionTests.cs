using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RootPrimingAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task InvalidPrimingEnvelopeNeverProvidesHints(int invalid)
    {
        using var fixture = new RootPrimingFixture();
        fixture.Transform = reply => reply.Question.Type != 2 ? reply : invalid switch
        {
            0 => OnlineDnssecFixture.Copy(reply, flags: (ushort)(reply.Flags & ~0x400)),
            1 => OnlineDnssecFixture.Copy(reply, authority: [DnssecFixture.A()]),
            2 => OnlineDnssecFixture.Copy(reply, question: new DnsQuestion(DnsName.Parse("example."), 2, 1)),
            3 => OnlineDnssecFixture.Copy(reply, server: new DnsServerEndpoint([127, 0, 0, 2], 5300)),
            4 => OnlineDnssecFixture.Copy(reply, version: 1),
            _ => OnlineDnssecFixture.Reply(reply.Question, reply.Server, [], code: 2),
        };
        Assert.Null(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(2, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task InvalidNsMembershipRefusesBeforeAddressRepair(int invalid)
    {
        using var fixture = new RootPrimingFixture(invalid == 0 ? 0 : invalid == 1 ? 33 : 1);
        if (invalid >= 2) fixture.NameServers[0] = new DnsRecord(RootPrimingFixture.Root, 2, 300,
            DnsName.Parse(invalid == 2 ? "." : "*.fixture.").ToWire());
        fixture.Transform = reply => reply.Question.Type == 2 && invalid == 0
            ? OnlineDnssecFixture.Reply(reply.Question, reply.Server, []) : reply;
        Assert.Null(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type is 1 or 28);
    }

    [Theory]
    [InlineData(48)]
    [InlineData(2)]
    public async Task ForgedAdCannotReplaceRootKeyOrNsAuthentication(int type)
    {
        using var fixture = new RootPrimingFixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type != type) return reply;
            return OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Select(record =>
            {
                if (record.Type != 46) return record;
                var data = record.GetData(); data[^1] ^= 1;
                return new DnsRecord(record.Owner, record.Type, record.Ttl, data);
            }).ToArray());
        };
        Assert.Null(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(type == 48 ? 1 : 2, fixture.Calls.Count);
    }

    [Theory]
    [InlineData("alias.fixture.")]
    [InlineData("other.")]
    public async Task DirectAddressAliasOrDifferentOwnerCannotSupplyHint(string owner)
    {
        using var fixture = new RootPrimingFixture(1) { Additional = [] };
        fixture.Transform = reply => reply.Question.Type is 1 or 28 ? OnlineDnssecFixture.Copy(reply, answers:
            string.Equals(owner, "alias.fixture.", StringComparison.Ordinal) ? [new DnsRecord(reply.Question.Name, 5, 300, DnsName.Parse(owner).ToWire())]
            : [new DnsRecord(DnsName.Parse(owner), reply.Question.Type, 300, reply.Question.Type == 1 ? [192, 0, 2, 1] : new byte[16])]) : reply;
        Assert.Null(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(4, fixture.Calls.Count);
    }
}
