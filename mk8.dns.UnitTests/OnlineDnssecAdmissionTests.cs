using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecAdmissionTests
{
    [Theory]
    [InlineData("other.", 1, 1)]
    [InlineData("example.", 0, 1)]
    [InlineData("example.", 41, 1)]
    [InlineData("example.", 46, 1)]
    [InlineData("example.", 249, 1)]
    [InlineData("example.", 250, 1)]
    [InlineData("example.", 251, 1)]
    [InlineData("example.", 252, 1)]
    [InlineData("example.", 255, 1)]
    [InlineData("example.", 1, 3)]
    [InlineData("*.example.", 1, 1)]
    public async Task UnsupportedQuestionCannotSpendEgress(string name, int type, int recordClass)
    {
        using var fixture = new OnlineDnssecFixture();
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse(name), (ushort)type, (ushort)recordClass), CancellationToken.None);
        Failure(result);
        Assert.Empty(fixture.Calls);
    }

    [Theory]
    [InlineData(0, 64, 16, 512)]
    [InlineData(5400, 0, 16, 512)]
    [InlineData(5400, 257, 16, 512)]
    [InlineData(5400, 64, 0, 512)]
    [InlineData(5400, 64, 33, 512)]
    [InlineData(5400, 64, 16, 0)]
    [InlineData(5400, 64, 16, 4097)]
    public void ConstructorBoundsAreEnforced(int port, int exchanges, int aliases, int attempts)
    {
        using var fixture = new OnlineDnssecFixture();
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecIterativeResolver(fixture, DnssecFixture.Verifier, fixture.Anchor(),
            [OnlineDnssecFixture.RootServer], (ushort)port, exchanges, aliases, attempts, fixture.Clock));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(17)]
    public void BootstrapCollectionMustBeBoundedAndDistinct(int count)
    {
        using var fixture = new OnlineDnssecFixture();
        Assert.Throws<ArgumentException>(() => new DnssecIterativeResolver(fixture, DnssecFixture.Verifier, fixture.Anchor(),
            Enumerable.Range(0, count).Select(index => new DnsServerEndpoint([127, 0, 0, (byte)(index + 1)], 5300))));
        Assert.Throws<ArgumentException>(() => new DnssecIterativeResolver(fixture, DnssecFixture.Verifier, fixture.Anchor(),
            [OnlineDnssecFixture.RootServer, OnlineDnssecFixture.RootServer]));
    }

    [Theory]
    [InlineData("key")]
    [InlineData("ds")]
    [InlineData("child-key")]
    [InlineData("data")]
    public async Task ForgedAdDoesNotAuthorizeCorruptSignatureAtAnyStage(string stage)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => string.Equals(Stage(reply), stage, StringComparison.Ordinal)
            ? OnlineDnssecFixture.Copy(reply, answers: Corrupt(reply.Answers)) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1), CancellationToken.None);
        Failure(result);
        if (stage is "key" or "ds") Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }

    [Theory]
    [InlineData("question")]
    [InlineData("peer")]
    [InlineData("aa")]
    [InlineData("version")]
    public async Task ProviderMetadataIsRecheckedWithoutPromotingIt(string mutation)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => mutation switch
        {
            "question" => OnlineDnssecFixture.Copy(reply, question: new DnsQuestion(DnsName.Parse("other."), 48, 1)),
            "peer" => OnlineDnssecFixture.Copy(reply, server: OnlineDnssecFixture.ChildServer),
            "aa" => OnlineDnssecFixture.Copy(reply, flags: (ushort)(reply.Flags & ~0x400)),
            _ => OnlineDnssecFixture.Copy(reply, version: 7),
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.example."), 1, 1), CancellationToken.None);
        Failure(result);
        Assert.Single(fixture.Calls);
    }

    [Theory]
    [InlineData("missing-nsec")]
    [InlineData("bad-nsec")]
    [InlineData("bad-soa")]
    [InlineData("wrong-soa")]
    public async Task MissingOrForgedDsAbsenceIsNotInsecureFallback(string mutation)
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = true };
        fixture.Transform = reply => reply.Question.Type != 43 ? reply : OnlineDnssecFixture.Copy(reply, authority: mutation switch
        {
            "missing-nsec" => reply.Authority.Where(record => record.Type is not (47 or 46)).ToArray(),
            "bad-nsec" => Corrupt(reply.Authority, 47),
            "bad-soa" => Corrupt(reply.Authority, 6),
            _ => reply.Authority.Select(record => record.Type == 6 ? record.WithOwner(DnsName.Parse("child.example.")) : record).ToArray(),
        });
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1), CancellationToken.None);
        Failure(result);
        Assert.All(fixture.Calls, call => Assert.Equal(OnlineDnssecFixture.RootServer, call.Server));
    }

    [Theory]
    [InlineData("outside")]
    [InlineData("same")]
    [InlineData("sibling")]
    [InlineData("foreign-glue")]
    [InlineData("no-glue")]
    public async Task IrrelevantCutsAndUnusableGlueCannotSelectNewAuthority(string mutation)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => reply.Authoritative ? reply : mutation switch
        {
            "outside" => fixture.Referral(reply.Question, reply.Server, DnsName.Parse("other.")),
            "same" => fixture.Referral(reply.Question, reply.Server, fixture.Root),
            "sibling" => fixture.Referral(reply.Question, reply.Server, DnsName.Parse("sibling.example.")),
            "foreign-glue" => fixture.Referral(reply.Question, reply.Server, target: "ns.other."),
            _ => OnlineDnssecFixture.Copy(reply, additional: []),
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1), CancellationToken.None);
        Failure(result);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }

    internal static DnsRecord[] Corrupt(IEnumerable<DnsRecord> records, ushort? covered = null)
        => records.Select(record =>
        {
            if (record.Type != 46 || covered is not null && DnssecFixture.CoveredType(record) != covered) return record;
            var data = record.GetData();
            data[^1] ^= 1;
            return new DnsRecord(record.GetOwnerWire(), record.Type, record.Ttl, data);
        }).ToArray();

    private static string Stage(DnsUpstreamEvidence reply)
        => reply.Question.Type == 48 ? reply.Question.Name.Equals(DnsName.Parse("example.")) ? "key" : "child-key"
            : reply.Question.Type == 43 ? "ds" : reply.Authoritative ? "data" : "referral";

    private static void Failure(DnssecResolutionResult result)
    {
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
        Assert.Null(result.UnsignedDelegation);
        Assert.Equal(0U, result.AuthenticatedTtl);
    }
}
