using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class IterativeResolverTests
{
    private static readonly DnsServerEndpoint Root = Server(1);
    private static readonly DnsServerEndpoint Child = Server(2);
    private static readonly DnsServerEndpoint Other = Server(3);
    private static readonly string[] AddressLookups = ["www.example.", "ns.other.", "ns.other.", "www.example."];

    [Theory]
    [InlineData(1)]
    [InlineData(28)]
    [InlineData(16)]
    [InlineData(65280)]
    public async Task FollowsStrictlyDescendingDelegationAndFiltersAnswer(int type)
    {
        var data = type switch { 1 => new byte[] { 192, 0, 2, 42 }, 28 => new byte[16], 16 => new byte[] { 1, 65 }, _ => new byte[] { 192, 12, 255 } };
        var source = new Script((question, server) => server.Equals(Root) ? Referral("example.", "ns.example.", 2)
            : new DnsAnswer(0, true, [new DnsRecord(question.Name, (ushort)type, 300, data), A("poison.example.", 9)], [], [A("additional.example.", 9)]));
        var answer = await Resolver(source).ResolveAsync(Q("www.example.", (ushort)type), CancellationToken.None);
        Assert.Equal(0, answer.ResponseCode);
        Assert.False(answer.Authoritative);
        Assert.Empty(answer.Authority);
        Assert.Empty(answer.Additional);
        Assert.Equal(data, Assert.Single(answer.Answers).GetData());
        Assert.Equal(new[] { Root, Child }, source.Calls.Select(call => call.Server));
    }

    [Theory]
    [InlineData("outside.")]
    [InlineData("unrelated.example.")]
    public async Task UnrelatedAddressesCannotBecomeGlue(string owner)
    {
        var source = new Script((_, _) => new DnsAnswer(0, false, [], [Name("example.", 2, "ns.example.")], [A(owner, 2)]));
        Assert.Equal(2, (await Resolver(source).ResolveAsync(Q("www.example."), CancellationToken.None)).ResponseCode);
        Assert.Single(source.Calls);
    }

    [Fact]
    public async Task OutOfBailiwickGlueIsIgnoredAndNameserverAddressesAreResolved()
    {
        var source = new Script((question, server) =>
        {
            if (server.Equals(Child)) return Positive(question.Name, 42);
            if (question.Name.Equals(N("www.example."))) return new DnsAnswer(0, false, [], [Name("example.", 2, "ns.other.")], [A("ns.other.", 9)]);
            return question.Type == 1 ? new DnsAnswer(0, true, [new DnsRecord(question.Name, 1, 300, new byte[] { 127, 0, 0, 2 })], [], []) : Negative(".", 0);
        });
        Assert.Equal(0, (await Resolver(source).ResolveAsync(Q("www.example."), CancellationToken.None)).ResponseCode);
        Assert.Equal(AddressLookups, source.Calls.Select(call => call.Question.Name.ToString()), StringComparer.Ordinal);
        Assert.Equal(Child, source.Calls[^1].Server);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AliasesRestartFromRootsAndIgnoreInlineForeignTargetData(bool dname)
    {
        var source = new Script((question, server) =>
        {
            if (server.Equals(Root)) return question.Name.IsSubdomainOf(N("example.")) ? Referral("example.", "ns.example.", 2) : Referral("other.", "ns.other.", 3);
            if (server.Equals(Other)) return Positive(question.Name, 43);
            return new DnsAnswer(0, true, [Name(dname ? "example." : "www.example.", dname ? (ushort)39 : (ushort)5, dname ? "other." : "www.other."), A("www.other.", 99)], [], []);
        });
        var result = await Resolver(source).ResolveAsync(Q("www.example."), CancellationToken.None);
        Assert.Equal(0, result.ResponseCode);
        Assert.Equal(dname ? new ushort[] { 39, 5, 1 } : new ushort[] { 5, 1 }, result.Answers.Select(record => record.Type));
        Assert.Equal((byte)43, result.Answers[^1].GetData()[3]);
        Assert.Equal(new[] { Root, Child, Root, Other }, source.Calls.Select(call => call.Server));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public async Task AliasNegativeKeepsOnlyItsChainAndCurrentAuthoritySoa(int code)
    {
        var source = new Script((question, server) => server.Equals(Root) ? Referral("example.", "ns.example.", 2)
            : question.Name.Equals(N("alias.example.")) ? new DnsAnswer(0, true, [Name("alias.example.", 5, "absent.example.")], [], []) : Negative("example.", (byte)code));
        var answer = await Resolver(source).ResolveAsync(Q("alias.example."), CancellationToken.None);
        Assert.Equal((byte)code, answer.ResponseCode);
        Assert.Equal((ushort)5, Assert.Single(answer.Answers).Type);
        Assert.Equal((uint)60, Assert.Single(answer.Authority).Ttl);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("other.")]
    [InlineData("example.")]
    public async Task NonDescendingOrUnrelatedReferralCannotAdvance(string cut)
    {
        var count = 0;
        var source = new Script((_, _) => ++count == 1 ? Referral("example.", "ns.example.", 2) : Referral(cut, "ns." + (string.Equals(cut, ".", StringComparison.Ordinal) ? "" : cut), 3));
        Assert.Equal(2, (await Resolver(source).ResolveAsync(Q("www.example."), CancellationToken.None)).ResponseCode);
        Assert.Equal(2, source.Calls.Count);
    }

    [Fact]
    public async Task NegativeNeedsAuthoritativeSoaAtTheSelectedCut()
    {
        var source = new Script((_, server) => server.Equals(Root) ? Referral("example.", "ns.example.", 2) : Negative("other.", 3));
        var answer = await Resolver(source).ResolveAsync(Q("absent.example."), CancellationToken.None);
        Assert.Equal(2, answer.ResponseCode);
        Assert.Empty(answer.Answers);
        Assert.Empty(answer.Authority);
    }

    [Fact]
    public async Task ParentDsDoesNotFollowTheChildDelegation()
    {
        var source = new Script((question, _) => new DnsAnswer(0, true, [new DnsRecord(question.Name, 43, 300, new byte[36] { 0, 1, 13, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })], [], []));
        Assert.Equal(0, (await Resolver(source).ResolveAsync(Q("example.", 43), CancellationToken.None)).ResponseCode);
        var refusing = new Script((_, _) => Referral("example.", "ns.example.", 2));
        Assert.Equal(2, (await Resolver(refusing).ResolveAsync(Q("example.", 43), CancellationToken.None)).ResponseCode);
        Assert.Single(refusing.Calls);
    }

    [Fact]
    public async Task AliasCyclesDiscardPartialAnswers()
    {
        var source = new Script((question, _) => new DnsAnswer(0, true, [Name(question.Name.ToString(), 5, question.Name.Equals(N("a.")) ? "b." : "a.")], [], []));
        var answer = await Resolver(source).ResolveAsync(Q("a."), CancellationToken.None);
        Assert.Equal(2, answer.ResponseCode);
        Assert.Empty(answer.Answers);
        Assert.Equal(2, source.Calls.Count);
    }

    [Fact]
    public async Task DependencyCyclesAndGlobalWorkBudgetTerminate()
    {
        var source = new Script((_, _) => new DnsAnswer(0, false, [], [Name("example.", 2, "ns.other.")], []));
        Assert.Equal(2, (await Resolver(source).ResolveAsync(Q("www.example."), CancellationToken.None)).ResponseCode);
        Assert.InRange(source.Calls.Count, 1, 64);
        var alias = new Script((question, _) => new DnsAnswer(0, true, [Name(question.Name.ToString(), 5, "x." + question.Name)], [], []));
        var result = await new NonValidatingIterativeResolver(alias, [Root], maximumExchanges: 2).ResolveAsync(Q("a."), CancellationToken.None);
        Assert.Equal(2, result.ResponseCode);
        Assert.Equal(2, alias.Calls.Count);
        Assert.Empty(result.Answers);
    }

    [Fact]
    public async Task FailingBootstrapFallsBackToNextServer()
    {
        var source = new Script((question, server) => server.Equals(Root) ? throw new IOException("owned fixture failure") : Positive(question.Name, 42));
        Assert.Equal(0, (await new NonValidatingIterativeResolver(source, [Root, Child]).ResolveAsync(Q("www.example."), CancellationToken.None)).ResponseCode);
        Assert.Equal(2, source.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DnameSynthesisMustAgreeWithSuppliedCname(bool conflicting)
    {
        var source = new Script((question, _) => question.Name.IsSubdomainOf(N("example."))
            ? new DnsAnswer(0, true, [Name("example.", 39, "other."), Name("www.example.", 5, conflicting ? "evil." : "www.other.")], [], [])
            : Positive(question.Name, 43));
        var answer = await Resolver(source).ResolveAsync(Q("www.example."), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(conflicting ? (byte)2 : (byte)0, answer.ResponseCode);
        Assert.Equal(conflicting ? Array.Empty<ushort>() : new ushort[] { 39, 5, 1 }, answer.Answers.Select(record => record.Type));
    }

    [Fact]
    public async Task DirectCnameAndDnameQueriesDoNotChaseTheirTarget()
    {
        var source = new Script((question, _) => new DnsAnswer(0, true, [Name(question.Name.ToString(), question.Type, "other.")], [], []));
        foreach (var type in new ushort[] { 5, 39 })
        {
            var answer = await Resolver(source).ResolveAsync(Q("example.", type), CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(type, Assert.Single(answer.Answers).Type);
        }
        Assert.Equal(2, source.Calls.Count);
    }

    [Fact]
    public async Task EarlierAliasTtlAgesDuringTargetResolution()
    {
        var clock = new Clock();
        var source = new Script((question, _) =>
        {
            if (question.Name.Equals(N("a."))) return new DnsAnswer(0, true, [new DnsRecord(question.Name, 5, 10, N("b.").ToWire())], [], []);
            clock.Seconds = 3.1;
            return Positive(question.Name, 42);
        });
        var result = await new NonValidatingIterativeResolver(source, [Root], time: clock).ResolveAsync(Q("a."), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(6u, result.Answers[0].Ttl);
        Assert.Equal(300u, result.Answers[1].Ttl);
    }

    [Fact]
    public async Task DuplicateDataUsesLowestRrsetTtl()
    {
        var source = new Script((question, _) => new DnsAnswer(0, true, [A(question.Name.ToString(), 42), A(question.Name.ToString(), 42).WithTtl(60)], [], []));
        var answer = await Resolver(source).ResolveAsync(Q("a."), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(60u, Assert.Single(answer.Answers).Ttl);
    }

    [Fact]
    public async Task TooManyReplyRecordsFailClosed()
    {
        var source = new Script((question, _) => new DnsAnswer(0, true, Enumerable.Repeat(A(question.Name.ToString(), 42), 513), [], []));
        var answer = await Resolver(source).ResolveAsync(Q("a."), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, answer.ResponseCode);
        Assert.Empty(answer.Answers);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(6)]
    public async Task OverlongDnameSynthesisReturnsYxdomainWithOnlyDname(int code)
    {
        var target = string.Concat(Enumerable.Repeat("a.", 127));
        var source = new Script((_, _) => new DnsAnswer((byte)code, true, [Name("example.", 39, target)], [], []));
        var answer = await Resolver(source).ResolveAsync(Q("www.example."), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(6, answer.ResponseCode);
        Assert.Equal((ushort)39, Assert.Single(answer.Answers).Type);
    }

    [Fact]
    public async Task UnsubstantiatedYxdomainCannotBecomeATerminalAnswer()
    {
        var source = new Script((_, _) => Negative(".", 6));
        Assert.Equal(2, (await Resolver(source).ResolveAsync(Q("a."), CancellationToken.None).ConfigureAwait(true)).ResponseCode);
    }

    private sealed class Clock : TimeProvider
    {
        public double Seconds { get; set; }
        public override long TimestampFrequency => 10;
        public override long GetTimestamp() => (long)(Seconds * 10);
    }

    [Fact]
    public async Task CancellationIsNotAReportedDnsFailure()
    {
        var source = new Script((_, _) => throw new OperationCanceledException(CancellationToken.None));
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await Resolver(source).ResolveAsync(Q("www.example."), CancellationToken.None).ConfigureAwait(false));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(255, 1)]
    [InlineData(1, 3)]
    public async Task UnsupportedQuestionIsRefusedBeforeIo(int type, int recordClass)
    {
        var source = new Script((_, _) => throw new InvalidOperationException("No I/O expected"));
        Assert.Equal(5, (await Resolver(source).ResolveAsync(new DnsQuestion(N("www.example."), (ushort)type, (ushort)recordClass), CancellationToken.None)).ResponseCode);
        Assert.Empty(source.Calls);
    }

    [Fact]
    public void EndpointOwnsItsAddressAndRejectsInvalidEgressKinds()
    {
        byte[] bytes = [127, 0, 0, 1];
        var endpoint = new DnsServerEndpoint(bytes);
        bytes[3] = 9;
        var copy = endpoint.GetAddress(); copy[3] = 8;
        Assert.Equal(new byte[] { 127, 0, 0, 1 }, endpoint.GetAddress());
        Assert.Throws<ArgumentException>(() => new DnsServerEndpoint(new byte[4]));
        Assert.Throws<ArgumentException>(() => new DnsServerEndpoint(new byte[] { 224, 0, 0, 1 }));
        Assert.Throws<ArgumentException>(() => new DnsServerEndpoint(new byte[] { 127, 0, 0, 1 }, 0));
    }

    private static NonValidatingIterativeResolver Resolver(Script source) => new(source, [Root]);
    private static DnsQuestion Q(string name, ushort type = 1) => new(N(name), type, 1);
    private static DnsName N(string name) => DnsName.Parse(name);
    private static DnsServerEndpoint Server(byte last) => new(new byte[] { 127, 0, 0, last });
    private static DnsRecord A(string name, byte last) => new(N(name), 1, 300, new byte[] { 192, 0, 2, last });
    private static DnsRecord Name(string owner, ushort type, string target) => new(N(owner), type, 300, N(target).ToWire());
    private static DnsAnswer Positive(DnsName name, byte last) => new(0, true, [A(name.ToString(), last)], [], []);
    private static DnsAnswer Referral(string origin, string ns, byte address) => new(0, false, [], [Name(origin, 2, ns)], [new DnsRecord(N(ns), 1, 300, new byte[] { 127, 0, 0, address })]);
    private static DnsAnswer Negative(string origin, byte code)
    {
        byte[] numbers = new byte[20]; numbers[^1] = 60;
        var suffix = string.Equals(origin, ".", StringComparison.Ordinal) ? "" : origin;
        return new DnsAnswer(code, true, [], [new DnsRecord(N(origin), 6, 300, [.. N("ns." + suffix).ToWire(), .. N("hostmaster." + suffix).ToWire(), .. numbers])], []);
    }
    private sealed class Script(Func<DnsQuestion, DnsServerEndpoint, DnsAnswer> action) : IDnsUpstream
    {
        public List<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = [];
        public ValueTask<DnsAnswer> ExchangeAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls.Add((question, server));
            return ValueTask.FromResult(action(question, server));
        }
    }
}
