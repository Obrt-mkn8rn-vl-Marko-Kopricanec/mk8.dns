using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnsUpstreamEvidenceTests
{
    [Fact]
    public void ConstructorOwnsInputCollectionsAndExposesOnlyObservations()
    {
        var record = DnssecFixture.A(); var data = record.GetData(); DnsRecord[] answers = [record];
        var value = Evidence(answers);
        answers[0] = DnssecFixture.A(last: 9); data[0] = 0;
        Assert.Same(record, Assert.Single(value.Answers)); Assert.Equal((byte)192, value.Answers[0].GetData()[0]);
        var list = Assert.IsAssignableFrom<IList<DnsRecord>>(value.Answers); Assert.Throws<NotSupportedException>(() => list[0] = answers[0]);
        Assert.True(value.AuthenticatedDataObserved); Assert.True(value.CheckingDisabledObserved);
    }

    [Theory]
    [InlineData(0x0000, 0)]
    [InlineData(0x8830, 0)]
    [InlineData(0x8670, 0)]
    [InlineData(0x8630, 0)]
    [InlineData(0x8431, 0)]
    [InlineData(0x8430, 4096)]
    public void IncompleteInvalidFlagsOrCodeCannotBeConstructed(ushort flags, ushort code)
        => Assert.Throws<ArgumentException>(() => new DnsUpstreamEvidence(DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server,
            42, flags, code, true, 1232, 0, 0x8000, [], [], []));

    [Theory]
    [InlineData(16, 0, 0, 0)]
    [InlineData(0, 1232, 0, 0)]
    [InlineData(0, 0, 1, 0)]
    [InlineData(0, 0, 0, 0x8000)]
    public void NoOptCannotCarryEdnsMetadata(ushort code, ushort payload, byte version, ushort flags)
        => Assert.Throws<ArgumentException>(() => new DnsUpstreamEvidence(DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server,
            42, 0x8430, code, false, payload, version, flags, [], [], []));

    [Fact]
    public void RecordAndLazyInputBoundsRejectBeforeUnboundedEnumeration()
    {
        var record = DnssecFixture.A();
        Assert.Throws<ArgumentException>(() => Evidence(Enumerable.Repeat(record, 513)));
        Assert.Throws<ArgumentException>(() => Evidence([null!]));
        Assert.Throws<ArgumentException>(() => Evidence(Enumerable.Repeat(record, 256), Enumerable.Repeat(record, 256)));
    }

    [Fact]
    public void ExpandedPayloadBudgetAlsoAppliesToDirectPortImplementations()
    {
        var value = new DnsRecord(DnsName.Parse("www.example."), 65280, 300, new byte[ushort.MaxValue]);
        Assert.Throws<ArgumentException>(() => Evidence(Enumerable.Repeat(value, 17)));
    }

    [Fact]
    public void QuestionAndEndpointAdmissionAreExplicit()
    {
        Assert.Throws<ArgumentNullException>(() => new DnsUpstreamEvidence(null!, DnssecUpstreamFixture.Server, 42, 0x8430, 0, true, 1232, 0, 0x8000, [], [], []));
        Assert.Throws<ArgumentNullException>(() => new DnsUpstreamEvidence(DnssecUpstreamFixture.Question, null!, 42, 0x8430, 0, true, 1232, 0, 0x8000, [], [], []));
        Assert.Throws<ArgumentException>(() => new DnsUpstreamEvidence(DnssecUpstreamFixture.Question with { Type = 255 }, DnssecUpstreamFixture.Server, 42, 0x8430, 0, true, 1232, 0, 0x8000, [], [], []));
    }

    private static DnsUpstreamEvidence Evidence(IEnumerable<DnsRecord> answers, IEnumerable<DnsRecord>? authority = null)
        => new(DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server, 42, 0x8430, 0, true, 1232, 0, 0x8000, answers, authority ?? [], []);
}
