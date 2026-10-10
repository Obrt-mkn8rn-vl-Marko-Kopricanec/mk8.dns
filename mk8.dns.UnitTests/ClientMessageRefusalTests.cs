using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientMessageRefusalTests
{
    [Theory]
    [InlineData(0x8000)]
    [InlineData(0x2000)]
    [InlineData(0x0400)]
    [InlineData(0x0200)]
    [InlineData(0x0080)]
    [InlineData(0x0040)]
    public async Task ManuallyConstructedNonQueryFlagsCannotEnterEncoding(int flags)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        var query = new DnsQuery(1, (ushort)flags, question, question.Name.ToWire(), 512, hasEdns: false, 0, dnssecOk: false);
        Assert.False(DnssecClientMessageCodec.TryEncode(query, result, tcp: false, recursionAvailable: true, authenticatedDataAllowed: true, out var message));
        Assert.Empty(message);
    }

    [Theory]
    [InlineData("other.example.", 1, 1, 0, false, false)]
    [InlineData("www.example.", 28, 1, 0, false, false)]
    [InlineData("www.example.", 1, 3, 0, false, false)]
    [InlineData("www.example.", 1, 1, 1, false, false)]
    [InlineData("www.example.", 1, 1, 0, true, false)]
    [InlineData("www.example.", 1, 1, 0, false, true)]
    public async Task QuestionEdnsAndCookieProfilesRefuseWithoutBytes(string name, int type, int queryClass, int version,
        bool inconsistentDo, bool cookie)
    {
        ArgumentNullException.ThrowIfNull(name);
        using var fixture = new OnlineDnssecFixture();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None);
        var question = new DnsQuestion(DnsName.Parse(name), (ushort)type, (ushort)queryClass);
        var query = new DnsQuery(1, 0x0100, question, question.Name.ToWire(), 512, !inconsistentDo, (byte)version,
            inconsistentDo, cookie ? new byte[8] : null);
        Assert.False(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true, authenticatedDataAllowed: true, out var message));
        Assert.Empty(message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CdAndAdNeverPromoteUnsignedOrProoflessSourceResults(bool unsignedChild)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.UnsignedChild = unsignedChild;
        var query = ClientMessageFixture.Query(unsignedChild ? "www.child.example." : "www.example.", flags: 0x0130);
        var result = await fixture.Resolver().ResolveDnssecAsync(query.Question!, CancellationToken.None);
        Assert.False(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true, authenticatedDataAllowed: true, out var message));
        Assert.Empty(message);
    }
}
