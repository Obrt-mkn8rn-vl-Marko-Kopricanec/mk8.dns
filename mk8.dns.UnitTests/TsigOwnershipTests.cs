using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TsigOwnershipTests
{
    [Fact]
    public void KeysAndAdmittedTransactionsRetainTheirOwnStateAndTerminalCallsFail()
    {
        var secret = (byte[])TsigPackets.Secret.Clone(); var peer = new byte[4];
        using var key = new TsigKey(DnsName.Parse("query-key."), secret, [DnsName.Parse("example.")], [peer]);
        using var service = new TsigService([key], new CookieClock(1559731985));
        secret[0] ^= 255; peer[0] = 1; key.Dispose();
        var request = TsigPackets.Sign(AuthorityFixture.Query());
        using var admitted = service.Open(request, new byte[4]); Assert.NotNull(admitted);
        Assert.Equal(0, admitted.TsigError); Assert.True(admitted.Authorizes(DnsName.Parse("example.")));
        var copy = admitted.GetRequest(); copy[0] = 0;
        Assert.Equal(0xab, admitted.GetRequest()[0]);
        request[^7] ^= 255;
        service.Dispose(); Assert.False(service.IsAvailable);
        var response = admitted.Complete(DnsMessageCodec.EncodeError(AuthorityFixture.Query(), 2));
        var original = TsigPackets.Sign(AuthorityFixture.Query()); var reply = TsigPackets.Parse(response);
        Assert.Equal(TsigPackets.ExpectedMac(reply, original), reply.Mac);
        Assert.Throws<InvalidOperationException>(() => admitted.Complete(new byte[12]));
        admitted.Dispose(); Assert.Throws<ObjectDisposedException>(() => admitted.Complete(new byte[12])); Assert.Throws<ObjectDisposedException>(() => admitted.GetRequest());
        Assert.Throws<ObjectDisposedException>(() => service.Open(original, new byte[4]));
    }

    [Fact]
    public void EnvelopeOwnsMessageMacAndOtherBytes()
    {
        var message = AuthorityFixture.Query(); var mac = new byte[32]; var other = new byte[3];
        var envelope = new TsigRequest(message, DnsName.Parse("key."), DnsName.Parse("hmac-sha256."), 1, 300, mac, 0xabcd, 0, other);
        message[0] = 0; mac[0] = 1; other[0] = 1;
        Assert.Equal(0xab, envelope.GetMessage()[0]); Assert.Equal(new byte[32], envelope.GetMac()); Assert.Equal(new byte[3], envelope.GetOtherData());
        envelope.GetMac()[0] = 1; Assert.Equal(new byte[32], envelope.GetMac());
    }

    [Fact]
    public void InvalidConfigurationAndDuplicateIdentitiesAreRejected()
    {
        Assert.Throws<ArgumentException>(() => new TsigKey(DnsName.Parse("."), TsigPackets.Secret, [DnsName.Parse("example.")], [new byte[4]]));
        Assert.Throws<ArgumentException>(() => new TsigKey(DnsName.Parse("key."), new byte[15], [DnsName.Parse("example.")], [new byte[4]]));
        Assert.Throws<ArgumentException>(() => new TsigKey(DnsName.Parse("key."), TsigPackets.Secret, [], [new byte[4]]));
        Assert.Throws<ArgumentException>(() => new TsigKey(DnsName.Parse("key."), TsigPackets.Secret, [DnsName.Parse("example.")], [new byte[3]]));
        Assert.Throws<ArgumentException>(() => new TsigKey(DnsName.Parse("key."), TsigPackets.Secret, [DnsName.Parse("example.")], [new byte[4]], 15));
        using var key = new TsigKey(DnsName.Parse("key."), TsigPackets.Secret, [DnsName.Parse("example.")], [new byte[4]]);
        Assert.Throws<ArgumentException>(() => new TsigService([key, key], TimeProvider.System));
        Assert.Throws<ArgumentException>(() => new TsigService(Enumerable.Repeat(key, 17), TimeProvider.System));
    }
}
