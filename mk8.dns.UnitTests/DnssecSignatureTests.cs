using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecSignatureTests
{
    [Fact]
    public void MultiRecordSignatureIgnoresOrderAndCapsEachReceivedTtl()
    {
        using var key = DnssecFixture.Key();
        var dnskey = DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, key.GetPublicKey());
        DnsRecord[] records = [DnssecFixture.A(last: 2), DnssecFixture.A()];
        var sig = DnssecRrsetSigner.Sign(records, dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
        DnsRecord[] cached = [records[1].WithTtl(45), records[0].WithTtl(90)];
        Assert.True(DnssecRrsetVerifier.TryVerify(cached, sig.WithTtl(75), dnskey, 100, DnssecFixture.Verifier, out var ttl));
        Assert.Equal(45u, ttl);
        Assert.True(DnssecRrsetVerifier.TryVerify(records.Select(record => record.WithTtl(600)).ToArray(), sig.WithTtl(600), dnskey, 100, DnssecFixture.Verifier, out ttl));
        Assert.Equal(300u, ttl);
        Assert.True(DnssecRrsetVerifier.TryVerify(records, sig, dnskey, 9999, DnssecFixture.Verifier, out ttl));
        Assert.Equal(1u, ttl);
        Assert.True(DnssecRrsetVerifier.TryVerify(records, sig, dnskey, 10000, DnssecFixture.Verifier, out ttl));
        Assert.Equal(0u, ttl);
        Assert.False(DnssecRrsetVerifier.TryVerify(records, sig, dnskey, 10001, DnssecFixture.Verifier, out ttl));
        Assert.Equal(0u, ttl);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(12)]
    [InlineData(16)]
    [InlineData(18)]
    [InlineData(19)]
    [InlineData(27)]
    [InlineData(90)]
    public void AlteredRrsigMetadataOrMacCannotAuthenticate(int offset)
    {
        using var key = DnssecFixture.Key();
        var dnskey = DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, key.GetPublicKey());
        var record = DnssecFixture.A();
        var sig = DnssecRrsetSigner.Sign([record], dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
        var data = sig.GetData();
        data[offset] ^= 1;
        Assert.False(DnssecRrsetVerifier.TryVerify([record], new DnsRecord(sig.Owner, 46, sig.Ttl, data), dnskey, 100, DnssecFixture.Verifier, out var ttl));
        Assert.Equal(0u, ttl);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(67)]
    public void AlteredDnskeyFlagsProtocolAlgorithmOrPointCannotAuthenticate(int offset)
    {
        using var key = DnssecFixture.Key();
        var dnskey = DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, key.GetPublicKey());
        var record = DnssecFixture.A();
        var sig = DnssecRrsetSigner.Sign([record], dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
        var data = dnskey.GetData();
        data[offset] ^= offset == 1 ? (byte)128 : (byte)1;
        Assert.False(DnssecRrsetVerifier.TryVerify([record], sig, new DnsRecord(dnskey.Owner, 48, 3600, data), 100, DnssecFixture.Verifier, out var ttl));
        Assert.Equal(0u, ttl);
    }

    [Fact]
    public void ChangedDataOwnerTypeSignerAndMissingMembersFailClosed()
    {
        using var key = DnssecFixture.Key();
        var dnskey = DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, key.GetPublicKey());
        DnsRecord[] records = [DnssecFixture.A(), DnssecFixture.A(last: 2)];
        var sig = DnssecRrsetSigner.Sign(records, dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
        Assert.False(Verify([records[0], DnssecFixture.A(last: 3)], sig, dnskey));
        Assert.False(Verify([records[0]], sig, dnskey));
        Assert.False(Verify([records[0], records[0]], sig, dnskey));
        Assert.False(Verify(records, sig.WithOwner(DnsName.Parse("other.example.")), dnskey));
        Assert.False(Verify(records.Select(record => record.WithOwner(DnsName.Parse("other.example."))).ToArray(), sig, dnskey));
        Assert.False(Verify([new DnsRecord(records[0].Owner, 65280, 300, records[0].GetData())], sig, dnskey));
        Assert.False(Verify(records, sig, dnskey.WithOwner(DnsName.Parse("other."))));
        Assert.False(Verify([], sig, dnskey));
        Assert.False(Verify([null!], sig, dnskey));
        Assert.False(Verify(records, new DnsRecord(sig.Owner, 46, 300, [0]), dnskey));
        Assert.False(Verify(records, new DnsRecord(sig.Owner, 65280, 300, sig.GetData()), dnskey));
        Assert.False(Verify(records, sig, new DnsRecord(dnskey.Owner, 48, 300, new byte[67])));
        Assert.False(Verify(Enumerable.Repeat(records[0], 10001).ToArray(), sig, dnskey));
    }

    [Fact]
    public void RrsigSignerNameCaseIsCanonicalButModernRdataCaseIsAuthenticated()
    {
        using var key = DnssecFixture.Key();
        var dnskey = DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, key.GetPublicKey());
        var record = new DnsRecord(DnsName.Parse("svc.example."), 65, 300, [0, 1, .. DnssecFixture.Name("target.example.", upper: true)]);
        var sig = DnssecRrsetSigner.Sign([record], dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
        var data = sig.GetData();
        DnssecFixture.Name("example.", upper: true).CopyTo(data, 18);
        Assert.True(Verify([record], new DnsRecord(sig.Owner, 46, 300, data), dnskey));
        Assert.False(Verify([new DnsRecord(record.Owner, 65, 300, [0, 1, .. DnssecFixture.Name("target.example.")])], sig, dnskey));
    }

    [Theory]
    [InlineData("*.example.", "host.example.")]
    [InlineData("*.example.", "deep.host.example.")]
    [InlineData("*.sub.example.", "host.sub.example.")]
    [InlineData("*.", "deep.example.")]
    public void WildcardSignatureValidatesExpandedOwnerCryptography(string wildcard, string expanded)
    {
        using var key = DnssecFixture.Key();
        var origin = string.Equals(wildcard, "*.", StringComparison.Ordinal) ? DnsName.Parse(".") : DnssecFixture.Origin;
        var dnskey = DnssecKeys.CreateDnskey(origin, 3600, key.GetPublicKey());
        var record = DnssecFixture.A(wildcard);
        var sig = DnssecRrsetSigner.Sign([record], dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
        Assert.True(Verify([record], sig, dnskey));
        var owner = DnsName.Parse(expanded);
        Assert.True(Verify([record.WithOwner(owner)], sig.WithOwner(owner), dnskey));
        Assert.Equal((byte)(record.Owner.LabelCount - 1), sig.GetData()[3]);
        // Cryptographic validity alone supplies no closest-encloser proof.
    }

    [Fact]
    public void InvalidSigningRrsetsAndMismatchFailBeforeProviderSigning()
    {
        using var key = DnssecFixture.Key();
        using var different = EcdsaP256DnssecSigningKey.Create();
        var spy = new DnssecFixture.CountingKey(key);
        var dnskey = DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, key.GetPublicKey());
        var record = DnssecFixture.A();
        Assert.Throws<ArgumentException>(() => Sign([], dnskey, spy));
        Assert.Throws<ArgumentException>(() => Sign([null!], dnskey, spy));
        Assert.Throws<ArgumentException>(() => Sign([record, record.WithTtl(301)], dnskey, spy));
        Assert.Throws<ArgumentException>(() => Sign([record, DnssecFixture.A("other.example.")], dnskey, spy));
        Assert.Throws<ArgumentException>(() => Sign([record.WithOwner(DnsName.Parse("outside."))], dnskey, spy));
        Assert.Throws<ArgumentException>(() => Sign([new DnsRecord(record.Owner, 46, 300, [0])], dnskey, spy));
        Assert.Throws<FormatException>(() => Sign([record, record], dnskey, spy));
        Assert.Throws<ArgumentException>(() => Sign([record], DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, different.GetPublicKey()), spy));
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public void InvalidProviderSignatureIsNeverPublished()
    {
        using var key = DnssecFixture.Key();
        var spy = new DnssecFixture.CountingKey(key) { CorruptSignature = true };
        var dnskey = DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, key.GetPublicKey());
        Assert.Throws<CryptographicException>(() => Sign([DnssecFixture.A()], dnskey, spy));
        Assert.Equal(1, spy.Calls);
    }

    [Fact]
    public void DnskeyConstructionOwnsBytesAndRejectsWrongWidths()
    {
        using var key = DnssecFixture.Key();
        var point = key.GetPublicKey();
        var dnskey = DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, point, secureEntryPoint: false);
        var original = dnskey.GetData();
        point[0] ^= 1;
        Assert.Equal(original, dnskey.GetData());
        Assert.Equal((byte)0, dnskey.GetData()[1]);
        Assert.Throws<ArgumentException>(() => DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, new byte[63]));
        Assert.Throws<ArgumentException>(() => DnssecKeys.CreateDnskey(DnssecFixture.Origin, 3600, new byte[65]));
        Assert.Throws<FormatException>(() => DnssecKeys.KeyTag(DnssecFixture.A()));
        Assert.Throws<FormatException>(() => DnssecKeys.CreateDs(DnssecFixture.A(), 3600));
    }

    private static bool Verify(IReadOnlyList<DnsRecord> records, DnsRecord signature, DnsRecord dnskey) => DnssecRrsetVerifier.TryVerify(records, signature, dnskey, 100, DnssecFixture.Verifier, out _);
    private static DnsRecord Sign(IReadOnlyList<DnsRecord> records, DnsRecord dnskey, IDnssecSigningKey key) => DnssecRrsetSigner.Sign(records, dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
}
