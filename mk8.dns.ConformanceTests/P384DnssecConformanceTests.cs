using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.ConformanceTests;

public sealed class P384DnssecConformanceTests
{
    // Public DNSKEY/RRSIG/DS records from RFC6605 section6.2, not production keys.
    private const string PublicKey = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";
    private const string Signature = "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm";
    private const string Digest = "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6";
    private const uint Inception = 1281608425;
    private const uint Expiration = 1284027625;

    [Theory]
    [InlineData(Inception - 1, false)]
    [InlineData(Inception, true)]
    [InlineData(Inception + 3600, true)]
    [InlineData(Expiration, true)]
    [InlineData(Expiration + 1, false)]
    public void PublicP384RfcVectorUsesExactSha384AndSerialWindow(uint now, bool expected)
    {
        var (key, record, signature) = Vector();
        Assert.Equal((ushort)10771, DnssecKeys.KeyTag(key));
        Assert.Equal(expected, DnssecRrsetVerifier.TryVerify([record], signature, key, now, new DnssecSignatureVerifier(), out var ttl));
        Assert.Equal(expected ? Math.Min(45U, unchecked(Expiration - now)) : 0, ttl);
    }

    [Fact]
    public void RfcSha384DsBindsTheFullOwnerAlgorithmKeytagAnd48ByteDigest()
    {
        var (key, _, _) = Vector(); var ds = DnssecKeys.CreateDs(key, 3600, 4);
        Assert.Equal(new byte[] { 42, 19, 14, 4 }, ds.GetData().AsSpan(0, 4).ToArray());
        Assert.Equal(Convert.FromHexString(Digest), ds.GetData().AsSpan(4).ToArray());
    }

    [Fact]
    public void SelectedSignatureBitAndWrongHashAlgorithmRefuse()
    {
        var (key, record, signature) = Vector(); var bytes = signature.GetData(); bytes[^1] ^= 1;
        Assert.False(DnssecRrsetVerifier.TryVerify([record], new DnsRecord(record.Owner, 46, 90, bytes), key, Inception + 1, new DnssecSignatureVerifier(), out _));
        Assert.False(new EcdsaP256DnssecVerifier().VerifyHash(14, key.GetData().AsSpan(4), new byte[48], Convert.FromBase64String(Signature)));
    }

    private static (DnsRecord Key, DnsRecord Record, DnsRecord Signature) Vector()
    {
        var owner = DnsName.Parse("www.example.net."); var signer = DnsName.Parse("example.net.");
        var key = new DnsRecord(signer, 48, 3600, [1, 1, 3, 14, .. Convert.FromBase64String(PublicKey)]);
        var record = new DnsRecord(owner, 1, 45, [192, 0, 2, 1]); var header = new byte[18];
        BinaryPrimitives.WriteUInt16BigEndian(header, 1); header[2] = 14; header[3] = 3;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), 3600); BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), Expiration);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), Inception); BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(16), 10771);
        return (key, record, new DnsRecord(owner, 46, 90, [.. header, .. signer.ToWire(), .. Convert.FromBase64String(Signature)]));
    }
}
