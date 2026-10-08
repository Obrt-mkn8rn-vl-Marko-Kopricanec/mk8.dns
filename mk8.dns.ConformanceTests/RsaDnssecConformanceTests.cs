using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.ConformanceTests;

public sealed class RsaDnssecConformanceTests
{
    // Public 512-bit key and signature from RFC5702 section6.1; not a generation recommendation.
    private const string PublicKey = "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=";
    private const string Signature = "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==";

    [Theory]
    [InlineData(946684799, false)]
    [InlineData(946684800, true)]
    [InlineData(1000000000, true)]
    [InlineData(1893456000, true)]
    [InlineData(1893456001, false)]
    public void Rfc5702PublicSignatureVerifiesWithSerialWindowAndOriginalTtl(uint time, bool expected)
    {
        var owner = DnsName.Parse("www.example.net."); var signer = DnsName.Parse("example.net.");
        var key = new DnsRecord(signer, 48, 3600, [1, 0, 3, 8, .. Convert.FromBase64String(PublicKey)]);
        var record = new DnsRecord(owner, 1, 45, [192, 0, 2, 91]);
        var header = new byte[18]; BinaryPrimitives.WriteUInt16BigEndian(header, 1); header[2] = 8; header[3] = 3;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), 3600);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), 1893456000);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), 946684800);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(16), 9033);
        var signature = new DnsRecord(owner, 46, 90, [.. header, .. signer.ToWire(), .. Convert.FromBase64String(Signature)]);
        Assert.Equal((ushort)9033, DnssecKeys.KeyTag(key));
        Assert.Equal(expected, DnssecRrsetVerifier.TryVerify([record], signature, key, time, new DnssecSignatureVerifier(), out var ttl));
        Assert.Equal(expected ? Math.Min(45U, unchecked(1893456000U - time)) : 0, ttl);
    }
}
