using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NsecWorkLimitTests
{
    [Fact]
    public void OneBudgetIncludesSuccessfulSoaAndCollidingNsecCandidates()
    {
        using var fixture = new DnssecChainFixture();
        var records = new List<DnsRecord> { fixture.ParentCskRecord };
        while (records.Count < DnssecChainValidator.MaximumKeys)
            records.Add(Collision(fixture.ParentCskRecord));
        var signature = DnssecChainFixture.Sign(records, fixture.ParentCskRecord, fixture.ParentCsk);
        var provider = new DnssecChainFixture.CountingVerifier();
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), records, [signature], out var keys));
        var soa = AuthorityFixture.Zone().Soa;
        var nsec = new DnsRecord(DnsName.Parse("a.example."), 47, 300, [.. DnsName.Parse("z.example.").ToWire(), .. NsecBitmap.Encode([1, 46, 47])]);
        var goodSoa = DnssecChainFixture.Sign([soa], fixture.ParentCskRecord, fixture.ParentCsk);
        var original = DnssecChainFixture.Sign([nsec], fixture.ParentCskRecord, fixture.ParentCsk);
        var bytes = original.GetData(); bytes[^1] ^= 1;
        var bad = new DnsRecord(original.Owner, 46, 300, bytes);
        provider.Reset();
        Assert.False(validator.TryAuthenticateNoData(keys, new DnsQuestion(nsec.Owner, 28, 1), [soa], [nsec], [goodSoa, bad, bad, bad], out _));
        Assert.Equal(DnssecChainValidator.MaximumVerificationAttempts, provider.Calls);
    }

    private static DnsRecord Collision(DnsRecord original)
    {
        var target = DnssecKeys.KeyTag(original);
        for (var attempt = 0; attempt < 256; attempt++)
        {
            using var key = EcdsaP256DnssecSigningKey.Create();
            var bytes = DnssecKeys.CreateDnskey(original.Owner, 300, key.GetPublicKey()).GetData();
            bytes[0] = bytes[1] = 0;
            uint sum = 0;
            for (var index = 0; index < bytes.Length; index++)
                sum += (index & 1) == 0 ? (uint)bytes[index] << 8 : bytes[index];
            var baseTag = (ushort)((sum + (sum >> 16)) & 0xffff);
            foreach (var correction in new[] { -1, 0, 1 })
            {
                var flags = unchecked((ushort)(target - baseTag + correction));
                if ((flags & 256) == 0 || (flags & 128) != 0) continue;
                BinaryPrimitives.WriteUInt16BigEndian(bytes, flags);
                var record = new DnsRecord(original.Owner, 48, 300, bytes);
                if (DnssecKeys.KeyTag(record) == target) return record;
            }
        }
        throw new InvalidOperationException("Could not construct a controlled public-key tag collision.");
    }
}
