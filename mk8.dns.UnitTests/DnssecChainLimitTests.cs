using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecChainLimitTests
{
    [Fact]
    public void EqualKeyTagWithDifferentPublicPointCannotSatisfyDsDigest()
    {
        using var fixture = new DnssecChainFixture();
        var collision = Collision(fixture.ChildCskRecord);
        Assert.Equal(DnssecKeys.KeyTag(fixture.ChildCskRecord), DnssecKeys.KeyTag(collision));
        Assert.NotEqual(fixture.Delegation.GetData(), DnssecKeys.CreateDs(collision, 300).GetData());
        // Even the matching trusted key's valid signature cannot authenticate a
        // replacement RRset that excludes the actual DS-matched public key.
        DnsRecord[] keys = [collision, fixture.ChildZskRecord];
        var signature = DnssecChainFixture.Sign(keys, fixture.ChildCskRecord, fixture.ChildCsk);
        Assert.False(fixture.Validator.TryAuthenticateChild(fixture.Trust(), fixture.Child, [fixture.Delegation], [fixture.DelegationSignature], keys, [signature], out _));
    }

    [Fact]
    public void CollidingKeyTagsCannotExceedTheCryptoAttemptBudget()
    {
        using var fixture = new DnssecChainFixture();
        var records = new List<DnsRecord> { fixture.ParentCskRecord };
        while (records.Count < DnssecChainValidator.MaximumKeys)
            records.Add(Collision(fixture.ParentCskRecord));
        var sig = DnssecChainFixture.Sign(records, fixture.ParentCskRecord, fixture.ParentCsk);
        var provider = new DnssecChainFixture.CountingVerifier();
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), records, [sig], out var keys));
        var data = DnssecFixture.A();
        var original = DnssecChainFixture.Sign([data], fixture.ParentCskRecord, fixture.ParentCsk);
        var bytes = original.GetData();
        bytes[^1] ^= 1;
        var bad = new DnsRecord(original.Owner, 46, 300, bytes);
        provider.Reset();
        Assert.False(validator.TryAuthenticateRrset(keys, new DnsQuestion(data.Owner, 1, 1), [data], Enumerable.Repeat(bad, 16).ToArray(), out _));
        Assert.Equal(DnssecChainValidator.MaximumVerificationAttempts, provider.Calls);
    }

    [Fact]
    public void MaximumDepthStopsBeforeVerifyingAnotherDelegation()
    {
        using var fixture = new DnssecChainFixture();
        var provider = new DnssecChainFixture.CountingVerifier();
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        var name = DnsName.Parse(".");
        var record = fixture.ParentCskRecord.WithOwner(name);
        var signature = DnssecChainFixture.Sign([record], record, fixture.ParentCsk);
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(record), [record], [signature], out var keys));
        for (var depth = 2; depth <= DnssecChainValidator.MaximumDepth; depth++)
        {
            var child = name.PrependLabel([(byte)'a']);
            var childRecord = record.WithOwner(child);
            var ds = DnssecKeys.CreateDs(childRecord, 300);
            var dsSig = DnssecChainFixture.Sign([ds], record, fixture.ParentCsk);
            var childSig = DnssecChainFixture.Sign([childRecord], childRecord, fixture.ParentCsk);
            Assert.True(validator.TryAuthenticateChild(keys, child, [ds], [dsSig], [childRecord], [childSig], out keys));
            name = child;
            record = childRecord;
        }
        var next = name.PrependLabel([(byte)'b']);
        var nextRecord = record.WithOwner(next);
        var nextDs = DnssecKeys.CreateDs(nextRecord, 300);
        var nextSig = DnssecChainFixture.Sign([nextDs], record, fixture.ParentCsk);
        var nextKeySig = DnssecChainFixture.Sign([nextRecord], nextRecord, fixture.ParentCsk);
        provider.Reset();
        Assert.False(validator.TryAuthenticateChild(keys, next, [nextDs], [nextSig], [nextRecord], [nextKeySig], out _));
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public void ExcessCanonicalBytesFailBeforeCrypto()
    {
        using var fixture = new DnssecChainFixture();
        var records = new List<DnsRecord> { fixture.ParentCskRecord };
        for (var index = 0; index < 17; index++)
        {
            var bytes = new byte[ushort.MaxValue];
            bytes[0] = 1;
            bytes[1] = 0;
            bytes[2] = 3;
            bytes[3] = 253;
            bytes[^1] = (byte)index;
            records.Add(new DnsRecord(fixture.Parent, 48, 300, bytes));
        }
        var provider = new DnssecChainFixture.CountingVerifier();
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        Assert.False(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), records, [fixture.ParentSignature], out _));
        Assert.Equal(0, provider.Calls);
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
