using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

internal sealed class TrustAnchorFixture : IDisposable
{
    internal DnsName Origin { get; } = DnsName.Parse("example.");
    internal EcdsaP256DnssecSigningKey A { get; } = DnssecFixture.Key();
    internal EcdsaP256DnssecSigningKey B { get; } = EcdsaP256DnssecSigningKey.Create();
    internal EcdsaP256DnssecSigningKey C { get; } = EcdsaP256DnssecSigningKey.Create();
    internal DnssecChainFixture.ClockProvider Clock { get; } = new();
    internal DnsRecord Key(IDnssecSigningKey key, uint ttl = 3600, bool sep = true)
        => DnssecKeys.CreateDnskey(Origin, ttl, key.GetPublicKey(), sep);
    internal static DnsRecord Revoke(DnsRecord record)
    {
        var data = record.GetData();
        data[1] |= 128;
        return new DnsRecord(record.Owner, 48, record.Ttl, data);
    }

    internal DnsRecord Sign(DnsRecord[] records, IDnssecSigningKey key, DnsRecord? signingRecord = null,
        uint? originalTtl = null, uint? signatureTtl = null, uint? expiration = null)
    {
        var dnskey = signingRecord ?? Key(key);
        var value = dnskey.GetData();
        uint tag = 0;
        for (var index = 0; index < value.Length; index++)
            tag += (index & 1) == 0 ? (uint)value[index] << 8 : value[index];
        tag += tag >> 16;
        var now = unchecked((uint)Clock.GetUtcNow().ToUnixTimeSeconds());
        var header = new byte[18 + Origin.ToWire().Length];
        BinaryPrimitives.WriteUInt16BigEndian(header, 48);
        header[2] = 13;
        header[3] = (byte)Origin.LabelCount;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), originalTtl ?? records[0].Ttl);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), expiration ?? unchecked(now + 86400));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), unchecked(now - 1));
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(16), (ushort)tag);
        Origin.ToWire().CopyTo(header, 18);
        byte[] message = [.. header, .. DnssecCanonical.GetRrset(records, originalTtl ?? records[0].Ttl, (byte)Origin.LabelCount)];
        return new DnsRecord(Origin, 46, signatureTtl ?? records[0].Ttl, [.. header, .. key.SignHash(SHA256.HashData(message))]);
    }

    internal DnssecTrustAnchorTracker Tracker(params IDnssecSigningKey[] keys)
        => new(Origin, keys.Select(key => Key(key)).ToArray(), DnssecFixture.Verifier, Clock);
    internal static bool Apply(DnssecTrustAnchorTracker tracker, DnsRecord[] records, params DnsRecord[] signatures)
    {
        Assert.True(tracker.TryCapture(records, signatures, out var observation));
        return tracker.TryApply(observation);
    }
    internal static DnssecAnchorStatus Status(DnssecTrustAnchorTracker tracker, DnsRecord key)
        => Assert.Single(tracker.GetStatus(), entry => entry.Key.GetData().AsSpan().SequenceEqual(key.GetData()));
    public void Dispose()
    {
        A.Dispose();
        B.Dispose();
        C.Dispose();
    }
}
