using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public static class DnssecKeys
{
    public static DnsRecord CreateDnskey(DnsName origin, uint ttl, ReadOnlySpan<byte> publicKey, bool secureEntryPoint = true)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (publicKey.Length != 64)
            throw new ArgumentException("Algorithm 13 requires a 64-octet P-256 public point.", nameof(publicKey));
        var data = new byte[68];
        BinaryPrimitives.WriteUInt16BigEndian(data, secureEntryPoint ? (ushort)257 : (ushort)256);
        data[2] = 3;
        data[3] = 13;
        publicKey.CopyTo(data.AsSpan(4));
        return new DnsRecord(origin, 48, ttl, data);
    }

    public static ushort KeyTag(DnsRecord dnskey)
    {
        var data = ReadValidationKey(dnskey);
        uint accumulator = 0;
        for (var index = 0; index < data.Length; index++)
            accumulator += (index & 1) == 0 ? (uint)data[index] << 8 : data[index];
        accumulator += accumulator >> 16;
        return (ushort)(accumulator & 0xffff);
    }

    public static DnsRecord CreateDs(DnsRecord dnskey, uint ttl)
    {
        var data = ReadValidationKey(dnskey);
        var owner = dnskey.Owner.ToWire();
        byte[] canonical = [.. owner, .. data];
        var digest = SHA256.HashData(canonical);
        var value = new byte[36];
        BinaryPrimitives.WriteUInt16BigEndian(value, KeyTag(dnskey));
        value[2] = data[3];
        value[3] = 2;
        digest.CopyTo(value, 4);
        // This is parent-side publication material, never child-apex zone data.
        return new DnsRecord(dnskey.Owner, 43, ttl, value);
    }

    internal static byte[] ReadKey(DnsRecord key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var data = key.GetData();
        DnssecData.Require(key.Type == 48 && data.Length == 68 && data[2] == 3 && data[3] == 13
            && (BinaryPrimitives.ReadUInt16BigEndian(data) & 256) != 0
            && (BinaryPrimitives.ReadUInt16BigEndian(data) & 128) == 0);
        return data;
    }

    // Validation may consume RSA; the signing/serving ReadKey profile remains algorithm13 only.
    internal static byte[] ReadValidationKey(DnsRecord key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var data = key.GetData();
        DnssecData.Require(key.Type == 48 && data.Length >= 4 && data[2] == 3
            && (BinaryPrimitives.ReadUInt16BigEndian(data) & 256) != 0
            && (BinaryPrimitives.ReadUInt16BigEndian(data) & 128) == 0);
        DnssecData.Require(data[3] == 13 && data.Length == 68
            || data[3] == 8 && DnssecRsaPublicKey.TryParse(data.AsSpan(4), out _));
        return data;
    }
}
