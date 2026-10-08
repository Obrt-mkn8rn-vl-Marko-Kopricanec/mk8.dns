using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.UnitTests;

internal sealed class RsaDnssecFixture : IDisposable
{
    private readonly RSA rsa;
    internal RsaDnssecFixture(int bits = 1024, string origin = "example.")
    {
        rsa = RSA.Create(bits);
        Origin = DnsName.Parse(origin);
        var material = rsa.ExportParameters(includePrivateParameters: false);
        PublicKey = [checked((byte)material.Exponent!.Length), .. material.Exponent, .. material.Modulus!];
        Key = new DnsRecord(Origin, 48, 300, [1, 1, 3, 8, .. PublicKey]);
    }

    internal DnsName Origin { get; }
    internal byte[] PublicKey { get; }
    internal DnsRecord Key { get; }
    internal static DnssecSignatureVerifier Verifier { get; } = new();
    internal DnssecChainFixture.ClockProvider Clock { get; } = new();
    internal DnssecChainValidator Validator() => new(Verifier, Clock);

    internal DnsRecord Sign(IReadOnlyList<DnsRecord> records, byte algorithm = 8, DnssecSignatureWindow? window = null)
    {
        var first = records[0]; var owner = Origin.ToWire(); var header = new byte[18 + owner.Length];
        BinaryPrimitives.WriteUInt16BigEndian(header, first.Type); header[2] = algorithm;
        header[3] = (byte)(first.Owner.LabelCount - (first.Owner.ToWire() is [1, 42, ..] ? 1 : 0));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), first.Ttl);
        var dates = window ?? DnssecFixture.Window;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), dates.Expiration);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), dates.Inception);
        // Independent key-tag sum, not the production key helper.
        var keyData = Key.GetData(); uint tag = 0;
        for (var index = 0; index < keyData.Length; index++) tag += (index & 1) == 0 ? (uint)keyData[index] << 8 : keyData[index];
        tag += tag >> 16; BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(16), (ushort)tag); owner.CopyTo(header, 18);
        byte[] input = [.. header, .. DnssecCanonical.GetRrset(records, first.Ttl, header[3])];
        var signature = rsa.SignHash(SHA256.HashData(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new DnsRecord(first.Owner, 46, first.Ttl, [.. header, .. signature]);
    }

    public void Dispose() => rsa.Dispose();
}
