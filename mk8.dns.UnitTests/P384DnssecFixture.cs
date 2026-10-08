using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.UnitTests;

internal sealed class P384DnssecFixture : IDisposable
{
    private readonly ECDsa key;
    private readonly byte algorithm;
    internal P384DnssecFixture(string origin = "example.", byte algorithm = 14, bool sep = true)
    {
        this.algorithm = algorithm;
        key = ECDsa.Create(algorithm == 14 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256);
        var material = key.ExportParameters(false); PublicKey = [.. material.Q.X!, .. material.Q.Y!];
        Origin = DnsName.Parse(origin); Key = new DnsRecord(Origin, 48, 300, [1, sep ? (byte)1 : (byte)0, 3, algorithm, .. PublicKey]);
    }
    internal DnsName Origin { get; }
    internal DnsRecord Key { get; }
    internal byte[] PublicKey { get; }
    internal DnssecChainFixture.ClockProvider Clock { get; } = new();
    internal static DnssecSignatureVerifier Verifier { get; } = new();
    internal DnssecChainValidator Validator() => new(Verifier, Clock);
    internal DnsRecord Sign(IReadOnlyList<DnsRecord> records, DnssecSignatureWindow? window = null)
    {
        var first = records[0]; var header = new byte[18];
        BinaryPrimitives.WriteUInt16BigEndian(header, first.Type); header[2] = algorithm;
        header[3] = (byte)(first.Owner.LabelCount - (first.Owner.ToWire() is [1, 42, ..] ? 1 : 0));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), first.Ttl);
        var dates = window ?? DnssecFixture.Window;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), dates.Expiration); BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), dates.Inception);
        var data = Key.GetData(); uint tag = 0;
        for (var index = 0; index < data.Length; index++) tag += (index & 1) == 0 ? (uint)data[index] << 8 : data[index];
        tag += tag >> 16; BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(16), (ushort)tag);
        byte[] prefix = [.. header, .. Origin.ToWire()]; byte[] canonical = [.. prefix, .. DnssecCanonical.GetRrset(records, first.Ttl, header[3])];
        var digest = algorithm == 14 ? SHA384.HashData(canonical) : SHA256.HashData(canonical);
        return new DnsRecord(first.Owner, 46, first.Ttl, [.. prefix, .. key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]);
    }
    public void Dispose() => key.Dispose();
}
