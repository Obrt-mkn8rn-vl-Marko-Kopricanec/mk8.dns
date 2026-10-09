using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.IntegrationTests;

internal sealed class AnchorRefreshWireFixture : IDisposable, IDnssecUpstream
{
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    internal DnsName Origin { get; } = DnsName.Parse("example.");
    internal EcdsaP256DnssecSigningKey Key { get; } = EcdsaP256DnssecSigningKey.Create();
    internal EcdsaP256DnssecSigningKey Next { get; } = EcdsaP256DnssecSigningKey.Create();
    internal EcdsaP256DnssecVerifier Verifier { get; } = new();
    internal FixedClock Clock { get; } = new();
    internal DnsRecord Initial => DnssecKeys.CreateDnskey(Origin, 3600, Key.GetPublicKey());
    internal DnsRecord[] Records(bool revoke = false, bool corrupt = false)
    {
        var first = Initial;
        if (revoke) { var bytes = first.GetData(); bytes[1] |= 128; first = new DnsRecord(Origin, 48, 3600, bytes); }
        DnsRecord[] records = revoke ? [first] : [first, DnssecKeys.CreateDnskey(Origin, 3600, Next.GetPublicKey())];
        var signature = revoke ? RevocationSignature(records, first)
            : DnssecRrsetSigner.Sign(records, first, Key, Verifier, new DnssecSignatureWindow(99, 10_000));
        if (corrupt) { var bytes = signature.GetData(); bytes[^1] ^= 1; signature = new DnsRecord(Origin, 46, 3600, bytes); }
        return [.. records, signature];
    }

    private DnsRecord RevocationSignature(DnsRecord[] records, DnsRecord revoked)
    {
        var data = revoked.GetData(); uint tag = 0;
        for (var index = 0; index < data.Length; index++) tag += (index & 1) == 0 ? (uint)data[index] << 8 : data[index];
        tag += tag >> 16;
        var header = new byte[18 + Origin.ToWire().Length];
        BinaryPrimitives.WriteUInt16BigEndian(header, 48); header[2] = 13; header[3] = (byte)Origin.LabelCount;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), 3600); BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), 10_000);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), 99); BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(16), (ushort)tag);
        Origin.ToWire().CopyTo(header, 18);
        byte[] message = [.. header, .. DnssecCanonical.GetRrset(records, 3600, (byte)Origin.LabelCount)];
        return new DnsRecord(Origin, 46, 3600, [.. header, .. Key.SignHash(SHA256.HashData(message))]);
    }

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        => ValueTask.FromResult(new DnsUpstreamEvidence(question, server, 1, 0x8430, 0, hasEdns: true, 1232, 0, 0x8000, Records(revoke: true), [], []));

    internal static byte[] Reply(byte[] request, DnsRecord[] records)
    {
        var end = 12;
        while (request[end] != 0) end += request[end] + 1;
        end += 5;
        using var output = new MemoryStream(); var header = request.AsSpan(0, end).ToArray();
        DnssecUpstreamFixture.Write16(header, 2, 0x8430); DnssecUpstreamFixture.Write16(header, 6, (ushort)records.Length);
        DnssecUpstreamFixture.Write16(header, 8, 0); DnssecUpstreamFixture.Write16(header, 10, 0); output.Write(header);
        foreach (var record in records)
        {
            output.Write(record.Owner.ToWire()); var bytes = record.GetData(); var fields = new byte[10];
            BinaryPrimitives.WriteUInt16BigEndian(fields, record.Type); BinaryPrimitives.WriteUInt16BigEndian(fields.AsSpan(2), 1);
            BinaryPrimitives.WriteUInt32BigEndian(fields.AsSpan(4), record.Ttl); BinaryPrimitives.WriteUInt16BigEndian(fields.AsSpan(8), (ushort)bytes.Length);
            output.Write(fields); output.Write(bytes);
        }
        return output.ToArray();
    }

    public void Dispose() { Key.Dispose(); Next.Dispose(); }
    internal sealed class FixedClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
