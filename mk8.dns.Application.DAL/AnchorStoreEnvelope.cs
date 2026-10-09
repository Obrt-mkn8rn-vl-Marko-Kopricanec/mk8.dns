using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Application.DAL;

internal static class AnchorStoreEnvelope
{
    internal const int MaximumBytes = DnssecTrustAnchorTracker.MaximumCheckpointBytes + 353;
    internal sealed record Generation(long Revision, byte[] Previous, byte[] Checkpoint);
    internal sealed record Pointer(long Revision, byte[] Digest);

    internal static byte[] Encode(string purpose, Guid identity, DnsName origin, long revision,
        ReadOnlySpan<byte> digest, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(System.Text.Encoding.ASCII.GetBytes(purpose));
            writer.Write(identity.ToByteArray());
            var name = origin.ToWire(); writer.Write((ushort)name.Length); writer.Write(name);
            if (!string.Equals(purpose, "M8L1", StringComparison.Ordinal))
            {
                writer.Write(revision); writer.Write(digest);
                if (string.Equals(purpose, "M8S1", StringComparison.Ordinal))
                {
                    writer.Write(payload.Length); writer.Write(payload);
                }
            }
        }
        var body = stream.ToArray();
        return [.. body, .. HMACSHA256.HashData(key, body)];
    }

    internal static Generation DecodeGeneration(byte[] input, Guid identity, DnsName origin, ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream(Authenticate(input, key), writable: false);
        using var reader = new BinaryReader(stream);
        ReadScope(reader, "M8S1", identity, origin);
        var revision = ReadRevision(reader);
        var previous = ReadField(reader, 32);
        var length = reader.ReadInt32();
        if (length is < 49 or > DnssecTrustAnchorTracker.MaximumCheckpointBytes)
            throw new InvalidDataException("Invalid anchor checkpoint payload size.");
        var payload = ReadField(reader, length);
        RequireEnd(reader);
        return new Generation(revision, previous, payload);
    }

    internal static Pointer DecodePointer(byte[] input, Guid identity, DnsName origin, ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream(Authenticate(input, key), writable: false);
        using var reader = new BinaryReader(stream);
        ReadScope(reader, "M8P1", identity, origin);
        var result = new Pointer(ReadRevision(reader), ReadField(reader, 32));
        RequireEnd(reader);
        return result;
    }

    internal static void VerifyMarker(byte[] input, Guid identity, DnsName origin, ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream(Authenticate(input, key), writable: false);
        using var reader = new BinaryReader(stream);
        ReadScope(reader, "M8L1", identity, origin);
        RequireEnd(reader);
    }

    private static byte[] Authenticate(byte[] input, ReadOnlySpan<byte> key)
    {
        if (input.Length is < 55 or > MaximumBytes
            || !CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(key, input.AsSpan(0, input.Length - 32)), input.AsSpan(input.Length - 32)))
            throw new InvalidDataException("Anchor storage authentication failed.");
        return input.AsSpan(0, input.Length - 32).ToArray();
    }

    private static void ReadScope(BinaryReader reader, string purpose, Guid identity, DnsName origin)
    {
        if (!ReadField(reader, 4).AsSpan().SequenceEqual(System.Text.Encoding.ASCII.GetBytes(purpose))
            || new Guid(ReadField(reader, 16)) != identity
            || !ReadField(reader, reader.ReadUInt16()).AsSpan().SequenceEqual(origin.ToWire()))
            throw new InvalidDataException("Anchor storage scope or purpose mismatch.");
    }

    private static long ReadRevision(BinaryReader reader)
    {
        var value = reader.ReadInt64();
        if (value is < 1 or > FileAnchorCheckpointStore.MaximumGenerations)
            throw new InvalidDataException("Invalid anchor storage revision.");
        return value;
    }

    private static byte[] ReadField(BinaryReader reader, int length)
    {
        if (length < 1 || length > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new InvalidDataException("Truncated anchor storage field.");
        return reader.ReadBytes(length);
    }

    private static void RequireEnd(BinaryReader reader)
    {
        if (reader.BaseStream.Position != reader.BaseStream.Length)
            throw new InvalidDataException("Trailing anchor storage data.");
    }
}
