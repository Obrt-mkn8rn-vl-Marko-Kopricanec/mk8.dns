using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Application.DAL;

// Separate purposes prevent either store mode from adopting the other's files.
internal static class AnchorRetentionEnvelope
{
    internal sealed record Generation(long Revision, byte[] Previous, byte[] Checkpoint);
    internal sealed record Pointer(long Revision, long First, byte[] Previous, byte[] Digest);

    internal static byte[] EncodeMarker(Guid identity, DnsName origin, ReadOnlySpan<byte> key)
        => Encode("M8L2", identity, origin, 0, 0, [], [], [], key);

    internal static byte[] EncodeGeneration(Guid identity, DnsName origin, long revision,
        ReadOnlySpan<byte> previous, ReadOnlySpan<byte> checkpoint, ReadOnlySpan<byte> key)
        => Encode("M8S2", identity, origin, revision, 0, previous, [], checkpoint, key);

    internal static byte[] EncodePointer(Guid identity, DnsName origin, Pointer value, ReadOnlySpan<byte> key)
        => Encode("M8P2", identity, origin, value.Revision, value.First, value.Previous, value.Digest, [], key);

    private static byte[] Encode(string purpose, Guid identity, DnsName origin, long revision, long first,
        ReadOnlySpan<byte> previous, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(System.Text.Encoding.ASCII.GetBytes(purpose));
            writer.Write(identity.ToByteArray());
            var name = origin.ToWire(); writer.Write((ushort)name.Length); writer.Write(name);
            if (string.Equals(purpose, "M8S2", StringComparison.Ordinal))
            {
                writer.Write(revision); writer.Write(previous); writer.Write(payload.Length); writer.Write(payload);
            }
            else if (string.Equals(purpose, "M8P2", StringComparison.Ordinal))
            {
                writer.Write(revision); writer.Write(first); writer.Write(previous); writer.Write(digest);
            }
        }
        var body = stream.ToArray();
        return [.. body, .. HMACSHA256.HashData(key, body)];
    }

    internal static void VerifyMarker(byte[] input, Guid identity, DnsName origin, ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream(Authenticate(input, key), writable: false);
        using var reader = new BinaryReader(stream);
        Scope(reader, "M8L2", identity, origin); End(reader);
    }

    internal static Generation DecodeGeneration(byte[] input, Guid identity, DnsName origin, ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream(Authenticate(input, key), writable: false);
        using var reader = new BinaryReader(stream);
        Scope(reader, "M8S2", identity, origin);
        var revision = Revision(reader); var previous = Field(reader, 32); var length = reader.ReadInt32();
        if (length is < 49 or > DnssecTrustAnchorTracker.MaximumCheckpointBytes)
            throw new InvalidDataException("Invalid retained anchor checkpoint size.");
        var payload = Field(reader, length); End(reader);
        return new Generation(revision, previous, payload);
    }

    internal static Pointer DecodePointer(byte[] input, Guid identity, DnsName origin, ReadOnlySpan<byte> key)
    {
        using var stream = new MemoryStream(Authenticate(input, key), writable: false);
        using var reader = new BinaryReader(stream);
        Scope(reader, "M8P2", identity, origin);
        var value = new Pointer(Revision(reader), Revision(reader), Field(reader, 32), Field(reader, 32));
        End(reader);
        if (value.First > value.Revision || value.Revision - value.First >= FileAnchorCheckpointStore.MaximumGenerations
            || (value.First == 1 && value.Previous.AsSpan().IndexOfAnyExcept((byte)0) >= 0))
        {
            throw new InvalidDataException("Invalid authenticated retention boundary.");
        }
        return value;
    }

    private static byte[] Authenticate(byte[] input, ReadOnlySpan<byte> key)
    {
        if (input.Length is < 55 or > AnchorStoreEnvelope.MaximumBytes
            || !CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(key, input.AsSpan(0, input.Length - 32)), input.AsSpan(input.Length - 32)))
        {
            throw new InvalidDataException("Retained anchor storage authentication failed.");
        }
        return input.AsSpan(0, input.Length - 32).ToArray();
    }

    private static void Scope(BinaryReader reader, string purpose, Guid identity, DnsName origin)
    {
        if (!Field(reader, 4).AsSpan().SequenceEqual(System.Text.Encoding.ASCII.GetBytes(purpose))
            || new Guid(Field(reader, 16)) != identity
            || !Field(reader, reader.ReadUInt16()).AsSpan().SequenceEqual(origin.ToWire()))
        {
            throw new InvalidDataException("Retained anchor scope or purpose mismatch.");
        }
    }

    private static long Revision(BinaryReader reader)
    {
        var value = reader.ReadInt64();
        if (value < 1) throw new InvalidDataException("Invalid retained anchor revision.");
        return value;
    }

    private static byte[] Field(BinaryReader reader, int length)
    {
        if (length < 1 || length > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new InvalidDataException("Truncated retained anchor field.");
        return reader.ReadBytes(length);
    }

    private static void End(BinaryReader reader)
    {
        if (reader.BaseStream.Position != reader.BaseStream.Length)
            throw new InvalidDataException("Trailing retained anchor data.");
    }
}
