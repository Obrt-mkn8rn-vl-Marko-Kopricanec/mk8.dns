using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorStorageAdmissionTests
{
    [Theory]
    [InlineData("magic")]
    [InlineData("identity")]
    [InlineData("origin")]
    [InlineData("zero-revision")]
    [InlineData("other-revision")]
    [InlineData("overflow-revision")]
    [InlineData("previous")]
    [InlineData("empty-payload")]
    [InlineData("oversize-payload")]
    [InlineData("trailing")]
    [InlineData("truncated")]
    [InlineData("name-length")]
    [InlineData("checkpoint-checksum")]
    public void AuthenticatedButMalformedGenerationCannotSupplyTrust(string mutation)
    {
        using var f = new AnchorStorageFixture(); using (f.Create()) { }
        var original = File.ReadAllBytes(f.Generation(1));
        var changed = f.Seal(Mutate(original.AsSpan(0, original.Length - 32).ToArray(), mutation, f.Keys.Origin.ToWire().Length));
        AnchorStorageFixture.Write(f.Generation(1), changed);
        var pointer = File.ReadAllBytes(f.Head); var body = pointer.AsSpan(0, pointer.Length - 32).ToArray();
        SHA256.HashData(changed).CopyTo(body, 22 + f.Keys.Origin.ToWire().Length + 8);
        AnchorStorageFixture.Write(f.Head, f.Seal(body));
        var before = f.Image();
        if (string.Equals(mutation, "checkpoint-checksum", StringComparison.Ordinal))
            Assert.Throws<FormatException>(() => { using var ignored = f.Open(); });
        else Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(); });
        Assert.Equal(before, f.Image());
    }

    [Theory]
    [InlineData("active.bin")]
    [InlineData(".writer.lock")]
    [InlineData("0000000000000001.anchor")]
    public void EveryAuthenticatedFileRejectsSelectedByteDamage(string entry)
    {
        using var f = new AnchorStorageFixture(); using (f.Create()) { }
        var path = Path.Combine(f.Root, entry); var original = File.ReadAllBytes(path);
        for (var index = 0; index < original.Length; index++)
        {
            var changed = (byte[])original.Clone(); changed[index] ^= 1; AnchorStorageFixture.Write(path, changed);
            Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(); });
        }
        AnchorStorageFixture.Write(path, original); using var recovered = f.Open(); Assert.Equal(1, recovered.Revision);
    }

    [Theory]
    [InlineData("marker")]
    [InlineData("generation")]
    public void AuthenticatedPurposeCannotBeReplayedAsActivePointer(string source)
    {
        using var f = new AnchorStorageFixture(); using (f.Create()) { }
        AnchorStorageFixture.Write(f.Head, File.ReadAllBytes(string.Equals(source, "marker", StringComparison.Ordinal) ? f.Marker : f.Generation(1)));
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(); });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void InvalidKeyLengthCannotCreateStorage(int length)
    {
        using var f = new AnchorStorageFixture();
        Assert.Throws<ArgumentException>(() =>
        { using var ignored = FileAnchorCheckpointStore.Create(f.Root, f.Identity, f.Keys.Tracker(f.Keys.A), new byte[length]); });
        Assert.False(Directory.Exists(f.Root));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(257)]
    public void RecoveryRequiresExplicitUsableRevisionFloor(long floor)
    {
        using var f = new AnchorStorageFixture();
        Assert.Throws<ArgumentOutOfRangeException>(() => { using var ignored = f.Open(floor); });
        Assert.False(Directory.Exists(f.Root));
    }

    private static byte[] Mutate(byte[] body, string kind, int nameLength)
    {
        var revision = 22 + nameLength; var payloadLength = revision + 8 + 32;
        switch (kind)
        {
            case "magic": body[0] ^= 1; break;
            case "identity": body[4] ^= 1; break;
            case "origin": body[23] = (byte)'E'; break;
            case "zero-revision": BinaryPrimitives.WriteInt64LittleEndian(body.AsSpan(revision), 0); break;
            case "other-revision": BinaryPrimitives.WriteInt64LittleEndian(body.AsSpan(revision), 2); break;
            case "overflow-revision": BinaryPrimitives.WriteInt64LittleEndian(body.AsSpan(revision), 257); break;
            case "previous": body[revision + 8] ^= 1; break;
            case "empty-payload": BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(payloadLength), 0); break;
            case "oversize-payload": BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(payloadLength), 1_048_577); break;
            case "trailing": return [.. body, 0];
            case "truncated": return body.AsSpan(0, revision + 1).ToArray();
            case "name-length": BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(20), 0); break;
            case "checkpoint-checksum": body[^1] ^= 1; break;
            default: throw new ArgumentException("Unknown malformed envelope.", nameof(kind));
        }
        return body;
    }
}
