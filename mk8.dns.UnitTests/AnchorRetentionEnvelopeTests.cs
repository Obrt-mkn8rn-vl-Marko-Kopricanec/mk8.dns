using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRetentionEnvelopeTests
{
    [Theory]
    [InlineData("zero-first")]
    [InlineData("after-head")]
    [InlineData("wide-window")]
    [InlineData("genesis-previous")]
    [InlineData("trailing")]
    [InlineData("purpose")]
    [InlineData("identity")]
    [InlineData("signature")]
    public void MalformedOrForeignPointerCannotAuthorizeRecovery(string mutation)
    {
        using var f = new AnchorRetentionFixture();
        using (f.Create()) { }
        var raw = File.ReadAllBytes(f.Storage.Head); var body = raw.AsSpan(0, raw.Length - 32).ToArray();
        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(20)); var revisionOffset = 22 + nameLength;
        switch (mutation)
        {
            case "zero-first": BinaryPrimitives.WriteInt64LittleEndian(body.AsSpan(revisionOffset + 8), 0); break;
            case "after-head": BinaryPrimitives.WriteInt64LittleEndian(body.AsSpan(revisionOffset + 8), 2); break;
            case "wide-window": BinaryPrimitives.WriteInt64LittleEndian(body.AsSpan(revisionOffset), 257); break;
            case "genesis-previous": body[revisionOffset + 16] = 1; break;
            case "trailing": body = [.. body, 1]; break;
            case "purpose": body[3] = (byte)'1'; break;
            case "identity": body[4] ^= 1; break;
            case "signature": raw[^1] ^= 1; break;
            default: throw new InvalidOperationException("Unknown controlled mutation.");
        }
        AnchorStorageFixture.Write(f.Storage.Head, string.Equals(mutation, "signature", StringComparison.Ordinal) ? raw : f.Storage.Seal(body));
        var before = f.Storage.Image();
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(1); });
        Assert.Equal(before, f.Storage.Image());
    }

    [Fact]
    public void CompleteIndependentPointerBytesBindScopeBoundaryAndHeadDigest()
    {
        using var f = new AnchorRetentionFixture(); using var store = f.Create();
        AnchorRetentionFixture.Advance(store, 4);
        var previous = AnchorRetentionFixture.Digest(f.Storage.Generation(2));
        var digest = AnchorRetentionFixture.Digest(f.Storage.Generation(4));
        Assert.Equal(3, store.Retain(4, 4, 2));
        Assert.Equal(f.Pointer(4, 3, previous, digest), File.ReadAllBytes(f.Storage.Head));
    }

    [Fact]
    public void CorruptedAuthenticatedRetiredPrefixIsNotSilentlyDiscarded()
    {
        using var f = new AnchorRetentionFixture(); var armed = false;
        using (var store = f.Create(stage =>
        {
            if (armed && stage == AnchorStoreWriteStage.RetentionDirectory) throw new IOException("Controlled post-pointer stop.");
        }))
        {
            AnchorRetentionFixture.Advance(store, 4); armed = true;
            Assert.Throws<IOException>(() => store.Retain(4, 4, 2));
        }
        var raw = File.ReadAllBytes(f.Storage.Generation(1)); raw[^1] ^= 1; AnchorStorageFixture.Write(f.Storage.Generation(1), raw);
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(4); });
    }

    [Fact]
    public void WrongCompleteCheckpointChecksumRefusesBeforeRecoveredTrackerPublication()
    {
        using var f = new AnchorRetentionFixture(); byte[] payload;
        using (var store = f.Create()) payload = ((Mk8.Dns.Engine.Dnssec.IDnssecAnchorCheckpointStore)store).ReadCommitted().GetCheckpoint();
        payload[^1] ^= 1;
        var raw = f.Generation(1, new byte[32], payload);
        AnchorStorageFixture.Write(f.Storage.Generation(1), raw);
        AnchorStorageFixture.Write(f.Storage.Head, f.Pointer(1, 1, new byte[32], SHA256.HashData(raw)));
        Assert.Throws<FormatException>(() => { using var ignored = f.Open(1); });
    }
}
