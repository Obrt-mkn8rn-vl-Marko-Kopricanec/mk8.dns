using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorCheckpointAdmissionTests
{
    [Theory]
    [InlineData("version")]
    [InlineData("trailing")]
    [InlineData("origin")]
    [InlineData("wildcard")]
    [InlineData("empty")]
    [InlineData("excess")]
    [InlineData("duplicate")]
    [InlineData("order")]
    [InlineData("state")]
    [InlineData("protocol")]
    [InlineData("zsk")]
    [InlineData("revoke")]
    [InlineData("algorithm")]
    [InlineData("width")]
    [InlineData("negative-hold")]
    [InlineData("excess-hold")]
    [InlineData("no-sponsor")]
    [InlineData("self-sponsor")]
    [InlineData("foreign-sponsor")]
    [InlineData("duplicate-sponsor")]
    [InlineData("unordered-sponsor")]
    [InlineData("unknown-flag")]
    [InlineData("pending-sponsor")]
    [InlineData("false-revocation")]
    [InlineData("all-early")]
    [InlineData("invalid-wall")]
    public void StructurallyInvalidTrustedInputCannotCreateRecoveredTracker(string scenario)
    {
        using var f = new TrustAnchorFixture();
        var keys = new[] { f.Key(f.A).GetData(), f.Key(f.B).GetData(), f.Key(f.C).GetData() }
            .OrderBy(Convert.ToHexString, StringComparer.Ordinal).ToArray();
        var entries = keys.Select(key => new AnchorCheckpointFixture.Saved(key)).ToArray();
        var keyData = entries[0].Key;
        var pending = new AnchorCheckpointFixture.Saved(keys[2], 0, TimeSpan.FromDays(30).Ticks, [(0, 0), (1, 0)]);
        var checkpoint = scenario switch
        {
            "version" => AnchorCheckpointFixture.Encode(f.Origin, entries, magic: "M8A2"),
            "trailing" => AnchorCheckpointFixture.Encode(f.Origin, entries, trailing: true),
            "origin" => AnchorCheckpointFixture.Encode(DnsName.Parse("other."), entries),
            "wildcard" => AnchorCheckpointFixture.Encode(DnsName.Parse("*.example."), entries),
            "empty" => AnchorCheckpointFixture.Encode(f.Origin, []),
            "excess" => AnchorCheckpointFixture.Encode(f.Origin, Enumerable.Repeat(entries[0], 65).ToArray()),
            "duplicate" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 1, entries[0])),
            "order" => AnchorCheckpointFixture.Encode(f.Origin, entries.Reverse().ToArray()),
            "state" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 0, entries[0] with { State = 4 })),
            "protocol" => AlterKey(f, entries, 2, 0),
            "zsk" => AlterKey(f, entries, 1, 0),
            "revoke" => AlterKey(f, entries, 1, 129),
            "algorithm" => AlterKey(f, entries, 3, 15),
            "width" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 0, entries[0] with { Key = keyData[..^1] })),
            "negative-hold" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Remaining = -1 })),
            "excess-hold" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Remaining = (long)uint.MaxValue * TimeSpan.TicksPerSecond + 1 })),
            "no-sponsor" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Sponsors = [] })),
            "self-sponsor" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Sponsors = [(2, 0)] })),
            "foreign-sponsor" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Sponsors = [(3, 0)] })),
            "duplicate-sponsor" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Sponsors = [(0, 0), (0, 0)] })),
            "unordered-sponsor" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Sponsors = [(1, 0), (0, 0)] })),
            "unknown-flag" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Sponsors = [(0, 2)] })),
            "pending-sponsor" => AnchorCheckpointFixture.Encode(f.Origin, Replace(Replace(entries, 0,
                new AnchorCheckpointFixture.Saved(keys[0], 0, 1, [(1, 0)])), 2, pending)),
            "false-revocation" => AnchorCheckpointFixture.Encode(f.Origin, Replace(entries, 2, pending with { Sponsors = [(0, 1)] })),
            "all-early" => AnchorCheckpointFixture.Encode(f.Origin, Replace(Replace(entries, 0,
                entries[0] with { State = 3 }), 2, pending with { Sponsors = [(0, 1)] })),
            _ => AnchorCheckpointFixture.Encode(f.Origin, entries, seconds: long.MaxValue),
        };
        Assert.Throws<FormatException>(() => AnchorCheckpointFixture.Restore(f, checkpoint));
    }

    private static AnchorCheckpointFixture.Saved[] Replace(AnchorCheckpointFixture.Saved[] entries, int index, AnchorCheckpointFixture.Saved replacement)
    {
        var copy = entries.ToArray(); copy[index] = replacement; return copy;
    }
    private static byte[] AlterKey(TrustAnchorFixture fixture, AnchorCheckpointFixture.Saved[] entries, int index, byte value)
    {
        var copy = entries[0].Key.ToArray(); copy[index] = value;
        return AnchorCheckpointFixture.Encode(fixture.Origin, Replace(entries, 0, entries[0] with { Key = copy }));
    }

    [Fact]
    public void EveryTruncationAndDamageRefusesWithoutChangingLiveTracker()
    {
        using var f = new TrustAnchorFixture();
        var tracker = AnchorCheckpointFixture.Pending(f);
        var checkpoint = tracker.CreateCheckpoint();
        for (var length = 0; length < checkpoint.Length; length++)
        {
            var truncated = checkpoint[..length];
            Assert.Throws<FormatException>(() => AnchorCheckpointFixture.Restore(f, truncated));
        }
        for (var index = 0; index < checkpoint.Length; index++)
        {
            var damaged = checkpoint.ToArray(); damaged[index] ^= 1;
            Assert.Throws<FormatException>(() => AnchorCheckpointFixture.Restore(f, damaged));
        }
        Assert.Equal(checkpoint, tracker.CreateCheckpoint());
    }

    [Fact]
    public void CorrectChecksumDoesNotAllowTruncatedFieldsOrNoncanonicalNames()
    {
        using var f = new TrustAnchorFixture();
        var checkpoint = f.Tracker(f.A).CreateCheckpoint();
        var body = checkpoint[..^32];
        for (var length = 4; length < body.Length; length++)
            Assert.Throws<FormatException>(() => AnchorCheckpointFixture.Restore(f, AnchorCheckpointFixture.Seal(body[..length])));
        body[7] = (byte)'E';
        Assert.Throws<FormatException>(() => AnchorCheckpointFixture.Restore(f, AnchorCheckpointFixture.Seal(body)));
        body = checkpoint[..^32]; BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(4), 256);
        Assert.Throws<FormatException>(() => AnchorCheckpointFixture.Restore(f, AnchorCheckpointFixture.Seal(body)));
    }

    [Fact]
    public void MaximumInputIsBoundedBeforeCopyAndDependenciesAreExplicit()
    {
        using var f = new TrustAnchorFixture();
        var oversized = new byte[DnssecTrustAnchorTracker.MaximumCheckpointBytes + 1];
        Assert.Throws<FormatException>(() => AnchorCheckpointFixture.Restore(f, oversized));
        Assert.Throws<ArgumentNullException>(() => DnssecTrustAnchorTracker.RestoreCheckpoint(null!, [], DnssecFixture.Verifier));
        Assert.Throws<ArgumentNullException>(() => DnssecTrustAnchorTracker.RestoreCheckpoint(f.Origin, [], null!));
    }
}
