using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.UnitTests;

internal static class AnchorCheckpointFixture
{
    internal sealed record Saved(byte[] Key, byte State = 1, long Remaining = 0, (byte Index, byte Early)[]? Sponsors = null);
    internal static byte[] Encode(DnsName origin, IReadOnlyList<Saved> entries, long seconds = 100, string magic = "M8A1", bool trailing = false)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(System.Text.Encoding.ASCII.GetBytes(magic));
            var name = origin.ToWire(); writer.Write((ushort)name.Length); writer.Write(name);
            writer.Write(seconds); writer.Write((byte)entries.Count);
            foreach (var entry in entries)
            {
                writer.Write(entry.State); writer.Write((ushort)entry.Key.Length); writer.Write(entry.Key);
                if (entry.State != 0) continue;
                writer.Write(entry.Remaining);
                var sponsors = entry.Sponsors ?? []; writer.Write((byte)sponsors.Length);
                foreach (var sponsor in sponsors) { writer.Write(sponsor.Index); writer.Write(sponsor.Early); }
            }
            if (trailing) writer.Write((byte)0);
        }
        return Seal(stream.ToArray());
    }
    internal static byte[] Seal(byte[] body) => [.. body, .. SHA256.HashData(body)];
    internal static DnssecTrustAnchorTracker Restore(TrustAnchorFixture fixture, byte[] bytes, TimeProvider? time = null)
        => DnssecTrustAnchorTracker.RestoreCheckpoint(fixture.Origin, bytes, DnssecFixture.Verifier, time ?? fixture.Clock);
    internal static DnssecTrustAnchorTracker Pending(TrustAnchorFixture fixture, bool bothSponsors = false)
    {
        var tracker = bothSponsors ? fixture.Tracker(fixture.A, fixture.B) : fixture.Tracker(fixture.A);
        DnsRecord[] records = bothSponsors ? [fixture.Key(fixture.A), fixture.Key(fixture.B), fixture.Key(fixture.C)]
            : [fixture.Key(fixture.A), fixture.Key(fixture.B)];
        var signatures = bothSponsors ? new[] { fixture.Sign(records, fixture.A), fixture.Sign(records, fixture.B) }
            : [fixture.Sign(records, fixture.A)];
        Xunit.Assert.True(TrustAnchorFixture.Apply(tracker, records, signatures));
        return tracker;
    }
}
