using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorCheckpointRoundTripTests
{
    [Fact]
    public void CanonicalCheckpointDoesNotDependOnBootstrapOrderAndOwnsBytes()
    {
        using var f = new TrustAnchorFixture();
        var forward = f.Tracker(f.A, f.B).CreateCheckpoint();
        Assert.Equal(forward, f.Tracker(f.B, f.A).CreateCheckpoint());
        var copy = forward.ToArray();
        var restored = AnchorCheckpointFixture.Restore(f, forward);
        forward.AsSpan().Clear();
        Assert.Equal(copy, restored.CreateCheckpoint());
        var returned = restored.CreateCheckpoint(); returned.AsSpan().Clear();
        Assert.Equal(copy, restored.CreateCheckpoint());
        Assert.All(restored.GetTrustAnchors(), anchor => Assert.Equal(0u, anchor.Record.Ttl));
    }

    [Fact]
    public void PendingMissingAndRevokedStatesSurviveTogether()
    {
        using var f = new TrustAnchorFixture();
        var tracker = AnchorCheckpointFixture.Pending(f, bothSponsors: true);
        f.Clock.Advance(10);
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A));
        DnsRecord[] records = [revoked, f.Key(f.C)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, revoked), f.Sign(records, f.B)));
        var restored = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        Assert.Equal(DnssecAnchorState.Revoked, TrustAnchorFixture.Status(restored, f.Key(f.A)).State);
        Assert.Equal(DnssecAnchorState.Missing, TrustAnchorFixture.Status(restored, f.Key(f.B)).State);
        Assert.Equal(DnssecAnchorState.AddPending, TrustAnchorFixture.Status(restored, f.Key(f.C)).State);
        Assert.Single(restored.GetTrustAnchors());
        Assert.Equal(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(10), TrustAnchorFixture.Status(restored, f.Key(f.C)).AddHoldDownRemaining);
    }

    [Fact]
    public void SoleRevokedTrustPointRestoresWithoutBootstrapOrReplacement()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A));
        Assert.True(TrustAnchorFixture.Apply(tracker, [revoked], f.Sign([revoked], f.A, revoked)));
        var restored = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        Assert.Empty(restored.GetTrustAnchors());
        Assert.Equal(DnssecAnchorState.Revoked, Assert.Single(restored.GetStatus()).State);
        DnsRecord[] ordinary = [f.Key(f.A), f.Key(f.B)];
        Assert.False(TrustAnchorFixture.Apply(restored, ordinary, f.Sign(ordinary, f.A)));
        Assert.Single(restored.GetStatus());
    }

    [Theory]
    [InlineData(8)]
    [InlineData(13)]
    [InlineData(14)]
    public void SupportedKeyFormatsRoundTripWithoutProviderWork(int algorithm)
    {
        using var f = new TrustAnchorFixture();
        using var rsa = new RsaDnssecFixture();
        using var p384 = new P384DnssecFixture();
        var data = algorithm switch
        {
            8 => rsa.Key.GetData(),
            14 => p384.Key.GetData(),
            _ => f.Key(f.A).GetData(),
        };
        var provider = new DnssecChainFixture.CountingVerifier();
        var tracker = new DnssecTrustAnchorTracker(f.Origin, [new DnsRecord(f.Origin, 48, 9, data)], provider, f.Clock);
        var restored = DnssecTrustAnchorTracker.RestoreCheckpoint(f.Origin, tracker.CreateCheckpoint(), provider, f.Clock);
        Assert.Equal(data, Assert.Single(restored.GetTrustAnchors()).Record.GetData());
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public void FullTableCannotLoseTombstonesOrAdmitThroughRestart()
    {
        using var f = new TrustAnchorFixture();
        var keys = new List<DnsRecord> { f.Key(f.A) };
        for (var index = 1; index < 64; index++)
        {
            var data = f.Key(f.B).GetData(); BinaryPrimitives.WriteUInt16BigEndian(data, (ushort)(257 | index << 9));
            keys.Add(new DnsRecord(f.Origin, 48, 3600, data));
        }
        var tracker = new DnssecTrustAnchorTracker(f.Origin, keys, DnssecFixture.Verifier, f.Clock);
        for (var index = 1; index < keys.Count; index++)
        {
            var revoked = TrustAnchorFixture.Revoke(keys[index]);
            DnsRecord[] records = [keys[0], revoked];
            Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.B, revoked), f.Sign(records, f.A)));
        }
        var restored = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        DnsRecord[] replacement = [keys[0], f.Key(f.C)];
        Assert.True(TrustAnchorFixture.Apply(restored, replacement, f.Sign(replacement, f.A)));
        Assert.Equal(64, restored.GetStatus().Count);
        Assert.Equal(63, restored.GetStatus().Count(status => status.State == DnssecAnchorState.Revoked));
        Assert.Single(restored.GetTrustAnchors());
    }
}
