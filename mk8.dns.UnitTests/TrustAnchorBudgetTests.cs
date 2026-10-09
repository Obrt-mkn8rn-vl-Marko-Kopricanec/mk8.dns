using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustAnchorBudgetTests
{
    [Fact]
    public void SharedBudgetStopsAt128ActualAttemptsWithoutTrustMutation()
    {
        using var f = new TrustAnchorFixture();
        var source = f.Key(f.A).GetData();
        var tag = DnssecKeys.KeyTag(f.Key(f.A));
        var keys = new List<DnsRecord>();
        for (var index = 0; index < 9; index++)
        {
            var value = source.ToArray();
            value[4] += (byte)index;
            value[6] -= (byte)index;
            var key = new DnsRecord(f.Origin, 48, 3600, value);
            Assert.Equal(tag, DnssecKeys.KeyTag(key));
            keys.Add(key);
        }
        var signatures = Enumerable.Range(0, 16).Select(index =>
        {
            var data = f.Sign(keys.ToArray(), f.A).GetData();
            data[^1] ^= (byte)(index + 1);
            return new DnsRecord(f.Origin, 46, 3600, data);
        }).ToArray();
        var provider = new RefusingVerifier();
        var tracker = new DnssecTrustAnchorTracker(f.Origin, keys, provider, f.Clock);
        Assert.True(tracker.TryCapture(keys, signatures, out var observation));
        Assert.False(tracker.TryApply(observation));
        Assert.Equal(128, provider.Calls);
        Assert.Equal(9, tracker.GetTrustAnchors().Count);
    }

    [Fact]
    public void TrackedTombstonesAndPendingEntriesCannotExceedBoundOrEvictTrust()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        var records = new List<DnsRecord> { f.Key(f.A) };
        for (var index = 1; index < 64; index++)
        {
            var data = f.Key(f.B).GetData();
            BinaryPrimitives.WriteUInt16BigEndian(data, (ushort)(257 | index << 9));
            records.Add(new DnsRecord(f.Origin, 48, 3600, data));
        }
        Assert.True(TrustAnchorFixture.Apply(tracker, records.ToArray(), f.Sign(records.ToArray(), f.A)));
        Assert.Equal(64, tracker.GetStatus().Count);
        var revoked = TrustAnchorFixture.Revoke(records[0]);
        records[0] = revoked;
        Assert.True(TrustAnchorFixture.Apply(tracker, records.ToArray(), f.Sign(records.ToArray(), f.A, revoked)));
        Assert.Empty(tracker.GetTrustAnchors());
        Assert.Single(tracker.GetStatus());
        Assert.Equal(DnssecAnchorState.Revoked, tracker.GetStatus()[0].State);
        Assert.False(TrustAnchorFixture.Apply(tracker, [f.Key(f.C)], f.Sign([f.Key(f.C)], f.C)));
        Assert.Single(tracker.GetStatus());
    }

    [Fact]
    public void ContradictoryNormalAndRevokedFormsAndExcessInputAreRejected()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] both = [f.Key(f.A), TrustAnchorFixture.Revoke(f.Key(f.A))];
        Assert.False(tracker.TryCapture(both, [f.Sign(both, f.A)], out _));
        Assert.False(tracker.TryCapture(Enumerable.Repeat(f.Key(f.A), 65).ToArray(), [f.Sign([f.Key(f.A)], f.A)], out _));
        Assert.False(tracker.TryCapture([f.Key(f.A)], Enumerable.Repeat(f.Sign([f.Key(f.A)], f.A), 17).ToArray(), out _));
        Assert.Single(tracker.GetTrustAnchors());
    }

    [Fact]
    public void NewCaptureRetiresOldOwnedMaterialEvenWhenNewInputIsInvalid()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(tracker.TryCapture(records, [f.Sign(records, f.A)], out var first));
        Assert.False(tracker.TryCapture([], [], out _));
        Assert.False(tracker.TryApply(first));
        Assert.Single(tracker.GetStatus());
    }

    [Fact]
    public void FullTombstoneTableDoesNotEvictToAdmitNewKey()
    {
        using var f = new TrustAnchorFixture();
        var keys = new List<DnsRecord> { f.Key(f.A) };
        for (var index = 1; index < 64; index++)
        {
            var value = f.Key(f.B).GetData();
            BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)(257 | index << 9));
            keys.Add(new DnsRecord(f.Origin, 48, 3600, value));
        }
        var tracker = new DnssecTrustAnchorTracker(f.Origin, keys, DnssecFixture.Verifier, f.Clock);
        for (var index = 1; index < keys.Count; index++)
        {
            var revoked = TrustAnchorFixture.Revoke(keys[index]);
            DnsRecord[] records = [keys[0], revoked];
            Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.B, revoked), f.Sign(records, f.A)));
        }
        Assert.Equal(64, tracker.GetStatus().Count);
        Assert.Equal(63, tracker.GetStatus().Count(s => s.State == DnssecAnchorState.Revoked));
        DnsRecord[] replacement = [keys[0], f.Key(f.C)];
        Assert.True(TrustAnchorFixture.Apply(tracker, replacement, f.Sign(replacement, f.A)));
        Assert.Equal(64, tracker.GetStatus().Count);
        Assert.Single(tracker.GetTrustAnchors());
        Assert.DoesNotContain(tracker.GetStatus(), s => s.Key.GetData().SequenceEqual(replacement[1].GetData()));
    }

    private sealed class RefusingVerifier : IDnssecSignatureVerifier
    {
        internal int Calls { get; private set; }
        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        {
            Calls++;
            return false;
        }
    }
}
