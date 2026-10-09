using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustAnchorAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void InvalidInputsCannotChangeAnchors(int scenario)
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        var signature = f.Sign(records, f.A);
        var data = signature.GetData();
        if (scenario == 0) data[^1] ^= 1;
        if (scenario == 1) data[3] = 0;
        if (scenario == 2) data[0] = 1;
        signature = new DnsRecord(f.Origin, 46, signature.Ttl, data);
        if (scenario == 3) records = [records[0], records[0]];
        if (scenario == 4) records = [records[0].WithOwner(DnsName.Parse("other."))];
        if (scenario == 5) records = [];
        var captured = tracker.TryCapture(records, [signature], out var observation);
        Assert.False(captured && tracker.TryApply(observation!));
        Assert.Single(tracker.GetStatus());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ForeignOrOutOfOrderCapturesAreRejected(bool foreign)
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        var other = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(tracker.TryCapture(records, [f.Sign(records, f.A)], out var first));
        if (foreign) Assert.False(other.TryApply(first));
        else
        {
            DnsRecord[] onlyA = [records[0]];
            Assert.True(TrustAnchorFixture.Apply(tracker, onlyA, f.Sign(onlyA, f.A)));
            Assert.False(tracker.TryApply(first));
        }
        Assert.Single((foreign ? other : tracker).GetStatus());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void ReceivedOrSignatureLifetimeExpiryDuringProviderWorkCannotMutate(int scenario)
    {
        using var f = new TrustAnchorFixture();
        var verifier = new DnssecChainFixture.CountingVerifier { AfterVerify = () => f.Clock.Advance(scenario == 2 ? 1 : 10) };
        var tracker = new DnssecTrustAnchorTracker(f.Origin, [f.Key(f.A)], verifier, f.Clock);
        DnsRecord[] records = [f.Key(f.A, scenario == 0 ? 10U : 3600U), f.Key(f.B, scenario == 0 ? 10U : 3600U)];
        var signature = f.Sign(records, f.A, signatureTtl: scenario == 1 ? 10U : 3600U, expiration: scenario == 2 ? 100U : 1000U);
        Assert.False(TrustAnchorFixture.Apply(tracker, records, signature));
        Assert.Single(tracker.GetStatus());
        Assert.Equal(1, verifier.Calls);
    }

    [Fact]
    public void CaptureOwnsCollectionsAndDoesNotExposeMutableStatusOrAnchorBytes()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        DnsRecord[] signatures = [f.Sign(records, f.A)];
        Assert.True(tracker.TryCapture(records, signatures, out var observation));
        records[1] = f.Key(f.C);
        signatures[0] = f.Sign(records, f.B);
        Assert.True(tracker.TryApply(observation));
        Assert.Equal(DnssecAnchorState.AddPending, TrustAnchorFixture.Status(tracker, f.Key(f.B)).State);
        var status = tracker.GetStatus();
        Assert.Throws<NotSupportedException>(() => ((IList<DnssecAnchorStatus>)status).Clear());
        var bytes = tracker.GetTrustAnchors()[0].Record.GetData();
        bytes[0] ^= 255;
        Assert.Equal(f.Key(f.A).GetData(), tracker.GetTrustAnchors()[0].Record.GetData());
    }

    [Fact]
    public void ProviderExceptionRetiresObservationWithoutPartialTrustMutation()
    {
        using var f = new TrustAnchorFixture();
        var verifier = new ThrowingVerifier();
        var tracker = new DnssecTrustAnchorTracker(f.Origin, [f.Key(f.A)], verifier, f.Clock);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(tracker.TryCapture(records, [f.Sign(records, f.A)], out var observation));
        Assert.Throws<InvalidOperationException>(() => tracker.TryApply(observation));
        Assert.Single(tracker.GetStatus());
        Assert.False(tracker.TryApply(observation));
    }

    [Fact]
    public void ProviderCannotRecaptureOrReenterStateMutation()
    {
        using var f = new TrustAnchorFixture();
        DnssecTrustAnchorTracker? tracker = null;
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        var signature = f.Sign(records, f.A);
        var provider = new DnssecChainFixture.CountingVerifier
        {
            AfterVerify = () => Assert.False(tracker!.TryCapture(records, [signature], out _)),
        };
        tracker = new DnssecTrustAnchorTracker(f.Origin, [records[0]], provider, f.Clock);
        Assert.True(TrustAnchorFixture.Apply(tracker, records, signature));
        Assert.Equal(2, tracker.GetStatus().Count);
        Assert.Single(tracker.GetTrustAnchors());
    }

    [Fact]
    public void HeldObservationCannotPromoteEvenWithLargeReceivedTtl()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] first = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, first, f.Sign(first, f.A)));
        f.Clock.Advance(2_592_000 - 10);
        DnsRecord[] held = [f.Key(f.A, 4_000_000), f.Key(f.B, 4_000_000)];
        var signature = f.Sign(held, f.A, originalTtl: 4_000_000, expiration: 8_000_000);
        Assert.True(tracker.TryCapture(held, [signature], out var observation));
        f.Clock.Advance(20);
        Assert.True(tracker.TryApply(observation));
        Assert.Single(tracker.GetTrustAnchors());
        Assert.True(TrustAnchorFixture.Apply(tracker, held, f.Sign(held, f.A, originalTtl: 4_000_000)));
        Assert.Equal(2, tracker.GetTrustAnchors().Count);
    }

    private sealed class ThrowingVerifier : IDnssecSignatureVerifier
    {
        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
            => throw new InvalidOperationException("Controlled provider failure.");
    }
}
