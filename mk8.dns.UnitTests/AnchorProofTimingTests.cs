using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorProofTimingTests
{
    [Theory]
    [InlineData(1u, 1u, 3600d, 3600d)]
    [InlineData(7200u, 9000u, 3600d, 3600d)]
    [InlineData(20_001u, 80_000u, 10_000.5, 3600d)]
    [InlineData(100_000u, 200_000u, 50_000d, 10_000d)]
    [InlineData(500_000u, 80_000u, 40_000d, 8000d)]
    [InlineData(4_000_000u, 4_000_000u, 1_296_000d, 86_400d)]
    [InlineData(2147483647u, 2_000_000_000u, 1_296_000d, 86_400d)]
    public void SuccessfulProofSuppliesAuthenticatedOriginalTtlAndBoundedIntervalCandidates(uint ttl, uint expiry, double query, double retry)
    {
        using var f = new TrustAnchorFixture(); var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A, ttl)];
        Assert.True(tracker.TryCapture(records, [f.Sign(records, f.A, expiration: 100 + expiry)], out var observation));
        Assert.True(tracker.TryApplyWithTiming(observation, out var timing));
        Assert.Equal(f.Origin, timing.Origin); Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(100), timing.CapturedUtc);
        Assert.Equal(ttl, timing.OriginalTtl); Assert.Equal(TimeSpan.FromSeconds(expiry), timing.SignatureExpirationInterval);
        Assert.Equal(TimeSpan.FromSeconds(query), timing.QueryInterval); Assert.Equal(TimeSpan.FromSeconds(retry), timing.RetryInterval);
        Assert.False(tracker.TryApplyWithTiming(observation, out var replay)); Assert.Null(replay);
    }

    [Fact]
    public void UnrelatedOrCorruptedShortSignatureCannotSupplyTimingAndKnownSponsorsUseConservativeMinimums()
    {
        using var f = new TrustAnchorFixture(); var tracker = f.Tracker(f.A, f.B);
        DnsRecord[] records = [f.Key(f.A, 100_000), f.Key(f.B, 100_000), f.Key(f.C, 100_000)];
        var first = f.Sign(records, f.A, originalTtl: 20_000, expiration: 30_100);
        var second = f.Sign(records, f.B, originalTtl: 50_000, expiration: 10_100);
        var foreign = f.Sign(records, f.C, originalTtl: 1, expiration: 101);
        var data = f.Sign(records, f.A, originalTtl: 1, expiration: 101).GetData(); data[^1] ^= 1;
        var corrupt = new DnsRecord(f.Origin, 46, 100_000, data);
        Assert.True(tracker.TryCapture(records, [foreign, corrupt, first, second], out var observation));
        Assert.True(tracker.TryApplyWithTiming(observation, out var timing));
        Assert.Equal(20_000u, timing.OriginalTtl); Assert.Equal(TimeSpan.FromSeconds(10_000), timing.SignatureExpirationInterval);
        Assert.Equal(TimeSpan.FromSeconds(5000), timing.QueryInterval); Assert.Equal(TimeSpan.FromHours(1), timing.RetryInterval);
        Assert.Equal(TimeSpan.FromDays(30), TrustAnchorFixture.Status(tracker, records[2]).AddHoldDownRemaining);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InvalidForeignOrConsumedObservationReturnsNoTiming(bool foreign)
    {
        using var f = new TrustAnchorFixture(); var tracker = f.Tracker(f.A); var other = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A)]; var bytes = f.Sign(records, f.A).GetData(); if (!foreign) bytes[^1] ^= 1;
        Assert.True(tracker.TryCapture(records, [new DnsRecord(f.Origin, 46, 3600, bytes)], out var observation));
        Assert.False((foreign ? other : tracker).TryApplyWithTiming(observation, out var timing)); Assert.Null(timing);
    }

    [Fact]
    public void LiveSelfRevocationAloneExportsHistoricalTimingWithoutRetainingTrust()
    {
        using var f = new TrustAnchorFixture(); var tracker = f.Tracker(f.A);
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A, 10_000)); DnsRecord[] records = [revoked];
        Assert.True(tracker.TryCapture(records, [f.Sign(records, f.A, revoked, expiration: 20_100)], out var observation));
        Assert.True(tracker.TryApplyWithTiming(observation, out var timing));
        Assert.Equal(10_000u, timing.OriginalTtl); Assert.Empty(tracker.GetTrustAnchors());
        Assert.Equal(DnssecAnchorState.Revoked, Assert.Single(tracker.GetStatus()).State);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProviderCrossingReceivedLifetimeCannotPublishTiming(bool wallOnly)
    {
        using var f = new TrustAnchorFixture();
        var verifier = new DnssecChainFixture.CountingVerifier
        {
            AfterVerify = () =>
        {
            if (wallOnly) f.Clock.SetWall(3700); else f.Clock.SetMonotonic(3600);
        },
        };
        var tracker = new DnssecTrustAnchorTracker(f.Origin, [f.Key(f.A)], verifier, f.Clock);
        DnsRecord[] records = [f.Key(f.A)];
        Assert.True(tracker.TryCapture(records, [f.Sign(records, f.A)], out var observation));
        Assert.False(tracker.TryApplyWithTiming(observation, out var timing)); Assert.Null(timing);
        Assert.Equal(1, verifier.Calls); Assert.Single(tracker.GetTrustAnchors());
    }

    [Fact]
    public void ExpiredSponsorDoesNotOverrideLiveSelfRevocationTiming()
    {
        using var f = new TrustAnchorFixture();
        var verifier = new DnssecChainFixture.CountingVerifier { AfterVerify = () => f.Clock.SetWall(1100) };
        var tracker = new DnssecTrustAnchorTracker(f.Origin, [f.Key(f.A), f.Key(f.B)], verifier, f.Clock);
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A, 30_000)); DnsRecord[] records = [revoked, f.Key(f.B, 30_000)];
        var self = f.Sign(records, f.A, revoked, originalTtl: 20_000, expiration: 20_100);
        var stale = f.Sign(records, f.B, originalTtl: 1, expiration: 150);
        Assert.True(tracker.TryCapture(records, [self, stale], out var observation));
        Assert.True(tracker.TryApplyWithTiming(observation, out var timing));
        Assert.Equal(20_000u, timing.OriginalTtl); Assert.Equal(TimeSpan.FromSeconds(20_000), timing.SignatureExpirationInterval);
        Assert.Single(tracker.GetTrustAnchors()); Assert.Equal(2, verifier.Calls);
    }

    [Fact]
    public void SerialWrapRemainingSignatureIntervalIsComputedWithinTheAdmittedWindow()
    {
        using var f = new TrustAnchorFixture(); f.Clock.SetWall(uint.MaxValue - 100L);
        var tracker = f.Tracker(f.A); DnsRecord[] records = [f.Key(f.A, 100_000)];
        Assert.True(tracker.TryCapture(records, [f.Sign(records, f.A, expiration: 899)], out var observation));
        Assert.True(tracker.TryApplyWithTiming(observation, out var timing));
        Assert.Equal(TimeSpan.FromSeconds(1000), timing.SignatureExpirationInterval); Assert.Equal(TimeSpan.FromHours(1), timing.QueryInterval);
    }
}
