using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecRenewalTests
{
    [Theory]
    [InlineData(900, false)]
    [InlineData(1000, false)]
    [InlineData(1059, false)]
    [InlineData(3699, false)]
    [InlineData(3700, true)]
    [InlineData(4600, true)]
    [InlineData(4601, true)]
    public async Task RenewalUsesTheVerifiedWindowAndDoesNotRunBeforeTheMargin(uint seconds, bool expected)
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        var original = fixture.Current!;
        fixture.Time.Seconds = seconds;
        Assert.Equal(expected, await fixture.Application().ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.True(fixture.Disposed);
        Assert.Equal(expected ? 1 : 0, fixture.Commits);
        if (expected)
        {
            Assert.Equal(2L, fixture.Current!.Revision);
            Assert.Equal(SoaSerial.Next(original.Serial), fixture.Current.Serial);
            Assert.Equal("mk8.dns:signature-renewal", fixture.Operation!.Actor);
            Assert.False(fixture.Operation.Activated);
            Assert.Equal(original.Origin, fixture.Current.Origin);
            Assert.Equal(fixture.Codec.DecodeContents(original).GetSecurityRecords().Single(record => record.Type == 48).GetData(),
                fixture.Codec.DecodeContents(fixture.Current).GetSecurityRecords().Single(record => record.Type == 48).GetData());
            _ = SignedZoneAdmission.Verify(fixture.Codec.DecodeContents(fixture.Current), seconds, DnssecFixture.Verifier);
        }
        else
            Assert.Equal(original.ContentHash, fixture.Current!.ContentHash);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(59)]
    [InlineData(3541)]
    [InlineData(uint.MaxValue)]
    public void InvalidMarginsCannotCreateAnAutomaticSigningPolicy(uint margin)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecRenewalScope(Guid.NewGuid(), DnssecFixture.Origin, 3600, margin));

    [Theory]
    [InlineData(3599)]
    [InlineData(2_592_001)]
    public void InvalidLifetimeIsRejected(uint lifetime)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecRenewalScope(Guid.NewGuid(), DnssecFixture.Origin, lifetime));

    [Fact]
    public void MissingIdentityAndDuplicateOrUnboundedScopesAreRejected()
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        Assert.Throws<ArgumentException>(() => new DnssecRenewalScope(Guid.Empty, DnssecFixture.Origin, 3600));
        var scope = new DnssecRenewalScope(fixture.Zone, DnssecFixture.Origin, 3600);
        Assert.Equal(900U, scope.RenewBeforeSeconds);
        foreach (var scopes in new[] { Array.Empty<DnssecRenewalScope>(), new[] { scope, scope }, Enumerable.Repeat(scope, 65).ToArray() })
            Assert.Throws<ArgumentException>(() => new ZoneResigningApplication(fixture, fixture.Codec, DnssecFixture.Verifier, fixture.Time, RenewalFixture.Node, scopes));
        Assert.Throws<ArgumentException>(() => new ZoneResigningApplication(fixture, fixture.Codec, DnssecFixture.Verifier, fixture.Time, RenewalFixture.Node,
            [scope, new DnssecRenewalScope(Guid.NewGuid(), scope.Origin, 3600)]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AQueuedGenerationOrAnyEarlierPendingPublicationPreventsRenewal(bool older)
    {
        using var key = DnssecFixture.Key();
        var counter = new DnssecFixture.CountingKey(key);
        using var fixture = new RenewalFixture(counter);
        fixture.Initialize();
        fixture.Time.Seconds = 5000;
        if (older)
            fixture.Pending = true;
        else
            fixture.Operation = fixture.Operation! with { Activated = false };
        var calls = counter.Calls;
        Assert.False(await fixture.Application().ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(calls, counter.Calls);
        Assert.Equal(0, fixture.Commits);
        Assert.Null(fixture.Staged);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task MissingOrDiscrepantCommittedPublicationEvidenceFailsWithoutSigning(int mismatch)
    {
        using var key = DnssecFixture.Key();
        var counter = new DnssecFixture.CountingKey(key);
        using var fixture = new RenewalFixture(counter);
        fixture.Initialize();
        fixture.Operation = mismatch switch
        {
            0 => null,
            1 => fixture.Operation! with { TenantId = Guid.NewGuid() },
            2 => fixture.Operation! with { TargetNode = "other" },
            3 => fixture.Operation! with { Snapshot = new ZoneSnapshot(fixture.Zone, DnssecFixture.Origin, 2, fixture.Current!.Serial, fixture.Current.GetPayload()) },
            _ => fixture.Operation! with { Snapshot = fixture.Codec.Compile(fixture.Zone, 1, AuthorityFixture.Zone(DnssecFixture.A(last: 99))) },
        };
        var calls = counter.Calls;
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application().ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(calls, counter.Calls);
        Assert.Equal(0, fixture.Commits);
        Assert.True(fixture.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnAbsentOrUnsignedZoneIsNeverBootstrappedByTheJob(bool hasUnsignedIntent)
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        if (hasUnsignedIntent)
        {
            fixture.Current = new ZoneBundleAdapter().Compile(fixture.Zone, 1, AuthorityFixture.Zone(DnssecFixture.A()));
            fixture.Operation = fixture.Operation! with { Snapshot = fixture.Current };
        }
        else
            fixture.Ownership = [];
        Assert.False(await fixture.Application().ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(0, fixture.Commits);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ScopedOwnershipMismatchOrLostCurrentStateFailsClosed(bool missing)
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        if (missing)
            fixture.Current = null;
        else
            fixture.Ownership = [new ZoneOwnership(fixture.Tenant, fixture.Zone, DnsName.Parse("other."))];
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application().ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, fixture.Commits);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task KeyReplacementAndUnsignedDowngradeCannotBeIntroducedByAutomaticMaintenance(bool downgrade)
    {
        using var key = DnssecFixture.Key();
        using var different = Mk8.Dns.Infrastructure.Cryptography.EcdsaP256DnssecSigningKey.Create();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        var codec = downgrade ? new ZoneBundleAdapter() : SignedAuthorityFixture.Codec(different, fixture.Time);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application(codec).ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, fixture.Commits);
        Assert.Null(fixture.Staged);
    }

    [Fact]
    public async Task AlteredIntentDespiteValidNewSignaturesCannotCommit()
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        var codec = new RenewalFixture.AlteredCodec(fixture.Codec, snapshot =>
        {
            var zone = fixture.Codec.Decode(snapshot);
            var altered = new AuthoritativeZone(zone.Origin, zone.GetAllRecords().Select(record => record.Type == 1 ? DnssecFixture.A(last: 99) : record));
            return fixture.Codec.Compile(snapshot.ZoneId, snapshot.Revision, altered);
        });
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application(codec).ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, fixture.Commits);
    }

    [Fact]
    public async Task InvalidRetainedMathIsRejectedAndHashChangesInvalidateTheVerifiedCache()
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        fixture.Time.Seconds = 2000;
        var verifier = new RenewalFixture.CountingVerifier(DnssecFixture.Verifier);
        var application = fixture.Application(verifier: verifier);
        Assert.False(await application.ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        var calls = verifier.Calls;
        Assert.True(calls > 0);
        Assert.False(await application.ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(calls, verifier.Calls);
        var contents = fixture.Codec.DecodeContents(fixture.Current!);
        var signature = contents.GetSecurityRecords().First(record => record.Type == 46);
        var data = signature.GetData();
        data[^1] ^= 1;
        var corrupt = SignedAuthorityFixture.Replace(contents, signature, new DnsRecord(signature.GetOwnerWire(), 46, signature.Ttl, data));
        fixture.Current = SignedZoneBundleCodec.Compile(fixture.Zone, 1, corrupt);
        fixture.Operation = fixture.Operation! with { Snapshot = fixture.Current };
        _ = await Assert.ThrowsAsync<FormatException>(() => application.ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.True(verifier.Calls > calls);
        Assert.Equal(0, fixture.Commits);
    }

    [Fact]
    public async Task CancellationAfterPrivateSigningCannotAppendAndReleasesTheTransaction()
    {
        using var key = DnssecFixture.Key();
        using var cancellation = new CancellationTokenSource();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        var counter = new DnssecFixture.CountingKey(key) { AfterSign = cancellation.Cancel };
        var codec = SignedAuthorityFixture.Codec(counter, fixture.Time);
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Application(codec).ResignAsync(fixture.Zone, cancellation.Token).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, fixture.Commits);
        Assert.Null(fixture.Staged);
        Assert.True(fixture.Disposed);
    }

    [Fact]
    public async Task CommitFailureRetainsCurrentStateAndAReattemptUsesTheSameInput()
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        var original = fixture.Current!;
        fixture.CommitFails = true;
        var application = fixture.Application();
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => application.ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(original.ContentHash, fixture.Current!.ContentHash);
        Assert.True(fixture.Disposed);
        fixture.CommitFails = false;
        Assert.True(await application.ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(2L, fixture.Current.Revision);
        Assert.Equal(1, fixture.Commits);
        Assert.False(await application.ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        fixture.Operation = fixture.Operation! with { Activated = true };
        Assert.False(await application.ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task SignatureTimeAndSoaSerialWrapAreHandledWithoutLosingFreshness()
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key, uint.MaxValue - 1000);
        fixture.Initialize();
        var source = fixture.Codec.Decode(fixture.Current!);
        var soaData = source.Soa.GetData();
        BinaryPrimitives.WriteUInt32BigEndian(soaData.AsSpan(soaData.Length - 20), uint.MaxValue);
        var wrappedSource = new AuthoritativeZone(source.Origin, source.GetAllRecords().Select(record => record.Type == 6 ? new DnsRecord(record.GetOwnerWire(), 6, record.Ttl, soaData) : record));
        fixture.Time.Seconds = uint.MaxValue - 1000;
        fixture.Current = fixture.Codec.Compile(fixture.Zone, 1, wrappedSource);
        fixture.Operation = fixture.Operation! with { Snapshot = fixture.Current };
        fixture.Time.Seconds = 2000;
        Assert.True(await fixture.Application().ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(0U, fixture.Current.Serial);
        Assert.Equal(2L, fixture.Current.Revision);
        _ = SignedZoneAdmission.Verify(fixture.Codec.DecodeContents(fixture.Current), 2000, DnssecFixture.Verifier);
    }

    [Theory]
    [InlineData(1059, false)]
    [InlineData(1060, true)]
    public async Task MaximumMarginStillRequiresOneMinuteBetweenGenerations(uint now, bool due)
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        fixture.Time.Seconds = now;
        Assert.Equal(due, await fixture.Application(margin: 3540).ResignAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(due ? 1 : 0, fixture.Commits);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ValidSignedBytesWithWrongSnapshotIdentityCannotBeCommitted(int mismatch)
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        var codec = new RenewalFixture.AlteredCodec(fixture.Codec, snapshot => new ZoneSnapshot(mismatch == 0 ? Guid.NewGuid() : snapshot.ZoneId,
            snapshot.Origin, mismatch == 1 ? snapshot.Revision + 1 : snapshot.Revision, mismatch == 2 ? snapshot.Serial + 1 : snapshot.Serial, snapshot.GetPayload()));
        if (mismatch == 2)
            _ = await Assert.ThrowsAsync<FormatException>(() => fixture.Application(codec).ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        else
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application(codec).ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, fixture.Commits);
        Assert.Null(fixture.Staged);
        Assert.True(fixture.Disposed);
    }

    [Fact]
    public async Task ACompilerThatReusesTheOldExpiryCannotAppendAFreshRevision()
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        var originalTime = new SignedAuthorityFixture.Clock();
        var codec = SignedAuthorityFixture.Codec(key, originalTime);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application(codec).ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, fixture.Commits);
        Assert.Null(fixture.Staged);
    }

    [Fact]
    public async Task DifferentConfiguredLifetimeCannotSilentlyOverrideTheCompilerPolicy()
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        var codec = SignedAuthorityFixture.Codec(key, fixture.Time, 7200);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application(codec).ResignAsync(fixture.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, fixture.Commits);
    }

    [Fact]
    public async Task UnknownScopeDoesNotAcquireAWriterTransaction()
    {
        using var key = DnssecFixture.Key();
        using var fixture = new RenewalFixture(key);
        fixture.Initialize();
        _ = await Assert.ThrowsAsync<ArgumentException>(() => fixture.Application().ResignAsync(Guid.NewGuid(), CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.False(fixture.Disposed);
        Assert.Equal(0, fixture.Commits);
    }
}
