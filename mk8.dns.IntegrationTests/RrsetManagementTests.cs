using System.Security.Cryptography;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Npgsql;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class RrsetManagementTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{

    [Fact]
    public async Task RecordReplacementAndScopedReadPreserveTheRestOfTheZone()
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var patch = fixture.Patch(1, RecordManagementFixture.Change("www.example.", 1, [new byte[] { 192, 0, 2, 99 }], replace: true)) with { Credential = fixture.RecordCredential };
        var result = await fixture.Application.ExecuteAsync(patch, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2L, result.Revision);
        Assert.Equal(2u, result.Serial);
        var read = await fixture.Application.ExecuteAsync(fixture.Read("WWW.EXAMPLE.", 1, fixture.ReaderCredential), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal("current", read.State);
        Assert.Equal(2L, read.Revision);
        Assert.Equal(new byte[] { 192, 0, 2, 99 }, Assert.Single(read.Records).Data.ToArray());
        var zone = new ZoneBundleAdapter().Decode(await fixture.SnapshotAsync().ConfigureAwait(true));
        Assert.Equal(3, zone.GetAllRecords().Count);
        Assert.Equal(2u, zone.Soa.GetSoaSerial());
        Assert.Single(zone.GetRecords(zone.Origin), record => record.Type == 2);
        Assert.Equal("record-client", (await ReadOperationAsync(fixture, patch).ConfigureAwait(true))!.Actor);
        await AssertAuditCountAsync(fixture, 2).ConfigureAwait(true);
    }

    [Fact]
    public async Task ConcurrentChallengesRetryByRevisionAndCleanupPreservesTheOtherValue()
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var first = fixture.Challenge(1);
        var second = fixture.Challenge(1, 'B');
        var attempts = await Task.WhenAll(TryPatchAsync(fixture, first), TryPatchAsync(fixture, second)).ConfigureAwait(true);
        Assert.Single(attempts, value => value);
        var winner = attempts[0] ? first : second;
        var loser = attempts[0] ? second : first;
        var read = await ReadChallengeAsync(fixture).ConfigureAwait(true);
        Assert.Equal(2L, read.Revision);
        _ = await fixture.Application.ExecuteAsync(loser with { ExpectedRevision = read.Revision }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, (await ReadChallengeAsync(fixture).ConfigureAwait(true)).Records.Count);
        var cleanup = fixture.Patch(3, winner.Changes[0] with { Add = Array.Empty<ReadOnlyMemory<byte>>(), Remove = winner.Changes[0].Add }) with { Credential = fixture.AcmeCredential };
        var removed = await fixture.Application.ExecuteAsync(cleanup, CancellationToken.None).ConfigureAwait(true);
        var remaining = await ReadChallengeAsync(fixture).ConfigureAwait(true);
        Assert.Equal(4L, remaining.Revision);
        Assert.Equal(loser.Changes[0].Add[0].ToArray(), Assert.Single(remaining.Records).Data.ToArray());
        Assert.Equal(removed, await fixture.Application.ExecuteAsync(cleanup, CancellationToken.None).ConfigureAwait(true));
        var replay = await fixture.Application.ExecuteAsync(winner, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2L, replay.Revision);
        Assert.Single((await ReadChallengeAsync(fixture).ConfigureAwait(true)).Records);
        await AssertAuditCountAsync(fixture, 4).ConfigureAwait(true);
    }

    [Fact]
    public async Task CanonicalPatchReplaySurvivesLaterEditsAndRejectsDifferentIntentOrAction()
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var request = fixture.Patch(1, RecordManagementFixture.Change("mail.example.", 15, [Mx("mx2.example."), Mx("MX1.EXAMPLE.")]));
        var accepted = await fixture.Application.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true);
        _ = await fixture.Application.ExecuteAsync(fixture.Control.Edit(2, 43), CancellationToken.None).ConfigureAwait(true);
        var reordered = request with { Changes = [RecordManagementFixture.Change("MAIL.EXAMPLE.", 15, [Mx("mx1.example."), Mx("MX2.EXAMPLE.")])] };
        Assert.Equal(accepted, await fixture.Application.ExecuteAsync(reordered, CancellationToken.None).ConfigureAwait(true));
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application.ExecuteAsync(request with { Changes = [request.Changes[0] with { Ttl = 301 }] }, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Application.ExecuteAsync(fixture.Control.Edit(1, operation: request.OperationId), CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(3L, (await fixture.SnapshotAsync().ConfigureAwait(true)).Revision);
        await AssertAuditCountAsync(fixture, 3).ConfigureAwait(true);
    }

    [Theory]
    [InlineData("edit")]
    [InlineData("other-read")]
    [InlineData("other-patch")]
    [InlineData("readonly-write")]
    [InlineData("foreign-status")]
    [InlineData("wrong-tenant")]
    public async Task RestrictedCredentialsCannotBroadenTheirScopeOrInspectOthersOperations(string attack)
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var request = attack switch
        {
            "edit" => fixture.Control.Edit(1) with { Credential = fixture.AcmeCredential },
            "other-read" => fixture.Read("www.example.", 1, fixture.AcmeCredential),
            "other-patch" => fixture.Patch(1, RecordManagementFixture.Change("www.example.", 1, [new byte[] { 192, 0, 2, 99 }])) with { Credential = fixture.AcmeCredential },
            "readonly-write" => fixture.Patch(1, RecordManagementFixture.Change("www.example.", 1, [new byte[] { 192, 0, 2, 99 }])) with { Credential = fixture.ReaderCredential },
            "wrong-tenant" => fixture.Challenge(1) with { TenantId = Guid.NewGuid() },
            _ => fixture.Control.Edit() with { Action = "status", OperationId = (await fixture.Store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!.OperationId, Credential = fixture.AcmeCredential, Records = Array.Empty<ZoneRecordData>() },
        };
        var original = await fixture.SnapshotAsync().ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => fixture.Application.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(original.ContentHash, (await fixture.SnapshotAsync().ConfigureAwait(true)).ContentHash);
        await AssertAuditCountAsync(fixture, 1).ConfigureAwait(true);
    }

    [Fact]
    public async Task ChallengeReceiptStatusIsScopedAndPublicationFeedsTheExistingAuthority()
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var request = fixture.Challenge(1);
        var accepted = await fixture.Application.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal("accepted", accepted.State);
        Assert.Equal(accepted, await fixture.Application.ExecuteAsync(request with { Action = "status", Changes = Array.Empty<RrsetChange>() }, CancellationToken.None).ConfigureAwait(true));
        var replica = new ReplicaFixture(fixture.Control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenAsync().ConfigureAwait(true);
        var publisher = new OutboxPublisher(fixture.Store, replica.Signer, replica.Publication!);
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.False(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        var activated = await fixture.Application.ExecuteAsync(request with { Action = "status", Changes = Array.Empty<RrsetChange>() }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal("activated", activated.State);
        Assert.Equal(accepted.ContentHash, activated.ContentHash);
        var active = await replica.Store.ReadActiveAsync(fixture.Control.Zone, CancellationToken.None).ConfigureAwait(true);
        var zone = new ZoneBundleAdapter().Decode(active!);
        Assert.Equal(RecordManagementFixture.Text('A'), Assert.Single(zone.GetRecords(RecordManagementFixture.ChallengeName)).GetData());
    }

    [Theory]
    [InlineData("soa")]
    [InlineData("duplicate-rdata")]
    [InlineData("duplicate-key")]
    [InlineData("add-remove")]
    [InlineData("ttl")]
    [InlineData("alias")]
    [InlineData("remove-apex-ns")]
    public async Task InvalidAtomicBatchLeavesZoneAuditAndOutboxUntouched(string invalid)
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var good = RecordManagementFixture.Change("new.example.", 1, [new byte[] { 192, 0, 2, 43 }]);
        var bad = invalid switch
        {
            "soa" => RecordManagementFixture.Change("example.", 6, []),
            "duplicate-rdata" => RecordManagementFixture.Change("mail.example.", 15, [Mx("mx.example."), Mx("MX.EXAMPLE.")]),
            "duplicate-key" => good,
            "add-remove" => RecordManagementFixture.Change("bad.example.", 1, [new byte[] { 192, 0, 2, 44 }], [new byte[] { 192, 0, 2, 44 }]),
            "ttl" => RecordManagementFixture.Change("www.example.", 1, [new byte[] { 192, 0, 2, 99 }], ttl: 301),
            "alias" => RecordManagementFixture.Change("www.example.", 5, [DnsName.Parse("other.example.").ToWire()]),
            _ => RecordManagementFixture.Change("example.", 2, [], replace: true),
        };
        var request = fixture.Patch(1, good, bad);
        var exception = await Record.ExceptionAsync(() => fixture.Application.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.True(exception is ArgumentException or InvalidOperationException);
        Assert.Equal(1L, (await fixture.SnapshotAsync().ConfigureAwait(true)).Revision);
        await AssertAuditCountAsync(fixture, 1).ConfigureAwait(true);
    }

    [Theory]
    [InlineData("cut")]
    [InlineData("alias")]
    public async Task UnservableAcmeOwnersFailWithoutAnyMutation(string obstruction)
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        var record = new ZoneRecordData(RecordManagementFixture.ChallengeName.ToWire(), obstruction is "cut" ? (ushort)2 : (ushort)5, 300, DnsName.Parse("other.example.").ToWire());
        await fixture.InitializeAsync(record).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => fixture.Application.ExecuteAsync(fixture.Challenge(1), CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => ReadChallengeAsync(fixture)).ConfigureAwait(true);
        Assert.Equal(1L, (await fixture.SnapshotAsync().ConfigureAwait(true)).Revision);
        await AssertAuditCountAsync(fixture, 1).ConfigureAwait(true);
    }

    [Fact]
    public async Task AdmittedPatchPinsCallerBuffersWhileWaitingForTheTransaction()
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var held = await fixture.Store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var heldLifetime = held.ConfigureAwait(true);
        var value = RecordManagementFixture.Text('A');
        var owner = RecordManagementFixture.ChallengeName.ToWire();
        var request = fixture.Patch(1, new RrsetChange(owner, 16, 300, new ReadOnlyMemory<byte>[] { value }, Array.Empty<ReadOnlyMemory<byte>>(), false)) with { Credential = fixture.AcmeCredential };
        var pending = fixture.Application.ExecuteAsync(request, CancellationToken.None).AsTask();
        Assert.False(pending.IsCompleted);
        Array.Fill(value, (byte)'B');
        owner[1] = (byte)'X';
        await held.DisposeAsync().ConfigureAwait(true);
        Assert.Equal(2L, (await pending.ConfigureAwait(true)).Revision);
        Assert.Equal(RecordManagementFixture.Text('A'), Assert.Single((await ReadChallengeAsync(fixture).ConfigureAwait(true)).Records).Data.ToArray());
    }

    [Fact]
    public async Task CredentialsThatExpireWhileQueuedCannotCommitOrRead()
    {
        var time = new AdvancingTime();
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true), time);
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var held = await fixture.Store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var heldLifetime = held.ConfigureAwait(true);
        var mutation = fixture.Application.ExecuteAsync(fixture.Challenge(1), CancellationToken.None).AsTask();
        var read = ReadChallengeAsync(fixture);
        var unknownStatus = fixture.Application.ExecuteAsync(fixture.Challenge(1) with { Action = "status", Changes = Array.Empty<RrsetChange>() }, CancellationToken.None).AsTask();
        Assert.False(mutation.IsCompleted);
        Assert.False(read.IsCompleted);
        Assert.False(unknownStatus.IsCompleted);
        time.Advance(TimeSpan.FromHours(2));
        await held.DisposeAsync().ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => mutation.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => read.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => unknownStatus.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(1L, (await fixture.SnapshotAsync().ConfigureAwait(true)).Revision);
        await AssertAuditCountAsync(fixture, 1).ConfigureAwait(true);
    }

    [Fact]
    public async Task ReadLimitsAndCanonicalRemoveApplyToExactRrsets()
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.InitializeAsync().ConfigureAwait(true);
        var add = fixture.Patch(1, RecordManagementFixture.Change("mail.example.", 15, [Mx("MX.EXAMPLE.")]));
        _ = await fixture.Application.ExecuteAsync(add, CancellationToken.None).ConfigureAwait(true);
        var remove = fixture.Patch(2, RecordManagementFixture.Change("MAIL.EXAMPLE.", 15, [], [Mx("mx.example.")], ttl: 999));
        _ = await fixture.Application.ExecuteAsync(remove, CancellationToken.None).ConfigureAwait(true);
        Assert.Empty((await fixture.Application.ExecuteAsync(fixture.Read("mail.example.", 15), CancellationToken.None).ConfigureAwait(true)).Records);
        var read = fixture.Read("www.example.", 1);
        _ = await Assert.ThrowsAsync<ArgumentException>(() => fixture.Application.ExecuteAsync(read with { Selection = read.Selection.Concat(read.Selection).ToArray() }, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<ArgumentException>(() => fixture.Application.ExecuteAsync(read with { Selection = Array.Empty<RrsetKey>() }, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<ArgumentException>(() => fixture.Application.ExecuteAsync(fixture.Read("outside.", 1), CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(3L, (await fixture.SnapshotAsync().ConfigureAwait(true)).Revision);
    }

    private static Task<ManagementReply> ReadChallengeAsync(RecordManagementFixture fixture) => fixture.Application.ExecuteAsync(fixture.Read(RecordManagementFixture.ChallengeName.ToString(), 16, fixture.AcmeCredential), CancellationToken.None).AsTask();
    private static byte[] Mx(string name) => new byte[] { 0, 10 }.Concat(DnsName.Parse(name).ToWire()).ToArray();

    private static async Task<bool> TryPatchAsync(RecordManagementFixture fixture, ManagementRequest request)
    {
        try { _ = await fixture.Application.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true); return true; }
        catch (InvalidOperationException) { return false; }
    }

    private static async Task<ZoneOperation?> ReadOperationAsync(RecordManagementFixture fixture, ManagementRequest request)
    {
        var transaction = await fixture.Store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = transaction.ConfigureAwait(true);
        return await transaction.ReadOperationAsync(fixture.Control.Tenant, request.OperationId, CancellationToken.None).ConfigureAwait(true);
    }

    private static async Task AssertAuditCountAsync(RecordManagementFixture fixture, long expected)
    {
        var connection = new NpgsqlConnection(fixture.Connection);
        await using var connectionLifetime = connection.ConfigureAwait(true);
        await connection.OpenAsync().ConfigureAwait(true);
        var command = new NpgsqlCommand("SELECT count(*) FROM mk8_operations WHERE zone_id=$1", connection);
        await using var commandLifetime = command.ConfigureAwait(true);
        command.Parameters.AddWithValue(fixture.Control.Zone);
        Assert.Equal(expected, (long)(await command.ExecuteScalarAsync().ConfigureAwait(true))!);
    }

    private sealed class AdvancingTime : TimeProvider
    {
        private long ticks = DateTimeOffset.UtcNow.UtcTicks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref ticks), TimeSpan.Zero);
        internal void Advance(TimeSpan duration) => Interlocked.Add(ref ticks, duration.Ticks);
    }
}
