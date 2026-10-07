using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class SignatureRenewalTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task AutomaticRefreshPublishesNewSerialWithoutChangingIntentOrHistoricalUserReplay()
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var storeLifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var codec = Codec(key, time);
        var management = new ZoneManagementApplication(store, control.Authorizer(), codec, ControlFixture.Node);
        var edit = control.Edit();
        var receipt = await management.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        var replica = new ReplicaFixture(control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        var publisher = new OutboxPublisher(store, replica.Signer, replica.Publication!);
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        var first = (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!;
        var job = Job(store, codec, time, control);
        time.Seconds = 3699;
        Assert.False(await job.ResignAsync(control.Zone, CancellationToken.None).ConfigureAwait(true));
        time.Seconds = 3700;
        Assert.True(await job.ResignAsync(control.Zone, CancellationToken.None).ConfigureAwait(true));
        var pending = (await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!;
        Assert.Equal(2L, pending.Snapshot.Revision);
        Assert.Equal(2U, pending.Snapshot.Serial);
        Assert.Equal("mk8.dns:signature-renewal", pending.Actor);
        Assert.Equal(first.ContentHash, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.ContentHash);
        Assert.False(await job.ResignAsync(control.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Null(await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true));
        var refreshed = (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!;
        Assert.Equal(pending.Snapshot.ContentHash, refreshed.ContentHash);
        var proof = SignedZoneAdmission.Verify(codec.DecodeContents(refreshed), time.Seconds, new EcdsaP256DnssecVerifier());
        Assert.Equal(7300U, proof.Window.Expiration);
        Assert.Equal(codec.DecodeContents(first).GetSecurityRecords().Single(record => record.Type == 48).GetData(), proof.Dnskey.GetData());
        Assert.Equal(42, codec.Decode(refreshed).GetRecords(DnsName.Parse("www.example.")).Single().GetData()[3]);
        var replay = await management.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(receipt.ContentHash, replay.ContentHash);
        Assert.Equal(1L, replay.Revision);
        Assert.Equal("activated", replay.State);
        Assert.False(await job.ResignAsync(control.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.True((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
    }

    [Fact]
    public async Task ConcurrentScansCommitExactlyOneGenerationThroughTheDatabaseFence()
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var codec = Codec(key, time);
        _ = await new ZoneManagementApplication(store, control.Authorizer(), codec, ControlFixture.Node).ExecuteAsync(control.Edit(), CancellationToken.None).ConfigureAwait(true);
        await AcknowledgeAsync(store).ConfigureAwait(true);
        time.Seconds = 4000;
        var jobs = new[] { Job(store, codec, time, control), Job(store, codec, time, control) };
        var results = await Task.WhenAll(jobs.Select(job => job.ResignAsync(control.Zone, CancellationToken.None).AsTask())).ConfigureAwait(true);
        Assert.Single(results, result => result);
        var pending = (await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!;
        Assert.Equal(2L, pending.Snapshot.Revision);
        await RequireRowsAsync(store, control, 2, true).ConfigureAwait(true);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RenewalCannotSkipAnUnactivatedHeadEvenWhenItIsExpired(bool newerIntent)
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var codec = Codec(key, time);
        var management = new ZoneManagementApplication(store, control.Authorizer(), codec, ControlFixture.Node);
        var original = await management.ExecuteAsync(control.Edit(), CancellationToken.None).ConfigureAwait(true);
        if (newerIntent)
        {
            _ = await management.ExecuteAsync(control.Edit(1, 43), CancellationToken.None).ConfigureAwait(true);
            var transaction = await ((IZoneResigningStore)store).BeginAsync(CancellationToken.None).ConfigureAwait(true);
            ZoneOperation operation;
            await using (transaction.ConfigureAwait(true))
                operation = (await transaction.ReadGenerationAsync(control.Tenant, control.Zone, 2, CancellationToken.None).ConfigureAwait(true))!;
            await store.MarkActivatedAsync(operation, new PublicationReply(ControlFixture.Node, control.Zone, 2, operation.Snapshot.ContentHash, "test-ack", "activated"), CancellationToken.None).ConfigureAwait(true);
        }
        time.Seconds = 6000;
        Assert.False(await Job(store, codec, time, control).ResignAsync(control.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(original.ContentHash, (await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!.Snapshot.ContentHash);
        await RequireRowsAsync(store, control, newerIntent ? 2 : 1, true).ConfigureAwait(true);
    }

    [Fact]
    public async Task AcknowledgedExpiredGenerationRecoversAfterControllerAndReplicaRestart()
    {
        var control = new ControlFixture();
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var store = new PostgresControlPlaneStore(connection);
        await using var firstLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var codec = Codec(key, time);
        _ = await new ZoneManagementApplication(store, control.Authorizer(), codec, ControlFixture.Node).ExecuteAsync(control.Edit(), CancellationToken.None).ConfigureAwait(true);
        var replica = new ReplicaFixture(control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        Assert.True(await new OutboxPublisher(store, replica.Signer, replica.Publication!).DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        await replica.Publication!.DisposeAsync().ConfigureAwait(true);
        await store.DisposeAsync().ConfigureAwait(true);
        time.Seconds = 5000;
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        Assert.False((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        Assert.Equal(1L, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
        var successor = new PostgresControlPlaneStore(connection);
        await using var successorLifetime = successor.ConfigureAwait(true);
        await successor.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
        Assert.True(await Job(successor, codec, time, control).ResignAsync(control.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.True(await new OutboxPublisher(successor, replica.Signer, replica.Publication!).DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.True((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        Assert.Equal(2L, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
    }

    [Fact]
    public async Task ConcurrentManagementEditAndRenewalCannotOverwriteEachOthersInput()
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var codec = Codec(key, time);
        var management = new ZoneManagementApplication(store, control.Authorizer(), codec, ControlFixture.Node);
        _ = await management.ExecuteAsync(control.Edit(), CancellationToken.None).ConfigureAwait(true);
        await AcknowledgeAsync(store).ConfigureAwait(true);
        var gate = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var gateLifetime = gate.ConfigureAwait(true);
        time.Seconds = 4000;
        var edit = management.ExecuteAsync(control.Edit(1, 99), CancellationToken.None).AsTask();
        var renew = Job(store, codec, time, control).ResignAsync(control.Zone, CancellationToken.None).AsTask();
        await gate.DisposeAsync().ConfigureAwait(true);
        var results = await Task.WhenAll(ObserveAsync(edit), ObserveRenewalAsync(renew)).ConfigureAwait(true);
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using (transaction.ConfigureAwait(true))
        {
            var current = (await transaction.ReadZoneAsync(control.Tenant, control.Zone, CancellationToken.None).ConfigureAwait(true))!;
            Assert.Equal(2L, current.Revision);
            var expectedAddress = results[0] ? 99 : 42;
            Assert.Equal(expectedAddress, codec.Decode(current).GetRecords(DnsName.Parse("www.example.")).Single().GetData()[3]);
            Assert.True(results[0] || results[1]);
        }
        Assert.NotNull(await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PrivateSigningFailureOrNewKeyCannotAppendAnAutomaticOperation(bool different)
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        using var other = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var original = Codec(key, time);
        _ = await new ZoneManagementApplication(store, control.Authorizer(), original, ControlFixture.Node).ExecuteAsync(control.Edit(), CancellationToken.None).ConfigureAwait(true);
        await AcknowledgeAsync(store).ConfigureAwait(true);
        time.Seconds = 4000;
        var codec = Codec(different ? other : new FaultedKey(key), time);
        if (different)
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => Job(store, codec, time, control).ResignAsync(control.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        else
            _ = await Assert.ThrowsAsync<CryptographicException>(() => Job(store, codec, time, control).ResignAsync(control.Zone, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Null(await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true));
        await RequireRowsAsync(store, control, 1, true).ConfigureAwait(true);
        Assert.True(await Job(store, original, time, control).ResignAsync(control.Zone, CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task ClosingTheStoreCancelsAQueuedRenewalAndRetainsAnAdmittedTransactionUntilItDrains()
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var codec = Codec(key, time);
        var admitted = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var admittedLifetime = admitted.ConfigureAwait(true);
        var waiting = Job(store, codec, time, control).ResignAsync(control.Zone, CancellationToken.None).AsTask();
        var disposal = store.DisposeAsync().AsTask();
        Assert.False(disposal.IsCompleted);
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(TimeSpan.FromSeconds(20))).ConfigureAwait(true);
        await admitted.DisposeAsync().ConfigureAwait(true);
        await disposal.ConfigureAwait(true);
    }

    private async Task<PostgresControlPlaneStore> StoreAsync(ControlFixture control)
    {
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        try
        {
            await store.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
            return store;
        }
        catch
        {
            await store.DisposeAsync().ConfigureAwait(true);
            throw;
        }
    }

    private static ZoneBundleAdapter Codec(IDnssecSigningKey key, Clock time) => new(new DnssecZoneSigningService(
        new Dictionary<DnsName, DnssecSigningPolicy> { [DnsName.Parse("example.")] = new(key, 3600) }, new EcdsaP256DnssecVerifier(), time));

    private static ZoneResigningApplication Job(PostgresControlPlaneStore store, ZoneBundleAdapter codec, Clock time, ControlFixture control)
        => new(store, codec, new EcdsaP256DnssecVerifier(), time, ControlFixture.Node, [new DnssecRenewalScope(control.Zone, DnsName.Parse("example."), 3600)]);

    private static async Task AcknowledgeAsync(PostgresControlPlaneStore store)
    {
        var pending = (await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!;
        await store.MarkActivatedAsync(pending, new PublicationReply(pending.TargetNode, pending.Snapshot.ZoneId, pending.Snapshot.Revision, pending.Snapshot.ContentHash,
            "test-ack", "activated"), CancellationToken.None).ConfigureAwait(true);
    }

    private static async Task RequireRowsAsync(PostgresControlPlaneStore store, ControlFixture control, long revision, bool hasOperation)
    {
        var transaction = await ((IZoneResigningStore)store).BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = transaction.ConfigureAwait(true);
        Assert.Equal(revision, (await transaction.ReadZoneAsync(control.Tenant, control.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
        Assert.Equal(hasOperation, await transaction.ReadGenerationAsync(control.Tenant, control.Zone, revision, CancellationToken.None).ConfigureAwait(true) is not null);
        Assert.Null(await transaction.ReadGenerationAsync(control.Tenant, control.Zone, revision + 1, CancellationToken.None).ConfigureAwait(true));
    }

    private static async Task<bool> ObserveAsync(Task operation)
    {
        try
        {
            await operation.WaitAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(true);
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static async Task<bool> ObserveRenewalAsync(Task<bool> operation) => await operation.WaitAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(true);

    private sealed class Clock : TimeProvider
    {
        internal uint Seconds { get; set; } = 1000;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Seconds);
    }

    private sealed class FaultedKey(IDnssecSigningKey key) : IDnssecSigningKey
    {
        public byte Algorithm => key.Algorithm;
        public byte[] GetPublicKey() => key.GetPublicKey();
        public byte[] SignHash(ReadOnlySpan<byte> digest) => throw new CryptographicException("Deterministic private signing failure.");
    }
}
