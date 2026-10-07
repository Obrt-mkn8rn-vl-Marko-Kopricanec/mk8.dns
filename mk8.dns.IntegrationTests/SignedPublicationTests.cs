using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class SignedPublicationTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task SignedCommitReplayAndOutboxPublicationPreserveOriginalIntentAndReceipt()
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var storeLifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var counter = new CountingKey(key);
        var time = new Clock();
        var codec = Codec(counter, time);
        var management = new ZoneManagementApplication(store, control.Authorizer(), codec, ControlFixture.Node, new ZoneMasterFileAdapter());
        var edit = control.Edit();
        var accepted = await management.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        var pending = await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(pending);
        Assert.Equal(1U, pending.Snapshot.Serial);
        Assert.True(codec.DecodeContents(pending.Snapshot).IsSigned);
        var calls = counter.Calls;
        time.Seconds = 2000;
        Assert.Equal(accepted, await management.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(calls, counter.Calls);
        var replica = new ReplicaFixture(control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        var publisher = new OutboxPublisher(store, replica.Signer, replica.Publication!);
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.True((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        var active = await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(accepted.ContentHash, active!.ContentHash);
        var later = await management.ExecuteAsync(control.Edit(1, 43), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2U, later.Serial);
        var replay = await management.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(accepted.ContentHash, replay.ContentHash);
        Assert.Equal(1L, replay.Revision);
        var export = await management.ExecuteAsync(edit with
        {
            Action = "read",
            OperationId = Guid.NewGuid(),
            Records = [],
            Selection = [new RrsetKey(DnsName.Parse("www.example.").ToWire(), 1), new RrsetKey(control.Edit().Origin, 48)],
        }, CancellationToken.None).ConfigureAwait(true);
        Assert.DoesNotContain(export.Records, record => record.Type is 46 or 47 or 48);
        Assert.Contains(export.Records, record => record.Type == 1 && record.Data.Span[3] == 43);
    }

    [Fact]
    public async Task ExpiredStartupStaysUnreadyButAcceptsAFreshGenerationWithoutForgettingAcknowledgedState()
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var storeLifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var management = new ZoneManagementApplication(store, control.Authorizer(), Codec(key, time), ControlFixture.Node);
        _ = await management.ExecuteAsync(control.Edit(), CancellationToken.None).ConfigureAwait(true);
        var replica = new ReplicaFixture(control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        Assert.True(await new OutboxPublisher(store, replica.Signer, replica.Publication!).DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        await replica.Publication!.DisposeAsync().ConfigureAwait(true);
        time.Seconds = 5000;
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        Assert.False((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        Assert.Equal(1L, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
        _ = await management.ExecuteAsync(control.Edit(1, 44), CancellationToken.None).ConfigureAwait(true);
        Assert.True(await new OutboxPublisher(store, replica.Signer, replica.Publication!).DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.True((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        Assert.Equal(2L, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task InvalidInnerSignatureUnsignedDowngradeOrNewSigningKeyCannotMutateActiveGeneration(int change)
    {
        var control = new ControlFixture();
        var time = new Clock();
        using var key = EcdsaP256DnssecSigningKey.Create();
        var codec = Codec(key, time);
        var source = Source(control.Edit());
        var first = codec.Compile(control.Zone, 1, source);
        var replica = new ReplicaFixture(control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        await PublishAsync(replica, first).ConfigureAwait(true);
        var later = WithSerial(source, first.Serial + 1);
        using var replacementKey = EcdsaP256DnssecSigningKey.Create();
        var candidate = change switch
        {
            1 => new ZoneBundleAdapter().Compile(control.Zone, 2, later),
            2 => Codec(replacementKey, time).Compile(control.Zone, 2, later),
            _ => Tampered(codec.Compile(control.Zone, 2, later)),
        };
        var request = Prepare(replica, candidate);
        if (change != 0)
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => replica.Publication!.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        else
            _ = await Assert.ThrowsAsync<FormatException>(() => replica.Publication!.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(first.ContentHash, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.ContentHash);
        Assert.True((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        await replica.Publication!.DisposeAsync().ConfigureAwait(true);
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        Assert.True((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ControllerRejectsKeyReplacementOrUnsignedDowngradeWithoutAppendingIntentOrOutbox(bool downgrade)
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var storeLifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        using var replacementKey = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var originalCodec = Codec(key, time);
        var management = new ZoneManagementApplication(store, control.Authorizer(), originalCodec, ControlFixture.Node);
        var first = await management.ExecuteAsync(control.Edit(), CancellationToken.None).ConfigureAwait(true);
        var changedCodec = downgrade ? new ZoneBundleAdapter() : Codec(replacementKey, time);
        var changedManagement = new ZoneManagementApplication(store, control.Authorizer(), changedCodec, ControlFixture.Node);
        var request = control.Edit(1, 44);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => changedManagement.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(first.ContentHash, (await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!.Snapshot.ContentHash);
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using (transaction.ConfigureAwait(true))
        {
            Assert.Equal(first.ContentHash, (await transaction.ReadZoneAsync(control.Tenant, control.Zone, CancellationToken.None).ConfigureAwait(true))!.ContentHash);
            Assert.Null(await transaction.ReadOperationAsync(control.Tenant, request.OperationId, CancellationToken.None).ConfigureAwait(true));
        }
        var accepted = await management.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2L, accepted.Revision);
    }

    [Fact]
    public async Task ExpirationAfterPreparePreventsActivationAndKeepsTheOldGeneration()
    {
        var control = new ControlFixture();
        using var key = EcdsaP256DnssecSigningKey.Create();
        var time = new Clock();
        var codec = Codec(key, time);
        var replica = new ReplicaFixture(control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenSignedAsync(time).ConfigureAwait(true);
        var first = codec.Compile(control.Zone, 1, Source(control.Edit()));
        await PublishAsync(replica, first).ConfigureAwait(true);
        var later = codec.Compile(control.Zone, 2, WithSerial(codec.Decode(first), first.Serial + 1));
        var request = Prepare(replica, later);
        _ = await replica.Publication!.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true);
        time.Seconds = 5000;
        _ = await Assert.ThrowsAsync<FormatException>(() => replica.Publication.ExecuteAsync(new PublicationRequest("activate", ReadOnlyMemory<byte>.Empty,
            replica.Signer.SignActivation(request.PublicationId), request.PublicationId), CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(first.ContentHash, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.ContentHash);
        Assert.False((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
    }

    [Fact]
    public async Task SigningFailureCannotAppendIntentAuditOrOutbox()
    {
        var control = new ControlFixture();
        var store = await StoreAsync(control).ConfigureAwait(true);
        await using var storeLifetime = store.ConfigureAwait(true);
        using var key = EcdsaP256DnssecSigningKey.Create();
        var management = new ZoneManagementApplication(store, control.Authorizer(), Codec(new FaultedKey(key), new Clock()), ControlFixture.Node);
        var request = control.Edit();
        _ = await Assert.ThrowsAsync<CryptographicException>(() => management.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Null(await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true));
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var transactionLifetime = transaction.ConfigureAwait(true);
        Assert.Null(await transaction.ReadZoneAsync(control.Tenant, control.Zone, CancellationToken.None).ConfigureAwait(true));
        Assert.Null(await transaction.ReadOperationAsync(control.Tenant, request.OperationId, CancellationToken.None).ConfigureAwait(true));
        Assert.Empty(await transaction.ReadOwnershipAsync(CancellationToken.None).ConfigureAwait(true));
    }

    private async Task<PostgresControlPlaneStore> StoreAsync(ControlFixture control)
    {
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await store.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
        return store;
    }

    private static ZoneBundleAdapter Codec(IDnssecSigningKey key, Clock time) => new(new DnssecZoneSigningService(
        new Dictionary<DnsName, DnssecSigningPolicy> { [DnsName.Parse("example.")] = new(key, 3600) }, new EcdsaP256DnssecVerifier(), time));
    private static AuthoritativeZone Source(ManagementRequest request) => new(DnsName.FromWire(request.Origin.Span),
        request.Records.Select(record => new DnsRecord(record.Owner.Span, record.Type, record.Ttl, record.Data.Span)));

    private static AuthoritativeZone WithSerial(AuthoritativeZone source, uint serial)
    {
        var data = source.Soa.GetData();
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(data.Length - 20), serial);
        return new AuthoritativeZone(source.Origin, source.GetAllRecords().Select(record => record.Type == 6 ? new DnsRecord(record.Owner, 6, record.Ttl, data) : record));
    }

    private static ZoneSnapshot Tampered(ZoneSnapshot snapshot)
    {
        var contents = SignedZoneBundleCodec.Decode(snapshot);
        var signature = contents.GetSecurityRecords().First(record => record.Type == 46);
        var data = signature.GetData();
        data[^1] ^= 1;
        return SignedZoneBundleCodec.Compile(snapshot.ZoneId, snapshot.Revision, new ZoneContents(contents.Source,
            contents.GetSecurityRecords().Select(record => ReferenceEquals(record, signature) ? new DnsRecord(record.Owner, 46, record.Ttl, data) : record)));
    }

    private static PublicationRequest Prepare(ReplicaFixture replica, ZoneSnapshot snapshot)
    {
        var body = replica.Signer.CreateBody(snapshot);
        return new PublicationRequest("prepare", body, replica.Signer.Sign(body), Convert.ToHexStringLower(SHA256.HashData(body)));
    }

    private static async Task PublishAsync(ReplicaFixture replica, ZoneSnapshot snapshot)
    {
        var request = Prepare(replica, snapshot);
        _ = await replica.Publication!.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true);
        _ = await replica.Publication.ExecuteAsync(new PublicationRequest("activate", ReadOnlyMemory<byte>.Empty,
            replica.Signer.SignActivation(request.PublicationId), request.PublicationId), CancellationToken.None).ConfigureAwait(true);
    }

    private sealed class Clock : TimeProvider
    {
        internal uint Seconds { get; set; } = 1000;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Seconds);
    }

    private sealed class CountingKey(IDnssecSigningKey key) : IDnssecSigningKey
    {
        internal int Calls { get; private set; }
        public byte Algorithm => key.Algorithm;
        public byte[] GetPublicKey() => key.GetPublicKey();
        public byte[] SignHash(ReadOnlySpan<byte> digest)
        {
            Calls++;
            return key.SignHash(digest);
        }
    }

    private sealed class FaultedKey(IDnssecSigningKey key) : IDnssecSigningKey
    {
        public byte Algorithm => key.Algorithm;
        public byte[] GetPublicKey() => key.GetPublicKey();
        public byte[] SignHash(ReadOnlySpan<byte> digest) => throw new CryptographicException("Deterministic signing failure.");
    }
}
