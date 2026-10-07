using System.Buffers.Binary;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class SvcbPublicationTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    private const string Data = "000100000100060268320268330003000201bbff00000200ff";

    [Fact]
    public async Task TypedImportPublishesAndHistoricalGenericReplayDoesNotUndoARawPatch()
    {
        var fixture = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var storeLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        var authorizer = new ScopedManagementAuthorizer([fixture.Grant() with { Actions = ["import", "export", "patch", "read", "status"] }], TimeProvider.System);
        var management = new ZoneManagementApplication(store, authorizer, new ZoneBundleAdapter(), ControlFixture.Node, new ZoneMasterFileAdapter());
        var replica = new ReplicaFixture(fixture);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenAsync().ConfigureAwait(true);
        var publisher = new OutboxPublisher(store, replica.Signer, replica.Publication!);
        var import = Import(fixture);
        var initial = await management.ExecuteAsync(import, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1L, initial.Revision);
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        await AssertReplyAsync(replica.Authority, Data).ConfigureAwait(true);
        var export = await management.ExecuteAsync(import with { Action = "export", ZoneFile = null }, CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(export.ZoneFile);
        Assert.Equal(initial.ContentHash, ZoneBundleCodec.Compile(fixture.Zone, 1, ZoneMasterFileCodec.Import(DnsName.Parse("example."), export.ZoneFile)).ContentHash);
        var replacement = Convert.FromHexString(Data);
        replacement[1] = 2;
        var patch = import with { Action = "patch", ZoneFile = null, OperationId = Guid.NewGuid(), ExpectedRevision = 1, Changes = [new RrsetChange(DnsName.Parse("svc.example.").ToWire(), 65, 300, [replacement], Array.Empty<ReadOnlyMemory<byte>>(), true)] };
        Assert.Equal(2L, (await management.ExecuteAsync(patch, CancellationToken.None).ConfigureAwait(true)).Revision);
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        var replay = await management.ExecuteAsync(import with { ZoneFile = export.ZoneFile }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal("activated", replay.State);
        Assert.Equal(initial.ContentHash, replay.ContentHash);
        Assert.Equal(1L, replay.Revision);
        await AssertReplyAsync(replica.Authority, Convert.ToHexString(replacement)).ConfigureAwait(true);
        Assert.Equal(2L, (await replica.Store.ReadActiveAsync(fixture.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
        Assert.Null(await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true));
    }

    private static ManagementRequest Import(ControlFixture fixture) => new("import", fixture.Tenant, fixture.Zone, Guid.NewGuid(), 0,
        DnsName.Parse("example.").ToWire(), Array.Empty<ZoneRecordData>(), fixture.Credential)
    { ZoneFile = ZoneFileManagementTests.Text + "svc HTTPS 1 . key65280=\"\\000\\255\" port=443 alpn=\"h2,h3\"\n" };

    private static async Task AssertReplyAsync(AuthoritativeApplication authority, string hex)
    {
        var query = Convert.FromHexString("abcd0100000100000000000003737663076578616d706c650000410001");
        foreach (var tcp in new[] { false, true })
        {
            var response = await authority.ExchangeAsync(query, tcp, new byte[] { 127, 0, 0, 1 }, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(Convert.FromHexString("abcd85000001000100000000"), response[..12]);
            Assert.Equal(query[12..], response[12..query.Length]);
            Assert.Equal(Convert.FromHexString("c00c004100010000012c"), response[query.Length..(query.Length + 10)]);
            Assert.Equal(hex.Length / 2, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(query.Length + 10)));
            Assert.Equal(Convert.FromHexString(hex), response[(query.Length + 12)..]);
        }
    }
}
