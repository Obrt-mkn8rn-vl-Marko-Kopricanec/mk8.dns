using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ZoneFileManagementTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    internal const string Text = "$ORIGIN example.\n$TTL 300\n@ IN SOA ns hostmaster (999 3600 600 86400 30)\n  NS ns\nns A 192.0.2.7\nwww A 192.0.2.42\nunknown TYPE65280 \\# 4 00ffabcd\n";

    [Fact]
    public async Task ImportExportAndCanonicalHistoricalReplayUseExistingAtomicIntent()
    {
        var control = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
        var application = Application(store, control);
        var import = Import(control);
        var first = await application.ExecuteAsync(import, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1L, first.Revision);
        Assert.Equal(1u, first.Serial);
        Assert.Equal("accepted", first.State);
        var export = await application.ExecuteAsync(Export(control), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal("current", export.State);
        Assert.Equal(first.ContentHash, export.ContentHash);
        Assert.Empty(export.Records);
        Assert.NotNull(export.ZoneFile);
        var parsed = ZoneMasterFileCodec.Import(DnsName.Parse("example."), export.ZoneFile);
        Assert.Equal(first.ContentHash, ZoneBundleCodec.Compile(control.Zone, 1, parsed).ContentHash);
        var patch = import with { Action = "patch", ExpectedRevision = 1, OperationId = Guid.NewGuid(), ZoneFile = null, Changes = [RecordManagementFixture.Change("www.example.", 1, [new byte[] { 192, 0, 2, 99 }], replace: true)] };
        Assert.Equal(2L, (await application.ExecuteAsync(patch, CancellationToken.None).ConfigureAwait(true)).Revision);
        var replay = await application.ExecuteAsync(import with { ZoneFile = "; generic representation, assigned serial and order normalize to the same intent\n" + export.ZoneFile }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(first, replay);
        var current = await application.ExecuteAsync(Export(control), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2L, current.Revision);
        Assert.Equal(new byte[] { 192, 0, 2, 99 }, Assert.Single(ZoneMasterFileCodec.Import(DnsName.Parse("example."), current.ZoneFile!).GetRecords(DnsName.Parse("www.example."))).GetData());
        var changed = import with { ZoneFile = Text.Replace("192.0.2.42", "192.0.2.1", StringComparison.Ordinal) };
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => application.ExecuteAsync(changed, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => application.ExecuteAsync(import with { OperationId = Guid.NewGuid() }, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(current, await application.ExecuteAsync(Export(control) with { OperationId = current.OperationId }, CancellationToken.None).ConfigureAwait(true));
    }

    [Theory]
    [InlineData("$INCLUDE /etc/passwd")]
    [InlineData("outside.test. A 192.0.2.1")]
    [InlineData("host TYPE1 \\# 3 00ffab")]
    [InlineData("@ DS 1 8 2 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")]
    [InlineData("host CNAME target\nhost A 192.0.2.1")]
    [InlineData("svc HTTPS 1 . alpn=h2 key1=\\002h3")]
    [InlineData("svc HTTPS 1 . mandatory=port alpn=h2")]
    [InlineData("svc HTTPS 1 . no-default-alpn")]
    [InlineData("svc SVCB 1 . ipv4hint=2001:db8::1")]
    [InlineData("svc SVCB 1 . key3=443")]
    [InlineData("svc SVCB 0 .")]
    [InlineData("svc HTTPS 1 . ech=AB==")]
    public async Task InvalidImportsCannotAppendZoneAuditOrOutbox(string invalid)
    {
        var control = new ControlFixture();
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var store = new PostgresControlPlaneStore(connection);
        await using var lifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
        var application = Application(store, control);
        var initial = await application.ExecuteAsync(Import(control), CancellationToken.None).ConfigureAwait(true);
        var bad = Import(control) with { ExpectedRevision = 1, ZoneFile = Text + invalid };
        _ = await Assert.ThrowsAsync<FormatException>(() => application.ExecuteAsync(bad, CancellationToken.None).AsTask()).ConfigureAwait(true);
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var transactionLifetime = transaction.ConfigureAwait(true);
        Assert.Null(await transaction.ReadOperationAsync(control.Tenant, bad.OperationId, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(initial.ContentHash, (await transaction.ReadZoneAsync(control.Tenant, control.Zone, CancellationToken.None).ConfigureAwait(true))!.ContentHash);
        var database = new Npgsql.NpgsqlConnection(connection);
        await using var databaseLifetime = database.ConfigureAwait(true);
        await database.OpenAsync().ConfigureAwait(true);
        var command = new Npgsql.NpgsqlCommand("SELECT (SELECT count(*) FROM mk8_zones), (SELECT count(*) FROM mk8_operations), (SELECT count(*) FROM mk8_operations WHERE NOT activated)", database);
        await using var commandLifetime = command.ConfigureAwait(true);
        var reader = await command.ExecuteReaderAsync().ConfigureAwait(true);
        await using var readerLifetime = reader.ConfigureAwait(true);
        Assert.True(await reader.ReadAsync().ConfigureAwait(true));
        Assert.Equal(new long[] { 1, 1, 1 }, Enumerable.Range(0, 3).Select(reader.GetInt64));
    }

    [Fact]
    public async Task ExistingGrantActionsDoNotImplicitlyGainImportOrExport()
    {
        var control = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
        var authorizer = control.Authorizer();
        var application = new ZoneManagementApplication(store, authorizer, new ZoneBundleAdapter(), ControlFixture.Node, new ZoneMasterFileAdapter());
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => application.ExecuteAsync(Import(control), CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => application.ExecuteAsync(Export(control), CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(1L, (await application.ExecuteAsync(control.Edit(), CancellationToken.None).ConfigureAwait(true)).Revision);
    }

    private static ZoneManagementApplication Application(PostgresControlPlaneStore store, ControlFixture control) => new(store,
        new ScopedManagementAuthorizer([control.Grant() with { Actions = ["edit", "patch", "read", "status", "import", "export"] }], TimeProvider.System), new ZoneBundleAdapter(), ControlFixture.Node, new ZoneMasterFileAdapter());

    private static ManagementRequest Import(ControlFixture control) => new("import", control.Tenant, control.Zone, Guid.NewGuid(), 0, DnsName.Parse("example.").ToWire(), Array.Empty<ZoneRecordData>(), control.Credential) { ZoneFile = Text };
    private static ManagementRequest Export(ControlFixture control) => new("export", control.Tenant, control.Zone, Guid.NewGuid(), 0, DnsName.Parse("example.").ToWire(), Array.Empty<ZoneRecordData>(), control.Credential);
}
