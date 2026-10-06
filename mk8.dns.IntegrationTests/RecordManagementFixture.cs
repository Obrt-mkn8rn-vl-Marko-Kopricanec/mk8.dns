using System.Security.Cryptography;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;

namespace Mk8.Dns.IntegrationTests;

internal sealed class RecordManagementFixture : IAsyncDisposable
{
    internal ControlFixture Control { get; } = new();
    internal byte[] AcmeCredential { get; } = RandomNumberGenerator.GetBytes(32);
    internal byte[] RecordCredential { get; } = RandomNumberGenerator.GetBytes(32);
    internal byte[] ReaderCredential { get; } = RandomNumberGenerator.GetBytes(32);
    internal string Connection { get; }
    internal PostgresControlPlaneStore Store { get; }
    internal ZoneManagementApplication Application { get; }
    internal static readonly DnsName ChallengeName = DnsName.Parse("_acme-challenge.example.");

    internal RecordManagementFixture(string connection, TimeProvider? time = null)
    {
        Connection = connection;
        Store = new PostgresControlPlaneStore(connection);
        var authorizer = new ScopedManagementAuthorizer([Control.Grant(), Grant("acme", "acme-client", AcmeCredential, ChallengeName, 16, ["patch", "read", "status"]),
            Grant("records", "record-client", RecordCredential, DnsName.Parse("www.example."), 1, ["patch", "read", "status"]),
            Grant("records", "reader-client", ReaderCredential, DnsName.Parse("www.example."), 1, ["read"])], time ?? TimeProvider.System);
        Application = new ZoneManagementApplication(Store, authorizer, new ZoneBundleAdapter(), ControlFixture.Node);
    }

    internal async Task InitializeAsync(params ZoneRecordData[] records)
    {
        await Store.InitializeAsync(Control.Epoch, CancellationToken.None).ConfigureAwait(true);
        var edit = Control.Edit();
        _ = await Application.ExecuteAsync(edit with { Records = edit.Records.Concat(records).ToArray() }, CancellationToken.None).ConfigureAwait(true);
    }

    internal ManagementRequest Patch(long revision, params RrsetChange[] changes) => new("patch", Control.Tenant, Control.Zone, Guid.NewGuid(), revision, DnsName.Parse("example.").ToWire(), Array.Empty<ZoneRecordData>(), Control.Credential) { Changes = changes };
    internal ManagementRequest Read(string name, ushort type, byte[]? credential = null) => new("read", Control.Tenant, Control.Zone, Guid.NewGuid(), 0, DnsName.Parse("example.").ToWire(), Array.Empty<ZoneRecordData>(), credential ?? Control.Credential) { Selection = [new(DnsName.Parse(name).ToWire(), type)] };
    internal ManagementRequest Challenge(long revision, char digest = 'A', bool remove = false) => Patch(revision, Change(ChallengeName.ToString(), 16, remove ? [] : [Text(digest)], remove ? [Text(digest)] : [])) with { Credential = AcmeCredential };
    internal static byte[] Text(char digest) => new[] { (byte)43 }.Concat(Enumerable.Repeat((byte)digest, 42)).Append((byte)'A').ToArray();
    internal static RrsetChange Change(string owner, ushort type, byte[][] added, byte[][]? removed = null, bool replace = false, uint ttl = 300)
        => new(DnsName.Parse(owner).ToWire(), type, ttl, added.Select(data => (ReadOnlyMemory<byte>)data).ToArray(), (removed ?? []).Select(data => (ReadOnlyMemory<byte>)data).ToArray(), replace);

    internal async Task<ZoneSnapshot> SnapshotAsync()
    {
        var transaction = await Store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = transaction.ConfigureAwait(true);
        return await transaction.ReadZoneAsync(Control.Tenant, Control.Zone, CancellationToken.None).ConfigureAwait(true) ?? throw new InvalidDataException();
    }

    public ValueTask DisposeAsync() => Store.DisposeAsync();

    private ManagementGrant Grant(string profile, string actor, byte[] credential, DnsName owner, ushort type, string[] actions) => Control.Grant() with
    {
        Profile = profile,
        Actor = actor,
        CredentialHash = SHA256.HashData(credential),
        Actions = actions,
        RecordScopes = [new(owner, type)],
    };
}
