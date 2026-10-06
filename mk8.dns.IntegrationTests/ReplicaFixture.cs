using System.Security.Cryptography;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;

namespace Mk8.Dns.IntegrationTests;

internal sealed class ReplicaFixture : IAsyncDisposable
{
    private readonly string root;
    private readonly FileZoneSnapshotStore snapshots;
    private readonly FilePublicationJournal journal;
    private readonly P256PublicationAuthenticator verifier;
    internal P256PublicationAuthenticator Signer { get; }
    internal AuthoritativeApplication Authority { get; }
    internal ZonePublicationApplication? Publication { get; private set; }
    private readonly Guid zone;

    internal ReplicaFixture(ControlFixture control)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        root = Path.Combine(Path.GetTempPath(), "m8relay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        snapshots = new FileZoneSnapshotStore(Path.Combine(root, "snapshots"));
        journal = new FilePublicationJournal(Path.Combine(root, "proofs"));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var scopes = new Dictionary<Guid, DnsName> { [control.Zone] = DnsName.Parse("example.") };
        Signer = new P256PublicationAuthenticator(control.Epoch, ControlFixture.Node, scopes, key.ExportPkcs8PrivateKeyPem(), canSign: true);
        verifier = new P256PublicationAuthenticator(control.Epoch, ControlFixture.Node, scopes, key.ExportSubjectPublicKeyInfoPem(), canSign: false);
        Authority = new AuthoritativeApplication(new DnsMessageCodecAdapter(), ControlFixture.Node);
        zone = control.Zone;
    }

    internal async Task OpenAsync() => Publication = await ZonePublicationApplication.OpenAsync(snapshots, journal, verifier, new ZoneBundleAdapter(), Authority, ControlFixture.Node, [zone], CancellationToken.None).ConfigureAwait(true);

    public async ValueTask DisposeAsync()
    {
        if (Publication is not null)
            await Publication.DisposeAsync().ConfigureAwait(true);
        await snapshots.DisposeAsync().ConfigureAwait(true);
        journal.Dispose();
        Signer.Dispose();
        verifier.Dispose();
        Directory.Delete(root, recursive: true);
    }
}
