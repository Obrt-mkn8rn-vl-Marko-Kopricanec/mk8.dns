using System.Security.Cryptography;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.IntegrationTests;

internal sealed class ReplicaFixture : IAsyncDisposable
{
    private readonly string root;
    internal FileZoneSnapshotStore Store { get; }
    private readonly FilePublicationJournal journal;
    private readonly P256PublicationAuthenticator verifier;
    internal P256PublicationAuthenticator Signer { get; }
    internal AuthoritativeApplication Authority { get; }
    internal ZonePublicationApplication? Publication { get; private set; }
    private readonly Guid zone;

    private ReplicaFixture(string root, Guid zone, FileZoneSnapshotStore snapshots, FilePublicationJournal journal,
        P256PublicationAuthenticator signer, P256PublicationAuthenticator verifier)
    {
        this.root = root; this.zone = zone; Store = snapshots; this.journal = journal;
        Signer = signer; this.verifier = verifier;
        Authority = new AuthoritativeApplication(new DnsMessageCodecAdapter(), ControlFixture.Node);
    }

    internal static async Task<ReplicaFixture> CreateAsync(ControlFixture control, Action<string>? beforeJournal = null,
        Action<string>? afterSnapshotRollback = null)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var ownedRoot = Path.Combine(Path.GetTempPath(), "m8relay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ownedRoot, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        FileZoneSnapshotStore? ownedSnapshots = null;
        FilePublicationJournal? ownedJournal = null;
        P256PublicationAuthenticator? signer = null;
        P256PublicationAuthenticator? ownedVerifier = null;
        try
        {
            ownedSnapshots = new FileZoneSnapshotStore(Path.Combine(ownedRoot, "snapshots"));
            beforeJournal?.Invoke(ownedRoot);
            ownedJournal = new FilePublicationJournal(Path.Combine(ownedRoot, "proofs"));
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var scopes = new Dictionary<Guid, DnsName> { [control.Zone] = DnsName.Parse("example.") };
            signer = new P256PublicationAuthenticator(control.Epoch, ControlFixture.Node, scopes, key.ExportPkcs8PrivateKeyPem(), canSign: true);
            ownedVerifier = new P256PublicationAuthenticator(control.Epoch, ControlFixture.Node, scopes, key.ExportSubjectPublicKeyInfoPem(), canSign: false);
            return new ReplicaFixture(ownedRoot, control.Zone, ownedSnapshots, ownedJournal, signer, ownedVerifier);
        }
        catch (Exception original)
        {
            List<Exception> failures = [original];
            await CaptureRollbackAsync(async () =>
            {
                if (ownedSnapshots is not null) await ownedSnapshots.DisposeAsync().ConfigureAwait(true);
                afterSnapshotRollback?.Invoke(ownedRoot);
            }, failures).ConfigureAwait(true);
            await CaptureRollbackAsync(() => { ownedJournal?.Dispose(); return Task.CompletedTask; }, failures).ConfigureAwait(true);
            await CaptureRollbackAsync(() => { signer?.Dispose(); return Task.CompletedTask; }, failures).ConfigureAwait(true);
            await CaptureRollbackAsync(() => { ownedVerifier?.Dispose(); return Task.CompletedTask; }, failures).ConfigureAwait(true);
            // Retain the root if resource retirement could not be established.
            if (failures.Count == 1)
                await CaptureRollbackAsync(() => { Directory.Delete(ownedRoot, recursive: true); return Task.CompletedTask; }, failures).ConfigureAwait(true);
            if (failures.Count > 1) throw new AggregateException(failures);
            throw;
        }
    }

    private static async Task CaptureRollbackAsync(Func<Task> action, List<Exception> failures)
    {
        var error = await Xunit.Record.ExceptionAsync(action).ConfigureAwait(true);
        if (error is not null) failures.Add(error);
    }

    internal async Task OpenAsync() => Publication = await ZonePublicationApplication.OpenAsync(Store, journal, verifier, new ZoneBundleAdapter(), Authority, ControlFixture.Node, [zone], CancellationToken.None).ConfigureAwait(true);

    internal async Task OpenSignedAsync(TimeProvider time) => Publication = await ZonePublicationApplication.OpenAsync(Store, journal, verifier, new ZoneBundleAdapter(), Authority, ControlFixture.Node, [zone],
        new EcdsaP256DnssecVerifier(), time, CancellationToken.None).ConfigureAwait(true);

    public async ValueTask DisposeAsync()
    {
        if (Publication is not null)
            await Publication.DisposeAsync().ConfigureAwait(true);
        await Store.DisposeAsync().ConfigureAwait(true);
        journal.Dispose();
        Signer.Dispose();
        verifier.Dispose();
        Directory.Delete(root, recursive: true);
    }
}
