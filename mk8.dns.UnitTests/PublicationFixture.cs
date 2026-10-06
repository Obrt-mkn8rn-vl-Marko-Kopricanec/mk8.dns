using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;

namespace Mk8.Dns.UnitTests;

internal sealed class PublicationFixture : IAsyncDisposable
{
    internal static readonly Guid ZoneId = Guid.Parse("21e850b9-fdf2-4e7e-a5d6-bbd03e6d913e");
    internal static readonly Guid Epoch = Guid.Parse("6e15cfe4-2e70-40d5-aaf6-a73f5049c5cc");
    internal const string Node = "publication-test";
    internal string Root { get; }
    internal FileZoneSnapshotStore Store { get; }
    internal FilePublicationJournal Journal { get; }
    internal P256PublicationAuthenticator Signer { get; }
    internal P256PublicationAuthenticator Verifier { get; }
    internal string PublicKey { get; }
    internal AuthoritativeApplication Authority { get; }

    internal PublicationFixture(Func<CancellationToken, ValueTask>? beforePointer = null)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        Root = Path.Combine(Path.GetTempPath(), "m8pub-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Store = new FileZoneSnapshotStore(Path.Combine(Root, "state"), beforePointer);
        Journal = new FilePublicationJournal(Path.Combine(Root, "proofs"));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PublicKey = key.ExportSubjectPublicKeyInfoPem();
        var scopes = new Dictionary<Guid, DnsName> { [ZoneId] = DnsName.Parse("example.") };
        Signer = new P256PublicationAuthenticator(Epoch, Node, scopes, key.ExportPkcs8PrivateKeyPem(), canSign: true);
        Verifier = new P256PublicationAuthenticator(Epoch, Node, scopes, PublicKey, canSign: false);
        Authority = new AuthoritativeApplication(new DnsMessageCodecAdapter(), Node);
    }

    internal ValueTask<ZonePublicationApplication> OpenAsync() => ZonePublicationApplication.OpenAsync(Store, Journal, Verifier, new ZoneBundleAdapter(), Authority, Node, [ZoneId], CancellationToken.None);

    internal static ZoneSnapshot Snapshot(long revision, uint serial, byte address = 1)
    {
        var zone = AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, address]));
        var data = zone.Soa.GetData();
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(data.Length - 20), serial);
        zone = new AuthoritativeZone(zone.Origin, zone.GetAllRecords().Select(record => record.Type == 6 ? new DnsRecord(record.Owner, 6, record.Ttl, data) : record));
        return ZoneBundleCodec.Compile(ZoneId, revision, zone);
    }

    internal PublicationRequest Prepare(ZoneSnapshot snapshot)
    {
        var body = Signer.CreateBody(snapshot);
        return new PublicationRequest("prepare", body, Signer.Sign(body), Convert.ToHexStringLower(SHA256.HashData(body)));
    }

    internal PublicationRequest Activate(string id) => new("activate", ReadOnlyMemory<byte>.Empty, Signer.SignActivation(id), id);

    public async ValueTask DisposeAsync()
    {
        await Store.DisposeAsync().ConfigureAwait(true);
        Journal.Dispose();
        Signer.Dispose();
        Verifier.Dispose();
        Directory.Delete(Root, recursive: true);
    }
}
