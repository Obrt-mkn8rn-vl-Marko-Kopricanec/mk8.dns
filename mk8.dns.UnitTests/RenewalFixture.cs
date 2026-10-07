using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure;

namespace Mk8.Dns.UnitTests;

internal sealed class RenewalFixture(IDnssecSigningKey key, uint issued = 1000) : IZoneResigningStore, IZoneResigningTransaction, IDisposable
{
    internal Guid Tenant { get; } = Guid.NewGuid();
    internal Guid Zone { get; } = Guid.NewGuid();
    internal SignedAuthorityFixture.Clock Time { get; } = new() { Seconds = issued };
    internal ZoneBundleAdapter Codec { get; private set; } = null!;
    internal ZoneSnapshot? Current { get; set; }
    internal ZoneOperation? Operation { get; set; }
    internal IReadOnlyList<ZoneOwnership> Ownership { get; set; } = [];
    internal bool Pending { get; set; }
    internal bool CommitFails { get; set; }
    internal bool Disposed { get; private set; }
    internal int Commits { get; private set; }
    internal ZoneOperation? Staged { get; private set; }
    internal const string Node = "renewal-test";

    internal void Initialize()
    {
        Codec = SignedAuthorityFixture.Codec(key, Time);
        Current = Codec.Compile(Zone, 1, AuthorityFixture.Zone(DnssecFixture.A()));
        Operation = new ZoneOperation(Tenant, Guid.NewGuid(), "initial", "original", Node, Current, Activated: true);
        Ownership = [new ZoneOwnership(Tenant, Zone, DnssecFixture.Origin)];
        Time.Seconds = unchecked(issued + 2800);
    }

    internal ZoneResigningApplication Application(IZoneBundleCodec? codec = null, IDnssecSignatureVerifier? verifier = null, uint? margin = null)
        => new(this, codec ?? Codec, verifier ?? DnssecFixture.Verifier, Time, Node, [new DnssecRenewalScope(Zone, DnssecFixture.Origin, 3600, margin)]);

    public ValueTask<IZoneResigningTransaction> BeginAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Disposed = false;
        Staged = null;
        return ValueTask.FromResult<IZoneResigningTransaction>(this);
    }

    public ValueTask<IReadOnlyList<ZoneOwnership>> ReadOwnershipAsync(CancellationToken cancellationToken) => ValueTask.FromResult(Ownership);
    public ValueTask<ZoneSnapshot?> ReadZoneAsync(Guid tenantId, Guid zoneId, CancellationToken cancellationToken) => ValueTask.FromResult(Current);
    public ValueTask<ZoneOperation?> ReadGenerationAsync(Guid tenantId, Guid zoneId, long revision, CancellationToken cancellationToken) => ValueTask.FromResult(Operation);
    public ValueTask<bool> HasPendingAsync(Guid zoneId, CancellationToken cancellationToken) => ValueTask.FromResult(Pending);
    public ValueTask<ZoneOperation?> ReadOperationAsync(Guid tenantId, Guid operationId, CancellationToken cancellationToken) => throw new NotSupportedException();
    public ValueTask AppendAsync(ZoneOperation operation, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Staged = operation;
        return ValueTask.CompletedTask;
    }

    public ValueTask CommitAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (CommitFails)
            throw new InvalidOperationException("Deterministic commit failure.");
        Current = Staged!.Snapshot;
        Operation = Staged;
        Commits++;
        return ValueTask.CompletedTask;
    }

    public void Dispose() => Disposed = true;

    public ValueTask DisposeAsync()
    {
        Disposed = true;
        return ValueTask.CompletedTask;
    }

    internal sealed class AlteredCodec(IZoneBundleCodec original, Func<ZoneSnapshot, ZoneSnapshot> change) : IZoneBundleCodec
    {
        public ZoneSnapshot Compile(Guid zoneId, long revision, AuthoritativeZone zone) => change(original.Compile(zoneId, revision, zone));
        public ZoneSnapshot CompileIntent(Guid zoneId, long revision, AuthoritativeZone zone) => original.CompileIntent(zoneId, revision, zone);
        public AuthoritativeZone Decode(ZoneSnapshot snapshot) => original.Decode(snapshot);
        public ZoneContents DecodeContents(ZoneSnapshot snapshot) => original.DecodeContents(snapshot);
    }

    internal sealed class CountingVerifier(IDnssecSignatureVerifier inner) : IDnssecSignatureVerifier
    {
        internal int Calls { get; private set; }
        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        {
            Calls++;
            return inner.VerifyHash(algorithm, publicKey, digest, signature);
        }
    }
}
