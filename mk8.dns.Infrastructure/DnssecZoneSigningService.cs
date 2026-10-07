using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Infrastructure;

public sealed class DnssecZoneSigningService : IZoneSigner
{
    private readonly Dictionary<DnsName, DnssecSigningPolicy> policies;
    private readonly IDnssecSignatureVerifier verifier;
    private readonly TimeProvider time;

    public DnssecZoneSigningService(IReadOnlyDictionary<DnsName, DnssecSigningPolicy> policies, IDnssecSignatureVerifier verifier, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(time);
        if (policies.Count is 0 or > 64 || policies.Values.Any(policy => policy.Key is null || policy.Key.Algorithm != 13
            || policy.LifetimeSeconds is < 3600 or > 2_592_000 || policy.DnskeyTtl > int.MaxValue))
            throw new ArgumentException("Invalid static DNSSEC signing policy.", nameof(policies));
        this.policies = new Dictionary<DnsName, DnssecSigningPolicy>(policies);
        this.verifier = verifier;
        this.time = time;
    }

    public ZoneContents Sign(AuthoritativeZone zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        if (!policies.TryGetValue(zone.Origin, out var policy))
            return new ZoneContents(zone);
        DnssecServingProfile.ValidateSource(zone);
        SignedZoneAdmission.ValidateCapacity(zone, DnssecKeys.CreateDnskey(zone.Origin, policy.DnskeyTtl, policy.Key.GetPublicKey()));
        var now = unchecked((uint)time.GetUtcNow().ToUnixTimeSeconds());
        var window = new DnssecSignatureWindow(unchecked(now - 300), unchecked(now + policy.LifetimeSeconds));
        var signed = NsecZoneSigner.Sign(zone, policy.Key, verifier, window, policy.DnskeyTtl);
        var contents = new ZoneContents(zone, signed.GetAllRecords().Where(record => record.Type is 46 or 47 or 48));
        _ = SignedZoneAdmission.Verify(contents, now, verifier);
        return contents;
    }
}
