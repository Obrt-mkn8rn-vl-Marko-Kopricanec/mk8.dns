using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

public sealed class DnssecRenewalScope
{
    public DnssecRenewalScope(Guid zoneId, DnsName origin, uint lifetimeSeconds, uint? renewBeforeSeconds = null)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (zoneId == Guid.Empty)
            throw new ArgumentException("A renewal zone identity is required.", nameof(zoneId));
        if (lifetimeSeconds is < 3600 or > 2_592_000)
            throw new ArgumentOutOfRangeException(nameof(lifetimeSeconds));
        var margin = renewBeforeSeconds ?? lifetimeSeconds / 4;
        if (margin < 60 || margin > lifetimeSeconds - 60)
            throw new ArgumentOutOfRangeException(nameof(renewBeforeSeconds));
        ZoneId = zoneId;
        Origin = origin;
        LifetimeSeconds = lifetimeSeconds;
        RenewBeforeSeconds = margin;
    }

    public Guid ZoneId { get; }
    public DnsName Origin { get; }
    public uint LifetimeSeconds { get; }
    public uint RenewBeforeSeconds { get; }
}
