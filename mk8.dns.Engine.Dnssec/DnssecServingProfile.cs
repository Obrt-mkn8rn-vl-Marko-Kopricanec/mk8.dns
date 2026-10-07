using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public static class DnssecServingProfile
{
    public static void ValidateSource(AuthoritativeZone source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (DnssecData.IsWildcard(source.Origin)
            || source.GetAllRecords().Any(record => record.Type == 2 && !record.Owner.Equals(source.Origin) && DnssecData.IsWildcard(record.Owner)))
            throw new FormatException("The signed serving profile excludes literal wildcard apices and wildcard delegations.");
    }
}
