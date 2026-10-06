using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Infrastructure;

public sealed class ZoneBundleAdapter : IZoneBundleCodec
{
    public ZoneSnapshot Compile(Guid zoneId, long revision, AuthoritativeZone zone) => ZoneBundleCodec.Compile(zoneId, revision, zone);
    public AuthoritativeZone Decode(ZoneSnapshot snapshot) => ZoneBundleCodec.Decode(snapshot);
}
