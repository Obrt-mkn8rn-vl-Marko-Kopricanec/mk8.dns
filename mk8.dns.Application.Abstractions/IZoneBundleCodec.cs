using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IZoneBundleCodec
{
    ZoneSnapshot Compile(Guid zoneId, long revision, AuthoritativeZone zone);
    AuthoritativeZone Decode(ZoneSnapshot snapshot);
    ZoneSnapshot CompileIntent(Guid zoneId, long revision, AuthoritativeZone zone) => Compile(zoneId, revision, zone);
    ZoneContents DecodeContents(ZoneSnapshot snapshot) => new(Decode(snapshot));
}
