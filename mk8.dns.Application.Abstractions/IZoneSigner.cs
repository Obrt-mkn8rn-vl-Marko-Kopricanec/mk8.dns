using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IZoneSigner
{
    ZoneContents Sign(AuthoritativeZone zone);
}
