using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IZoneMasterFileCodec
{
    AuthoritativeZone Import(DnsName origin, string text);
    string Export(AuthoritativeZone zone);
}
