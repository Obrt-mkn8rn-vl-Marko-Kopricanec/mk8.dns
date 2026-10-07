using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Infrastructure;

public sealed class ZoneMasterFileAdapter : IZoneMasterFileCodec
{
    public AuthoritativeZone Import(DnsName origin, string text) => ZoneMasterFileCodec.Import(origin, text);
    public string Export(AuthoritativeZone zone) => ZoneMasterFileCodec.Export(zone);
}
