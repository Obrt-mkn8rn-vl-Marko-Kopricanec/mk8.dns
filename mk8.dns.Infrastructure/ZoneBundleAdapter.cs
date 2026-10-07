using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Infrastructure;

public sealed class ZoneBundleAdapter : IZoneBundleCodec
{
    private readonly IZoneSigner? signer;

    public ZoneBundleAdapter() { }
    public ZoneBundleAdapter(IZoneSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        this.signer = signer;
    }

    public ZoneSnapshot Compile(Guid zoneId, long revision, AuthoritativeZone zone) => signer is null ? CompileIntent(zoneId, revision, zone)
        : SignedZoneBundleCodec.Compile(zoneId, revision, signer.Sign(zone));
    public ZoneSnapshot CompileIntent(Guid zoneId, long revision, AuthoritativeZone zone) => ZoneBundleCodec.Compile(zoneId, revision, zone);
    public AuthoritativeZone Decode(ZoneSnapshot snapshot) => DecodeContents(snapshot).Source;
    public ZoneContents DecodeContents(ZoneSnapshot snapshot) => SignedZoneBundleCodec.Decode(snapshot);
}
