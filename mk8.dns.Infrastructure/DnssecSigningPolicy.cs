using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure;

public sealed record DnssecSigningPolicy(IDnssecSigningKey Key, uint LifetimeSeconds = 604_800, uint DnskeyTtl = 3600);
