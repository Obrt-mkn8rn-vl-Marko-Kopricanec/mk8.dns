using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public sealed record UpstreamResponse(DnsAnswer Answer, bool Truncated);
