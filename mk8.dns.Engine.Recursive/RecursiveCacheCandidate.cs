using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

internal sealed record RecursiveCacheCandidate(DnsAnswer Answer, bool NameWide, uint Lifetime, long PayloadBytes);
