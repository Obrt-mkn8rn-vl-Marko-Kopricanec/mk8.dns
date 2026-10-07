using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

internal sealed record RecursiveCacheResult(DnsAnswer Answer, long Received);
