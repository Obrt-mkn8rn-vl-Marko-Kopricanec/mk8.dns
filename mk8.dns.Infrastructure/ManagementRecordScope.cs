using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure;

public sealed record ManagementRecordScope(DnsName Owner, ushort Type);
