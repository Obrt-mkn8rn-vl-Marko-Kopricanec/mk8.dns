namespace Mk8.Dns.Domain;

public sealed record DnsQuestion(DnsName Name, ushort Type, ushort Class);
