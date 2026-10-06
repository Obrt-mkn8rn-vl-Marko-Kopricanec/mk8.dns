namespace Mk8.Dns.Contracts;

public sealed record ApplicationStatus(uint ProtocolVersion, string NodeId, string Role, bool DnsReady, uint ActiveSnapshots);
