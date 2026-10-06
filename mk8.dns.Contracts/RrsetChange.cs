namespace Mk8.Dns.Contracts;

public sealed record RrsetChange(ReadOnlyMemory<byte> Owner, ushort Type, uint Ttl, IReadOnlyList<ReadOnlyMemory<byte>> Add, IReadOnlyList<ReadOnlyMemory<byte>> Remove, bool Replace);
