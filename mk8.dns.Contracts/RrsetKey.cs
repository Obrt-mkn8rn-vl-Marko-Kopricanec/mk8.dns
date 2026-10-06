namespace Mk8.Dns.Contracts;

public sealed record RrsetKey(ReadOnlyMemory<byte> Owner, ushort Type);
