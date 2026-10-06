namespace Mk8.Dns.Contracts;

public sealed record ZoneRecordData(ReadOnlyMemory<byte> Owner, ushort Type, uint Ttl, ReadOnlyMemory<byte> Data);
