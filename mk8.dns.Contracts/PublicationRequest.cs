namespace Mk8.Dns.Contracts;

public sealed record PublicationRequest(string Action, ReadOnlyMemory<byte> Body, ReadOnlyMemory<byte> Signature, string PublicationId);
