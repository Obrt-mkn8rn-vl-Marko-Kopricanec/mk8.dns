namespace Mk8.Dns.Wire;

internal readonly record struct MasterFileEntry(IReadOnlyList<MasterFileToken> Tokens, bool ReuseOwner);
