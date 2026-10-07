namespace Mk8.Dns.UnitTests;

internal sealed record TsigReply(byte[] Message, string Key, string Algorithm, ulong Time, ushort Fudge, byte[] Mac, ushort Id, ushort Error, byte[] Other, int RecordOffset);
