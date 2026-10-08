using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

internal sealed class Nsec3Proof
{
    private Nsec3Proof(DnsRecord record, byte[] owner, byte[] next, byte[] salt, ushort[] types, bool optOut)
    {
        Record = record;
        Owner = owner;
        Next = next;
        Salt = salt;
        Types = types;
        OptOut = optOut;
    }

    internal DnsRecord Record { get; }
    internal byte[] Owner { get; }
    internal byte[] Next { get; }
    internal byte[] Salt { get; }
    internal ushort[] Types { get; }
    internal bool OptOut { get; }
    internal bool Delegation => Types.Contains((ushort)2) && !Types.Contains((ushort)6);

    internal static Nsec3Proof Decode(DnsRecord record, DnsName origin)
    {
        DnssecData.Require(record.Type == 50 && record.Owner.Parent.Equals(origin));
        var wire = record.Owner.ToWire();
        DnssecData.Require(wire[0] == 32);
        var owner = DecodeOwner(wire.AsSpan(1, 32));
        var data = record.GetData();
        // RFC 9276 permits refusing nonzero iterations. No insecure fallback.
        DnssecData.Require(data.Length >= 26 && data[0] == 1 && data[1] <= 1 && data[2] == 0 && data[3] == 0);
        var saltLength = data[4];
        var nextOffset = 6 + saltLength;
        DnssecData.Require(nextOffset + 20 <= data.Length && data[5 + saltLength] == 20);
        var types = nextOffset + 20 == data.Length ? [] : NsecBitmap.Decode(data.AsSpan(nextOffset + 20));
        return new Nsec3Proof(record, owner, data.AsSpan(nextOffset, 20).ToArray(), data.AsSpan(5, saltLength).ToArray(), types, data[1] == 1);
    }

    internal bool Matches(ReadOnlySpan<byte> hash) => hash.SequenceEqual(Owner);
    internal bool Covers(ReadOnlySpan<byte> hash)
    {
        if (Matches(hash) || hash.SequenceEqual(Next)) return false;
        return Owner.AsSpan().SequenceCompareTo(Next) < 0
            ? Owner.AsSpan().SequenceCompareTo(hash) < 0 && hash.SequenceCompareTo(Next) < 0
            : Owner.AsSpan().SequenceCompareTo(hash) < 0 || hash.SequenceCompareTo(Next) < 0 || Owner.AsSpan().SequenceEqual(Next);
    }

    // Unlike NSEC, NSEC3's bitmap describes the ORIGINAL name. Neither NSEC3
    // nor RRSIG is implicitly present; an empty bitmap denotes an empty name.
    internal bool Lacks(ushort type) => !Types.Contains(type) && !Types.Contains((ushort)5);

    private static byte[] DecodeOwner(ReadOnlySpan<byte> label)
    {
        var result = new byte[20];
        var buffer = 0;
        var bits = 0;
        var index = 0;
        foreach (ref readonly var octet in label)
        {
            var value = octet switch { >= (byte)'0' and <= (byte)'9' => octet - '0', >= (byte)'a' and <= (byte)'v' => octet - 'a' + 10, _ => -1 };
            DnssecData.Require(value >= 0);
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits < 8) continue;
            bits -= 8;
            result[index++] = (byte)(buffer >> bits);
        }
        return result;
    }
}
