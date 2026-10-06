using System.Buffers.Binary;

namespace Mk8.Dns.Domain;

public sealed class DnsRecord
{
    private readonly byte[] data;
    private readonly byte[] ownerWire;

    public DnsRecord(ReadOnlySpan<byte> ownerWire, ushort type, uint ttl, ReadOnlySpan<byte> data)
        : this(DnsName.FromWire(ownerWire), type, ttl, data)
    {
        this.ownerWire = ownerWire.ToArray();
    }

    public DnsRecord(DnsName owner, ushort type, uint ttl, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(owner);
        if (type is 0 or 41 or (>= 249 and <= 255))
            throw new ArgumentOutOfRangeException(nameof(type), "Invalid stored Internet-class record.");
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ttl, (uint)int.MaxValue);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(data.Length, ushort.MaxValue, nameof(data));
        ValidateData(type, data);
        Owner = owner;
        ownerWire = owner.ToWire();
        Type = type;
        Ttl = ttl;
        this.data = data.ToArray();
    }

    public DnsName Owner { get; }
    public ushort Type { get; }
    public uint Ttl { get; }
    public byte[] GetData() => (byte[])data.Clone();
    public byte[] GetOwnerWire() => (byte[])ownerWire.Clone();

    public byte[] GetCanonicalData()
    {
        var copy = GetData();
        var offset = Type == 15 ? 2 : Type == 33 ? 6 : Type is 64 or 65 ? 2 : 0;
        var names = Type == 6 ? 2 : Type is 2 or 5 or 12 or 15 or 33 or 39 or 64 or 65 ? 1 : 0;
        for (var index = 0; index < names; index++)
        {
            while (copy[offset] != 0)
            {
                var length = copy[offset++];
                for (var octet = 0; octet < length; octet++, offset++)
                    if (copy[offset] is >= (byte)'A' and <= (byte)'Z')
                        copy[offset] += 32;
            }
            offset++;
        }
        return copy;
    }
    public DnsRecord WithOwner(DnsName owner) => new(owner, Type, Ttl, data);
    public DnsRecord WithTtl(uint ttl) => new(ownerWire, Type, ttl, data);

    public DnsName GetTarget()
    {
        if (Type is not (2 or 5 or 12 or 39))
            throw new InvalidOperationException("This record has no single name target.");
        return DnsName.FromWire(data);
    }

    public uint GetSoaSerial()
    {
        if (Type != 6)
            throw new InvalidOperationException("This record is not SOA.");
        return BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(data.Length - 20));
    }

    public uint GetSoaMinimum()
    {
        if (Type != 6)
            throw new InvalidOperationException("This record is not SOA.");
        return BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(data.Length - 4));
    }

    private static void ValidateData(ushort type, ReadOnlySpan<byte> value)
    {
        var offset = 0;
        switch (type)
        {
            case 1:
                Require(value.Length == 4);
                return;
            case 28:
                Require(value.Length == 16);
                return;
            case 43:
                Require(value.Length > 4 && value[2] != 0);
                Require(value[3] switch { 1 => value.Length == 24, 2 => value.Length == 36, 4 => value.Length == 52, _ => true });
                return;
            case 2 or 5 or 12 or 39:
                ReadName(value, ref offset);
                break;
            case 6:
                ReadName(value, ref offset);
                ReadName(value, ref offset);
                Require(value.Length - offset == 20);
                return;
            case 15:
                Require(value.Length >= 3);
                offset = 2;
                ReadName(value, ref offset);
                break;
            case 33:
                Require(value.Length >= 7);
                offset = 6;
                ReadName(value, ref offset);
                break;
            case 16:
                ValidateText(value);
                return;
            case 64 or 65:
                ValidateServiceBinding(value);
                return;
            default:
                // Unknown RDATA is opaque. Name compression is forbidden in stored data.
                return;
        }
        Require(offset == value.Length);
    }

    private static void ValidateText(ReadOnlySpan<byte> value)
    {
        Require(!value.IsEmpty);
        var offset = 0;
        while (offset < value.Length)
        {
            var length = value[offset++];
            Require(length <= value.Length - offset);
            offset += length;
        }
    }

    private static void ValidateServiceBinding(ReadOnlySpan<byte> value)
    {
        Require(value.Length >= 3);
        var priority = BinaryPrimitives.ReadUInt16BigEndian(value);
        var offset = 2;
        var targetStart = offset;
        ReadName(value, ref offset);
        if (priority == 0)
        {
            Require(value[targetStart] != 0 && offset == value.Length);
            return;
        }
        var lastKey = -1;
        HashSet<ushort> keys = [];
        List<ushort> mandatory = [];
        while (offset < value.Length)
        {
            Require(offset + 4 <= value.Length);
            var key = BinaryPrimitives.ReadUInt16BigEndian(value[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(value[(offset + 2)..]);
            offset += 4;
            Require(key > lastKey && length <= value.Length - offset);
            var parameter = value.Slice(offset, length);
            keys.Add(key);
            ValidateServiceParameter(key, parameter, mandatory);
            lastKey = key;
            offset += length;
        }
        Require(mandatory.All(keys.Contains) && (!keys.Contains(2) || keys.Contains(1)));
    }

    private static void ValidateServiceParameter(ushort key, ReadOnlySpan<byte> parameter, List<ushort> mandatory)
    {
        var length = parameter.Length;
        switch (key)
        {
            case 0:
                Require(length > 0 && length % 2 == 0);
                ushort lastMandatory = 0;
                for (var position = 0; position < length; position += 2)
                {
                    var required = BinaryPrimitives.ReadUInt16BigEndian(parameter[position..]);
                    Require(required > lastMandatory);
                    mandatory.Add(required);
                    lastMandatory = required;
                }
                break;
            case 1:
                Require(length > 0);
                for (var position = 0; position < length;)
                {
                    var size = parameter[position++];
                    Require(size != 0 && size <= length - position);
                    position += size;
                }
                break;
            case 2:
                Require(length == 0);
                break;
            case 3:
                Require(length == 2);
                break;
            case 4:
                Require(length > 0 && length % 4 == 0);
                break;
            case 6:
                Require(length > 0 && length % 16 == 0);
                break;
        }
    }

    private static void ReadName(ReadOnlySpan<byte> value, ref int offset)
    {
        var start = offset;
        while (true)
        {
            Require(offset < value.Length);
            var length = value[offset++];
            Require(length <= 63 && length <= value.Length - offset);
            offset += length;
            if (length == 0)
                break;
        }
        _ = DnsName.FromWire(value[start..offset]);
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Invalid uncompressed record data.");
    }
}
