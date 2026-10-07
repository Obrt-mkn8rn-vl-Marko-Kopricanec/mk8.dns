using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Configuration;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;

namespace Mk8.Dns.Application;

internal static class TsigKeys
{
    internal static TsigService Load(ApplicationSettings settings)
    {
        if (settings.TsigKeyFile is null)
            return new TsigService([], TimeProvider.System);
        var bytes = PrivateFile.Read(settings.TsigKeyFile, 32_768);
        List<TsigKey> keys = [];
        try
        {
            var offset = 0;
            if (ReadByte(bytes, ref offset) != 1)
                throw new InvalidDataException("TSIG keys require version one.");
            var count = ReadCount(bytes, ref offset);
            for (var index = 0; index < count; index++)
                keys.Add(ReadKey(bytes, ref offset));
            if (offset != bytes.Length)
                throw new InvalidDataException("Trailing TSIG key configuration.");
            return new TsigService(keys, TimeProvider.System);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            foreach (var key in keys)
                key.Dispose();
        }
    }

    private static TsigKey ReadKey(ReadOnlySpan<byte> bytes, ref int offset)
    {
        var name = ReadName(bytes, ref offset);
        var minimum = ReadByte(bytes, ref offset);
        var length = ReadByte(bytes, ref offset);
        var secret = Read(bytes, ref offset, length).ToArray();
        try
        {
            List<DnsName> zones = [];
            var count = ReadCount(bytes, ref offset);
            for (var index = 0; index < count; index++)
                zones.Add(ReadName(bytes, ref offset));
            List<byte[]> peers = [];
            count = ReadCount(bytes, ref offset);
            for (var index = 0; index < count; index++)
            {
                var size = ReadByte(bytes, ref offset);
                if (size is not (4 or 16))
                    throw new InvalidDataException("TSIG peers require exact IPv4 or IPv6 addresses.");
                peers.Add(Read(bytes, ref offset, size).ToArray());
            }
            return new TsigKey(name, secret, zones, peers, minimum);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static DnsName ReadName(ReadOnlySpan<byte> bytes, ref int offset)
    {
        var length = BinaryPrimitives.ReadUInt16BigEndian(Read(bytes, ref offset, 2));
        return DnsName.FromWire(Read(bytes, ref offset, length));
    }

    private static byte ReadByte(ReadOnlySpan<byte> bytes, ref int offset) => Read(bytes, ref offset, 1)[0];
    private static byte ReadCount(ReadOnlySpan<byte> bytes, ref int offset)
    {
        var value = ReadByte(bytes, ref offset);
        if (value is 0 or > 16)
            throw new InvalidDataException("TSIG scope counts must be between one and sixteen.");
        return value;
    }
    private static ReadOnlySpan<byte> Read(ReadOnlySpan<byte> bytes, ref int offset, int size)
    {
        if (size > bytes.Length - offset)
            throw new InvalidDataException("Incomplete TSIG key configuration.");
        var value = bytes.Slice(offset, size);
        offset += size;
        return value;
    }
}
