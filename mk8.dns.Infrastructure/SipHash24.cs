using System.Buffers.Binary;
using System.Numerics;

namespace Mk8.Dns.Infrastructure;

internal static class SipHash24
{
    internal static ulong Hash(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key)
    {
        if (key.Length != 16)
            throw new ArgumentException("SipHash requires a 128-bit key.", nameof(key));
        var first = BinaryPrimitives.ReadUInt64LittleEndian(key);
        var second = BinaryPrimitives.ReadUInt64LittleEndian(key[8..]);
        var v0 = first ^ 0x736f6d6570736575UL;
        var v1 = second ^ 0x646f72616e646f6dUL;
        var v2 = first ^ 0x6c7967656e657261UL;
        var v3 = second ^ 0x7465646279746573UL;
        var offset = 0;
        while (input.Length - offset >= 8)
        {
            var word = BinaryPrimitives.ReadUInt64LittleEndian(input[offset..]);
            Compress(word, ref v0, ref v1, ref v2, ref v3);
            offset += 8;
        }
        var tail = (ulong)(input.Length & 255) << 56;
        for (var index = 0; offset + index < input.Length; index++)
            tail |= (ulong)input[offset + index] << (8 * index);
        Compress(tail, ref v0, ref v1, ref v2, ref v3);
        v2 ^= 255;
        for (var round = 0; round < 4; round++)
            Round(ref v0, ref v1, ref v2, ref v3);
        return v0 ^ v1 ^ v2 ^ v3;
    }

    private static void Compress(ulong word, ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
    {
        v3 ^= word;
        Round(ref v0, ref v1, ref v2, ref v3);
        Round(ref v0, ref v1, ref v2, ref v3);
        v0 ^= word;
    }

    private static void Round(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
    {
        unchecked
        {
            v0 += v1;
            v1 = BitOperations.RotateLeft(v1, 13) ^ v0;
            v0 = BitOperations.RotateLeft(v0, 32);
            v2 += v3;
            v3 = BitOperations.RotateLeft(v3, 16) ^ v2;
            v0 += v3;
            v3 = BitOperations.RotateLeft(v3, 21) ^ v0;
            v2 += v1;
            v1 = BitOperations.RotateLeft(v1, 17) ^ v2;
            v2 = BitOperations.RotateLeft(v2, 32);
        }
    }
}
