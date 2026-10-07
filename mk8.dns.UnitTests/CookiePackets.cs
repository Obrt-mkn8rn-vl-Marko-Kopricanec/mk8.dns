using System.Buffers.Binary;

namespace Mk8.Dns.UnitTests;

internal static class CookiePackets
{
    internal static byte[] Query(byte[]? cookie, bool prefetch = false, ushort size = 1232, byte version = 0, ushort type = 16, byte[]? second = null)
    {
        var basis = AuthorityFixture.Query(type: type, edns: size, version: version);
        if (prefetch)
        {
            basis = basis[..12].Concat(basis[^11..]).ToArray();
            basis[5] = 0;
        }
        var options = cookie is null ? Array.Empty<byte>() : Option(cookie);
        if (second is not null)
            options = options.Concat(Option(second)).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(basis.AsSpan(basis.Length - 2), (ushort)options.Length);
        return basis.Concat(options).ToArray();
    }

    private static byte[] Option(byte[] cookie)
    {
        var result = new byte[cookie.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(result, 10);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), (ushort)cookie.Length);
        cookie.CopyTo(result, 4);
        return result;
    }

    internal static byte[] ResponseCookie(byte[] response)
    {
        Xunit.Assert.Equal(new byte[] { 0, 10, 0, 24 }, response[^28..^24]);
        return response[^24..];
    }

    internal static int ResponseCode(byte[] response) => (response[3] & 15) + (response[^34] << 4);
}
