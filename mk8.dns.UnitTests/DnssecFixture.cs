using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.UnitTests;

internal static class DnssecFixture
{
    // Public, non-production RFC 6605 section 6.1 private-key example.
    internal const string Pkcs8 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mShRANCAAQaiMiGFdQ3+7i/nhlCoZKfKFYnBq5sK9OZ57G/ttHp51uStKpCkXrhxhtwHvA1w/574wCcuv5aL3ExbJAtzw0A";
    internal static DnsName Origin { get; } = DnsName.Parse("example.");
    internal static DnssecSignatureWindow Window { get; } = new(100, 10_000);
    internal static EcdsaP256DnssecVerifier Verifier { get; } = new();
    internal static EcdsaP256DnssecSigningKey Key() => EcdsaP256DnssecSigningKey.ImportPkcs8(Convert.FromBase64String(Pkcs8));
    internal static DnsRecord A(string name = "www.example.", byte last = 1, uint ttl = 300) => AuthorityFixture.Record(name, 1, [192, 0, 2, last], ttl);

    internal static byte[] Name(string name, bool upper = false)
    {
        var wire = DnsName.Parse(name).ToWire();
        if (upper)
            for (var index = 0; index < wire.Length; index++)
                if (wire[index] is >= (byte)'a' and <= (byte)'z')
                    wire[index] -= 32;
        return wire;
    }

    internal static ushort CoveredType(DnsRecord signature) => System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(signature.GetData());
    internal static int NameEnd(byte[] data)
    {
        var offset = 0;
        while (data[offset] != 0)
            offset += data[offset] + 1;
        return offset + 1;
    }

    internal sealed class CountingKey(IDnssecSigningKey inner) : IDnssecSigningKey
    {
        internal int Calls { get; private set; }
        internal Action? AfterSign { get; init; }
        internal bool CorruptSignature { get; init; }
        public byte Algorithm => inner.Algorithm;
        public byte[] GetPublicKey() => inner.GetPublicKey();
        public byte[] SignHash(ReadOnlySpan<byte> digest)
        {
            Calls++;
            var signature = inner.SignHash(digest);
            AfterSign?.Invoke();
            if (CorruptSignature)
                signature[0] ^= 1;
            return signature;
        }
    }
}
