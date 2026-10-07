using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IDnsMessageCodec
{
    DnsQuery Decode(ReadOnlySpan<byte> message);
    byte[] Encode(DnsQuery query, DnsAnswer answer, bool tcp);
    byte[] Encode(DnsQuery query, DnsAnswer answer, bool tcp, ReadOnlySpan<byte> cookie, ushort udpLimit);
    byte[] EncodeError(ReadOnlySpan<byte> message, byte code);
}
