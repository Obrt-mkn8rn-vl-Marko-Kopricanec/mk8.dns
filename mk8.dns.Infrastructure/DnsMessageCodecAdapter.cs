using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Infrastructure;

public sealed class DnsMessageCodecAdapter : IDnsMessageCodec
{
    public DnsQuery Decode(ReadOnlySpan<byte> message) => DnsMessageCodec.DecodeQuery(message);
    public byte[] Encode(DnsQuery query, DnsAnswer answer, bool tcp) => DnsMessageCodec.EncodeResponse(query, answer, tcp);
    public byte[] EncodeError(ReadOnlySpan<byte> message, byte code) => DnsMessageCodec.EncodeError(message, code);
}
