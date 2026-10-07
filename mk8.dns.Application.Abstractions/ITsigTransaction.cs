using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface ITsigTransaction : IDisposable
{
    ushort TsigError { get; }
    ushort SignatureBytes { get; }
    bool PeerAllowed { get; }
    byte[] GetRequest();
    bool Authorizes(DnsName origin);
    byte[] Complete(ReadOnlySpan<byte> response);
}
