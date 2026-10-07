namespace Mk8.Dns.Application.Abstractions;

public interface IDnsResponseLimiter
{
    bool TryAdmit(ReadOnlySpan<byte> peerAddress, int responseBytes);
}
