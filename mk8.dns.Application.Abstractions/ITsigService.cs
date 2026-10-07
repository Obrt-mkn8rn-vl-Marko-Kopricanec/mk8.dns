namespace Mk8.Dns.Application.Abstractions;

public interface ITsigService
{
    bool IsAvailable { get; }
    ITsigTransaction? Open(ReadOnlySpan<byte> message, ReadOnlySpan<byte> peerAddress);
}
