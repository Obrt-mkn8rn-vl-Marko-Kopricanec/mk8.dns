namespace Mk8.Dns.Application.Abstractions;

public interface IDnsCookieService
{
    bool IsAvailable { get; }
    byte[]? Create(ReadOnlySpan<byte> clientCookie, ReadOnlySpan<byte> peerAddress);
    bool Validate(ReadOnlySpan<byte> cookie, ReadOnlySpan<byte> peerAddress);
}
