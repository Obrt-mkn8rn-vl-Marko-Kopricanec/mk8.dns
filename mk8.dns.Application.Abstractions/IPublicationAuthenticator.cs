using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IPublicationAuthenticator
{
    byte[] CreateBody(ZoneSnapshot snapshot);
    byte[] Sign(ReadOnlySpan<byte> body);
    ZoneSnapshot Verify(ReadOnlySpan<byte> body, ReadOnlySpan<byte> signature);
    byte[] SignActivation(string publicationId);
    void VerifyActivation(string publicationId, ReadOnlySpan<byte> signature);
}
