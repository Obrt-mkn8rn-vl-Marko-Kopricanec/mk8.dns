using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure;

public sealed class ScopedManagementAuthorizer : IManagementAuthorizer
{
    private readonly ManagementGrant[] grants;
    private readonly TimeProvider time;

    public ScopedManagementAuthorizer(IEnumerable<ManagementGrant> grants, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(time);
        this.grants = grants.Select(grant => grant with { CredentialHash = grant.CredentialHash.ToArray() }).Take(65).ToArray();
        if (this.grants.Length is 0 or > 64 || this.grants.Any(grant => grant.TenantId == Guid.Empty || grant.ZoneId == Guid.Empty || string.IsNullOrWhiteSpace(grant.Actor) || grant.Actor.Length > 128 || grant.CredentialHash.Length != 32))
            throw new ArgumentException("Invalid scoped management grants.", nameof(grants));
        this.time = time;
    }

    public string Authorize(ManagementRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Credential is not { Length: 32 } || request.Origin is not { Length: > 0 and <= 255 })
            throw new UnauthorizedAccessException("Management authorization failed.");
        var origin = DnsName.FromWire(request.Origin.Span);
        var hash = SHA256.HashData(request.Credential.Span);
        var grant = grants.FirstOrDefault(item => item.TenantId == request.TenantId && item.ZoneId == request.ZoneId && item.Origin.Equals(origin)
            && item.Expires > time.GetUtcNow() && CryptographicOperations.FixedTimeEquals(item.CredentialHash.Span, hash));
        return grant?.Actor ?? throw new UnauthorizedAccessException("Management authorization failed.");
    }
}
