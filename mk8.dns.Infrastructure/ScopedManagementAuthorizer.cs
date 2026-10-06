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
        this.grants = grants.Take(65).Select(ManagementGrantPolicy.Freeze).ToArray();
        if (this.grants.Length is 0 or > 64
            || this.grants.GroupBy(grant => (grant.TenantId, grant.ZoneId, grant.Actor)).Any(group => group.Count() != 1)
            || this.grants.GroupBy(grant => (grant.TenantId, grant.ZoneId, Hash: Convert.ToHexString(grant.CredentialHash.Span))).Any(group => group.Count() != 1))
            throw new ArgumentException("Invalid scoped management grants.", nameof(grants));
        this.time = time;
    }

    public string Authorize(ManagementRequest request)
    {
        var grant = FindGrant(request);
        ManagementGrantPolicy.RequireRequest(grant, request);
        return grant.Actor;
    }

    public void AuthorizeOperation(ManagementRequest request, string operationActor)
    {
        var grant = FindGrant(request);
        ManagementGrantPolicy.RequireRequest(grant, request);
        if (!string.Equals(grant.Profile, "zone", StringComparison.Ordinal) && !string.Equals(grant.Actor, operationActor, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Management authorization failed.");
    }

    public void AuthorizeZone(ManagementRequest request, AuthoritativeZone zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        var grant = FindGrant(request);
        ManagementGrantPolicy.RequireRequest(grant, request);
        if (!zone.Origin.Equals(grant.Origin))
            throw new UnauthorizedAccessException("Management authorization failed.");
        if (grant.Profile is "acme")
            ManagementGrantPolicy.RequireChallengeAuthority(request, zone);
    }

    private ManagementGrant FindGrant(ManagementRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Credential is not { Length: 32 } || request.Origin is not { Length: > 0 and <= 255 })
            throw new UnauthorizedAccessException("Management authorization failed.");
        var origin = DnsName.FromWire(request.Origin.Span);
        var hash = SHA256.HashData(request.Credential.Span);
        var grant = grants.FirstOrDefault(item => item.TenantId == request.TenantId && item.ZoneId == request.ZoneId && item.Origin.Equals(origin)
            && item.Expires > time.GetUtcNow() && CryptographicOperations.FixedTimeEquals(item.CredentialHash.Span, hash));
        return grant ?? throw new UnauthorizedAccessException("Management authorization failed.");
    }
}
