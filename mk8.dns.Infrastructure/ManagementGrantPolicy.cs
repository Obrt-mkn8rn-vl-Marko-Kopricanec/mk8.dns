using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure;

internal static class ManagementGrantPolicy
{
    internal static ManagementGrant Freeze(ManagementGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        if (grant.TenantId == Guid.Empty || grant.ZoneId == Guid.Empty || grant.Origin is null
            || string.IsNullOrWhiteSpace(grant.Actor) || grant.Actor.Length > 128 || grant.CredentialHash.Length != 32
            || grant.Actions is not { Count: > 0 and <= 4 } || grant.RecordScopes is not { Count: <= 64 }
            || grant.Profile is not ("zone" or "records" or "acme"))
            throw new ArgumentException("Invalid scoped management grant.", nameof(grant));
        var actions = grant.Actions.ToArray();
        var scopes = grant.RecordScopes.ToArray();
        if (actions.Distinct(StringComparer.Ordinal).Count() != actions.Length || actions.Any(action => action is not ("edit" or "patch" or "read" or "status"))
            || grant.Profile is not "zone" && (actions.Contains("edit", StringComparer.Ordinal) || scopes.Length == 0)
            || grant.Profile is "zone" && scopes.Length != 0)
            throw new ArgumentException("Invalid management action or record scope.", nameof(grant));
        foreach (var scope in scopes)
        {
            if (scope is null || scope.Owner is null || !scope.Owner.IsSubdomainOf(grant.Origin) || scope.Type is 0 or 6 or 41 or (>= 249 and <= 255)
                || grant.Profile is "acme" && (scope.Type != 16 || !IsChallengeName(scope.Owner)))
                throw new ArgumentException("Invalid management record scope.", nameof(grant));
        }
        if (scopes.Distinct().Count() != scopes.Length)
            throw new ArgumentException("Duplicate management record scope.", nameof(grant));
        return grant with { CredentialHash = grant.CredentialHash.ToArray(), Actions = Array.AsReadOnly(actions), RecordScopes = Array.AsReadOnly(scopes) };
    }

    internal static void RequireRequest(ManagementGrant grant, ManagementRequest request)
    {
        if (!grant.Actions.Contains(request.Action, StringComparer.Ordinal))
            Deny();
        if (grant.Profile is "zone")
            return;
        if (request.Records is not { Count: 0 } || request.Changes is null || request.Selection is null)
            Deny();
        foreach (var key in request.Selection)
        {
            if (key is null)
                Deny();
            RequireKey(grant, key.Owner.Span, key.Type);
        }
        foreach (var change in request.Changes)
        {
            if (change is null)
                Deny();
            RequireKey(grant, change.Owner.Span, change.Type);
            if (grant.Profile is "acme")
                RequireChallenge(change);
        }
    }

    internal static void RequireChallengeAuthority(ManagementRequest request, AuthoritativeZone zone)
    {
        foreach (var wire in request.Selection.Select(key => key.Owner).Concat(request.Changes.Select(change => change.Owner)))
        {
            var name = DnsName.FromWire(wire.Span);
            if (zone.GetRecords(name).Any(record => record.Type == 5))
                Deny();
            for (var ancestor = name; ; ancestor = ancestor.Parent)
            {
                if (zone.GetRecords(ancestor).Any(record => record.Type == 39 || record.Type == 2 && !ancestor.Equals(zone.Origin)))
                    Deny();
                if (ancestor.Equals(zone.Origin))
                    break;
            }
        }
    }

    private static void RequireKey(ManagementGrant grant, ReadOnlySpan<byte> owner, ushort type)
    {
        var name = DnsName.FromWire(owner);
        if (!grant.RecordScopes.Any(scope => scope.Type == type && scope.Owner.Equals(name)))
            Deny();
    }

    private static void RequireChallenge(RrsetChange change)
    {
        if (change.Replace || change.Add is null || change.Remove is null || change.Add.Count + change.Remove.Count != 1 || change.Ttl is < 60 or > 3600)
            Deny();
        var value = change.Add.Count == 1 ? change.Add[0].Span : change.Remove[0].Span;
        if (value.Length != 44 || value[0] != 43)
            Deny();
        foreach (var octet in value[1..])
            if (octet is not (>= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_'))
                Deny();
        // SHA-256 has 256 bits: the final base64url sextet has two zero padding bits.
        if (!"AEIMQUYcgkosw048"u8.Contains(value[^1]))
            Deny();
    }

    private static bool IsChallengeName(DnsName name)
    {
        var wire = name.ToWire();
        return wire.AsSpan().StartsWith("\u000f_acme-challenge"u8) && !name.ToString().Contains('*', StringComparison.Ordinal);
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Deny() => throw new UnauthorizedAccessException("Management authorization failed.");
}
