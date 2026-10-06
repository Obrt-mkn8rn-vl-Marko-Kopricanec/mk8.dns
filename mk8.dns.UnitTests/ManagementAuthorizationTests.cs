using System.Security.Cryptography;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ManagementAuthorizationTests
{
    [Theory]
    [InlineData("tenant")]
    [InlineData("zone")]
    [InlineData("origin")]
    [InlineData("credential")]
    [InlineData("expired")]
    public void GrantsRequireEveryScopeAndUnexpiredCredential(string changed)
    {
        var tenant = Guid.NewGuid();
        var zone = Guid.NewGuid();
        var credential = RandomNumberGenerator.GetBytes(32);
        var expiration = string.Equals(changed, "expired", StringComparison.Ordinal) ? DateTimeOffset.UtcNow.AddHours(-1) : DateTimeOffset.UtcNow.AddHours(1);
        var grant = new ManagementGrant(tenant, zone, DnsName.Parse("example."), "test-actor", expiration, SHA256.HashData(credential));
        var authorizer = new ScopedManagementAuthorizer([grant], TimeProvider.System);
        var request = new ManagementRequest("edit", string.Equals(changed, "tenant", StringComparison.Ordinal) ? Guid.NewGuid() : tenant,
            string.Equals(changed, "zone", StringComparison.Ordinal) ? Guid.NewGuid() : zone, Guid.NewGuid(), 0,
            DnsName.Parse(string.Equals(changed, "origin", StringComparison.Ordinal) ? "elsewhere." : "example.").ToWire(), Array.Empty<ZoneRecordData>(),
            string.Equals(changed, "credential", StringComparison.Ordinal) ? new byte[32] : credential);
        _ = Assert.Throws<UnauthorizedAccessException>(() => authorizer.Authorize(request));
    }

    [Fact]
    public void GrantsPinCredentialHashAndAcceptCanonicalOriginCasing()
    {
        var tenant = Guid.NewGuid();
        var zone = Guid.NewGuid();
        var credential = RandomNumberGenerator.GetBytes(32);
        var hash = SHA256.HashData(credential);
        var authorizer = new ScopedManagementAuthorizer([new ManagementGrant(tenant, zone, DnsName.Parse("example."), "test-actor", DateTimeOffset.UtcNow.AddHours(1), hash)], TimeProvider.System);
        Array.Clear(hash);
        var request = new ManagementRequest("status", tenant, zone, Guid.NewGuid(), 0, DnsName.Parse("EXAMPLE.").ToWire(), Array.Empty<ZoneRecordData>(), credential);
        Assert.Equal("test-actor", authorizer.Authorize(request));
    }
}
