using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class P384DnssecLifetimeTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(300)]
    public void DataMayAuthenticateAtZeroTtlButKeyLeaseMustBePositive(uint ttl)
    {
        using var fixture = new P384DnssecFixture(); var validator = fixture.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key], [fixture.Sign([fixture.Key])], out var keys));
        var record = DnssecFixture.A().WithTtl(ttl);
        Assert.True(validator.TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record], [fixture.Sign([record])], out var lease));
        Assert.Equal(ttl, lease);
        Assert.False(fixture.Validator().TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key.WithTtl(0)], [fixture.Sign([fixture.Key])], out _));
    }

    [Fact]
    public void P384KeyContextRetainsCreatorExpiryAndNonrevivalFences()
    {
        using var fixture = new P384DnssecFixture(); var validator = fixture.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key], [fixture.Sign([fixture.Key])], out var keys));
        var record = DnssecFixture.A(); var signatures = new[] { fixture.Sign([record]) }; var question = new DnsQuestion(record.Owner, 1, 1);
        Assert.False(fixture.Validator().TryAuthenticateRrset(keys!, question, [record], signatures, out _));
        fixture.Clock.Advance(301); Assert.False(validator.TryAuthenticateRrset(keys!, question, [record], signatures, out _));
        fixture.Clock.SetMonotonic(0); fixture.Clock.SetWall(100); Assert.False(validator.TryAuthenticateRrset(keys!, question, [record], signatures, out _));
    }
}
