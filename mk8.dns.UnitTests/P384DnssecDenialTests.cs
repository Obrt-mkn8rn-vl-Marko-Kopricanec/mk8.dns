using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class P384DnssecDenialTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void P384AuthenticatesNsecAndNsec3ExactNegativeResponses(bool nsec3, bool nameError)
    {
        using var fixture = new P384DnssecFixture(); var validator = fixture.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key], [fixture.Sign([fixture.Key])], out var keys));
        var soa = AuthorityFixture.Zone().Soa; var question = NsecValidationFixture.Question(nameError ? "new.example." : "www.example.", nameError ? (ushort)1 : (ushort)28);
        var denial = nsec3 ? Nsec3ValidationFixture.Ring() : nameError
            ? [OnlineDnssecFixture.Nsec(fixture.Origin, DnsName.Parse("www.example."), 2, 6, 48)]
            : new[] { OnlineDnssecFixture.Nsec(question.Name, fixture.Origin, 1) };
        var signatures = denial.Prepend(soa).Select(record => fixture.Sign([record])).ToArray();
        var valid = nsec3 ? nameError
                ? validator.TryAuthenticateNsec3NameError(keys!, question, [soa], denial, signatures, out _)
                : validator.TryAuthenticateNsec3NoData(keys!, question, [soa], denial, signatures, out _)
            : nameError ? validator.TryAuthenticateNameError(keys!, question, [soa], denial, signatures, out _)
                : validator.TryAuthenticateNoData(keys!, question, [soa], denial, signatures, out _);
        Assert.True(valid);
    }

    [Fact]
    public void P384ExpandedWildcardNeedsItsNsec3NextCloserProof()
    {
        using var fixture = new P384DnssecFixture(); var validator = fixture.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key], [fixture.Sign([fixture.Key])], out var keys));
        var original = DnssecFixture.A("*.example."); var question = NsecValidationFixture.Question("new.example."); var denial = Nsec3ValidationFixture.Ring(wildcard: true);
        var signatures = new[] { fixture.Sign([original]).WithOwner(question.Name) }.Concat(denial.Select(record => fixture.Sign([record]))).ToArray();
        Assert.True(validator.TryAuthenticateNsec3Wildcard(keys!, question, [original.WithOwner(question.Name)], denial, signatures, out _));
        Assert.False(validator.TryAuthenticateNsec3Wildcard(keys!, question, [original.WithOwner(question.Name)], [], signatures, out _));
    }
}
