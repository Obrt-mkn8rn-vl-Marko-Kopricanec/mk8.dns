using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class P384DnssecChainTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(4)]
    public void FullDigestAnchorAuthenticatesCompleteP384KeysetAndData(byte digest)
    {
        using var fixture = new P384DnssecFixture(); var validator = fixture.Validator();
        var anchor = new DnssecTrustAnchor(DnssecKeys.CreateDs(fixture.Key, 0, digest));
        Assert.True(validator.TryAuthenticateAnchor(anchor, [fixture.Key], [fixture.Sign([fixture.Key])], out var keys));
        var record = DnssecFixture.A();
        Assert.True(validator.TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record], [fixture.Sign([record])], out var ttl));
        Assert.Equal(300U, ttl);
    }

    [Theory]
    [InlineData(13, 14, 2)]
    [InlineData(13, 14, 4)]
    [InlineData(14, 13, 2)]
    [InlineData(14, 13, 4)]
    [InlineData(14, 14, 2)]
    [InlineData(14, 14, 4)]
    public void MixedEcdsaParentChildRequiresParentDsAndChildKeyset(byte parentAlgorithm, byte childAlgorithm, byte digest)
    {
        using var parent = new P384DnssecFixture(algorithm: parentAlgorithm); using var child = new P384DnssecFixture("child.example.", childAlgorithm);
        var validator = parent.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(parent.Key), [parent.Key], [parent.Sign([parent.Key])], out var trusted));
        var ds = DnssecKeys.CreateDs(child.Key, 300, digest);
        Assert.True(validator.TryAuthenticateChild(trusted!, child.Origin, [ds], [parent.Sign([ds])], [child.Key], [child.Sign([child.Key])], out var keys));
        var record = DnssecFixture.A("www.child.example.");
        Assert.True(validator.TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record], [child.Sign([record])], out _));
    }

    [Fact]
    public void RsaParentCanAuthenticateP384ChildThroughSha384Ds()
    {
        using var parent = new RsaDnssecFixture(); using var child = new P384DnssecFixture("child.example."); var validator = parent.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(parent.Key), [parent.Key], [parent.Sign([parent.Key])], out var trusted));
        var ds = DnssecKeys.CreateDs(child.Key, 300, 4);
        Assert.True(validator.TryAuthenticateChild(trusted!, child.Origin, [ds], [parent.Sign([ds])], [child.Key], [child.Sign([child.Key])], out _));
    }

    [Theory]
    [InlineData(13)]
    [InlineData(14)]
    public void CompletePinnedKeysetCanDelegateDataToAnIncludedZsk(byte algorithm)
    {
        using var csk = new P384DnssecFixture(); using var zsk = new P384DnssecFixture(algorithm: algorithm, sep: false);
        var validator = csk.Validator(); DnsRecord[] keyset = [csk.Key, zsk.Key];
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(csk.Key), keyset, [csk.Sign(keyset)], out var keys));
        var record = DnssecFixture.A();
        Assert.True(validator.TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record], [zsk.Sign([record])], out _));
        Assert.False(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(csk.Key), keyset, [zsk.Sign(keyset)], out _));
    }
}
