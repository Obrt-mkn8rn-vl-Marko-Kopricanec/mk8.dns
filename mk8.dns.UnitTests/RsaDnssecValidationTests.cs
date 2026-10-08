using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RsaDnssecValidationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RsaDnskeyOrCompleteSha256DsPinAuthenticatesKeysetAndOrdinaryData(bool ds)
    {
        using var fixture = new RsaDnssecFixture();
        var validator = fixture.Validator();
        var anchor = new DnssecTrustAnchor(ds ? DnssecKeys.CreateDs(fixture.Key, 0) : fixture.Key);
        Assert.True(validator.TryAuthenticateAnchor(anchor, [fixture.Key], [fixture.Sign([fixture.Key])], out var keys));
        var record = DnssecFixture.A();
        Assert.True(validator.TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record], [fixture.Sign([record])], out var ttl));
        Assert.Equal(300U, ttl);
    }

    [Theory]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(4096)]
    public void MathematicalRrsetVerificationAcceptsBoundedRsaKeySizes(int bits)
    {
        using var fixture = new RsaDnssecFixture(bits);
        var record = DnssecFixture.A();
        Assert.True(DnssecRrsetVerifier.TryVerify([record], fixture.Sign([record]), fixture.Key, 100, RsaDnssecFixture.Verifier, out _));
    }

    [Fact]
    public void ParentRsaCanAuthenticateEcdsaChildAndItsData()
    {
        using var parent = new RsaDnssecFixture(); using var child = new DnssecChainFixture();
        var validator = parent.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(parent.Key), [parent.Key], [parent.Sign([parent.Key])], out var parentKeys));
        var ds = DnssecKeys.CreateDs(child.ChildCskRecord, 300);
        Assert.True(validator.TryAuthenticateChild(parentKeys!, child.Child, [ds], [parent.Sign([ds])], child.ChildRecords, [child.ChildSignature], out var childKeys));
        var record = DnssecFixture.A("www.child.example.");
        Assert.True(validator.TryAuthenticateRrset(childKeys!, new DnsQuestion(record.Owner, 1, 1), [record],
            [DnssecChainFixture.Sign([record], child.ChildZskRecord, child.ChildZsk)], out _));
    }

    [Fact]
    public void ParentEcdsaCanAuthenticateRsaChildAndItsData()
    {
        using var parent = new DnssecChainFixture(); using var child = new RsaDnssecFixture(origin: "child.example.");
        var validator = new DnssecChainValidator(RsaDnssecFixture.Verifier, parent.Clock);
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(parent.ParentCskRecord), parent.ParentRecords, [parent.ParentSignature], out var parentKeys));
        var ds = DnssecKeys.CreateDs(child.Key, 300);
        Assert.True(validator.TryAuthenticateChild(parentKeys!, child.Origin, [ds], [DnssecChainFixture.Sign([ds], parent.ParentZskRecord, parent.ParentZsk)],
            [child.Key], [child.Sign([child.Key])], out var childKeys));
        var record = DnssecFixture.A("www.child.example.");
        Assert.True(validator.TryAuthenticateRrset(childKeys!, new DnsQuestion(record.Owner, 1, 1), [record], [child.Sign([record])], out _));
    }
}
