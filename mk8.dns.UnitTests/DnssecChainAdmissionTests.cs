using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecChainAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void InvalidAnchorShapesAndUnsupportedProfilesAreRejected(int selector)
    {
        using var fixture = new DnssecChainFixture();
        var data = fixture.ParentCskRecord.GetData();
        if (selector == 0) data[0] = 0;
        if (selector == 1) data[1] |= 128;
        if (selector == 2) data[2] = 2;
        if (selector == 3) data[3] = 14;
        var record = selector switch
        {
            4 => new DnsRecord(fixture.Parent, 43, 300, [0, 1, 13, 1, .. new byte[20]]),
            5 => fixture.ParentCskRecord.WithOwner(DnsName.Parse("*.example.")),
            _ => new DnsRecord(fixture.Parent, 48, 300, data),
        };
        Assert.ThrowsAny<ArgumentException>(() => new DnssecTrustAnchor(record));
    }

    [Fact]
    public void UnknownDsDigestDoesNotBecomeAnInsecureOrTrustedChild()
    {
        using var fixture = new DnssecChainFixture();
        var data = fixture.Delegation.GetData();
        data[3] = 253;
        var ds = new DnsRecord(fixture.Child, 43, 300, data);
        var signature = DnssecChainFixture.Sign([ds], fixture.ParentCskRecord, fixture.ParentCsk);
        Assert.False(fixture.Validator.TryAuthenticateChild(fixture.Trust(), fixture.Child, [ds], [signature], fixture.ChildRecords, [fixture.ChildSignature], out var keys));
        Assert.Null(keys);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void InvalidDnskeySetBoundsAndMembersFailBeforeCrypto(int selector)
    {
        using var fixture = new DnssecChainFixture();
        var provider = new DnssecChainFixture.CountingVerifier();
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        var records = selector switch
        {
            0 => Array.Empty<DnsRecord>(),
            1 => new DnsRecord[] { null! },
            2 => new[] { fixture.ParentCskRecord, fixture.ParentCskRecord },
            3 => new[] { fixture.ChildCskRecord },
            4 => new[] { new DnsRecord(fixture.Parent, 48, 300, [1, 0, 3]) },
            _ => Enumerable.Repeat(fixture.ParentCskRecord, 65).ToArray(),
        };
        Assert.False(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), records, [fixture.ParentSignature], out _));
        Assert.Equal(0, provider.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void UnrelatedQuestionsAndWholeRrsetTamperingCannotAuthenticate(int selector)
    {
        using var fixture = new DnssecChainFixture();
        var keys = fixture.Trust();
        DnsRecord[] records = [DnssecFixture.A(), DnssecFixture.A(last: 2)];
        var sig = DnssecChainFixture.Sign(records, fixture.ParentZskRecord, fixture.ParentZsk);
        var question = new DnsQuestion(records[0].Owner, 1, 1);
        if (selector == 0) question = question with { Name = DnsName.Parse("other.example.") };
        if (selector == 1) question = question with { Type = 28 };
        if (selector == 2) question = question with { Class = 3 };
        if (selector == 3) records = [records[0]];
        Assert.False(fixture.Validator.TryAuthenticateRrset(keys, question, records, [sig], out var ttl));
        Assert.Equal(0u, ttl);
    }

    [Fact]
    public void WildcardExpandedSignatureRequiresSeparateDenialProofAndIsNotAdmitted()
    {
        using var fixture = new DnssecChainFixture();
        var keys = fixture.Trust();
        var wildcard = DnssecFixture.A("*.example.");
        var sig = DnssecChainFixture.Sign([wildcard], fixture.ParentZskRecord, fixture.ParentZsk);
        var owner = DnsName.Parse("www.example.");
        var expanded = wildcard.WithOwner(owner);
        var expandedSig = sig.WithOwner(owner);
        Assert.True(DnssecRrsetVerifier.TryVerify([expanded], expandedSig, fixture.ParentZskRecord, 100, DnssecFixture.Verifier, out _));
        Assert.False(fixture.Validator.TryAuthenticateRrset(keys, new DnsQuestion(owner, 1, 1), [expanded], [expandedSig], out _));
    }

    [Fact]
    public void ChildApexDsAndNonApexDnskeyCannotClaimSelectedZoneAuthentication()
    {
        using var fixture = new DnssecChainFixture();
        var child = fixture.AuthenticateChild();
        var dsSignature = DnssecChainFixture.Sign([fixture.Delegation], fixture.ChildCskRecord, fixture.ChildCsk);
        Assert.False(fixture.Validator.TryAuthenticateRrset(child, new DnsQuestion(fixture.Child, 43, 1), [fixture.Delegation], [dsSignature], out _));
        var key = fixture.ChildCskRecord.WithOwner(DnsName.Parse("www.child.example."));
        var keySig = DnssecChainFixture.Sign([key], fixture.ChildCskRecord, fixture.ChildCsk);
        Assert.False(fixture.Validator.TryAuthenticateRrset(child, new DnsQuestion(key.Owner, 48, 1), [key], [keySig], out _));
    }

    [Fact]
    public void SignedSiblingDataCannotBeValidatedUnderAnotherChildContext()
    {
        using var fixture = new DnssecChainFixture();
        var child = fixture.AuthenticateChild();
        var data = DnssecFixture.A("www.sibling.example.");
        var signature = DnssecChainFixture.Sign([data], fixture.ParentCskRecord, fixture.ParentCsk);
        Assert.False(fixture.Validator.TryAuthenticateRrset(child, new DnsQuestion(data.Owner, 1, 1), [data], [signature], out _));
    }
}
