using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecChainTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExplicitAnchorAuthenticatesCompleteKeysetAndItsZsk(bool dsAnchor)
    {
        using var fixture = new DnssecChainFixture();
        var keys = fixture.Trust(dsAnchor);
        Assert.Equal(fixture.Parent, keys.Origin);
        Assert.Equal(1, keys.Depth);
        Assert.Equal(2, keys.Records.Count);
        Assert.Equal(300u, fixture.Validator.GetRemainingTtl(keys));
        var data = DnssecFixture.A();
        var signature = DnssecChainFixture.Sign([data], fixture.ParentZskRecord, fixture.ParentZsk);
        Assert.True(fixture.Validator.TryAuthenticateRrset(keys, new DnsQuestion(data.Owner, 1, 1), [data], [signature], out var ttl));
        Assert.Equal(300u, ttl);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnchorMatchAloneDoesNotTrustAnUnrelatedKeysetSignature(bool dsAnchor)
    {
        using var fixture = new DnssecChainFixture();
        var anchor = new DnssecTrustAnchor(dsAnchor ? DnssecKeys.CreateDs(fixture.ParentCskRecord, 300) : fixture.ParentCskRecord);
        var untrusted = DnssecChainFixture.Sign(fixture.ParentRecords, fixture.ParentZskRecord, fixture.ParentZsk);
        Assert.False(fixture.Validator.TryAuthenticateAnchor(anchor, fixture.ParentRecords, [untrusted], out var keys));
        Assert.Null(keys);
    }

    [Fact]
    public void AuthenticatedParentDsAndMatchedChildSignatureEstablishChildZskTrust()
    {
        using var fixture = new DnssecChainFixture();
        var keys = fixture.AuthenticateChild();
        Assert.Equal(fixture.Child, keys.Origin);
        Assert.Equal(2, keys.Depth);
        var data = DnssecFixture.A("www.child.example.");
        var signature = DnssecChainFixture.Sign([data], fixture.ChildZskRecord, fixture.ChildZsk);
        Assert.True(fixture.Validator.TryAuthenticateRrset(keys, new DnsQuestion(data.Owner, 1, 1), [data], [signature], out var ttl));
        Assert.Equal(300u, ttl);
    }

    [Fact]
    public void ChildKeysetCannotAuthenticateItselfUsingAnUnmatchedIncludedZsk()
    {
        using var fixture = new DnssecChainFixture();
        var untrusted = DnssecChainFixture.Sign(fixture.ChildRecords, fixture.ChildZskRecord, fixture.ChildZsk);
        Assert.False(fixture.Validator.TryAuthenticateChild(fixture.Trust(), fixture.Child, [fixture.Delegation], [fixture.DelegationSignature],
            fixture.ChildRecords, [untrusted], out var keys));
        Assert.Null(keys);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(35)]
    public void SignedDsWithAlteredTagOrDigestCannotEstablishChildTrust(int offset)
    {
        using var fixture = new DnssecChainFixture();
        var data = fixture.Delegation.GetData();
        data[offset] ^= 1;
        var altered = new DnsRecord(fixture.Child, 43, 300, data);
        var validParentSignature = DnssecChainFixture.Sign([altered], fixture.ParentZskRecord, fixture.ParentZsk);
        Assert.False(fixture.Validator.TryAuthenticateChild(fixture.Trust(), fixture.Child, [altered], [validParentSignature],
            fixture.ChildRecords, [fixture.ChildSignature], out var keys));
        Assert.Null(keys);
    }

    [Fact]
    public void ChildSideDsSignatureCannotReplaceParentSideAuthentication()
    {
        using var fixture = new DnssecChainFixture();
        var childSignature = DnssecChainFixture.Sign([fixture.Delegation], fixture.ChildCskRecord, fixture.ChildCsk);
        Assert.False(fixture.Validator.TryAuthenticateChild(fixture.Trust(), fixture.Child, [fixture.Delegation], [childSignature],
            fixture.ChildRecords, [fixture.ChildSignature], out _));
    }

    [Fact]
    public void MultipleDsRecordsPermitOneSupportedMatchingPathWithoutRequiringSepBit()
    {
        using var fixture = new DnssecChainFixture();
        var unsupported = new DnsRecord(fixture.Child, 43, 300, [0, 1, 13, 1, .. new byte[20]]);
        var match = DnssecKeys.CreateDs(fixture.ChildZskRecord, 300);
        var ds = new[] { fixture.Delegation, unsupported, match };
        var signature = DnssecChainFixture.Sign(ds, fixture.ParentCskRecord, fixture.ParentCsk);
        var childSignature = DnssecChainFixture.Sign(fixture.ChildRecords, fixture.ChildZskRecord, fixture.ChildZsk);
        Assert.True(fixture.Validator.TryAuthenticateChild(fixture.Trust(), fixture.Child, ds, [signature], fixture.ChildRecords, [childSignature], out var keys));
        Assert.NotNull(keys);
    }

    [Fact]
    public void UnknownAndUnusableDnskeysCanBeAuthenticatedButCannotSignData()
    {
        using var fixture = new DnssecChainFixture();
        var nonZoneData = fixture.ParentZskRecord.GetData();
        nonZoneData[0] = 0;
        var nonZone = new DnsRecord(fixture.Parent, 48, 300, nonZoneData);
        var unknown = new DnsRecord(fixture.Parent, 48, 300, [1, 0, 3, 253, 1]);
        var records = new[] { fixture.ParentCskRecord, nonZone, unknown };
        var sig = DnssecChainFixture.Sign(records, fixture.ParentCskRecord, fixture.ParentCsk);
        Assert.True(fixture.Validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), records, [sig], out var keys));
        Assert.Equal(3, keys.Records.Count);
        var data = DnssecFixture.A();
        var dataSig = DnssecChainFixture.Sign([data], fixture.ParentZskRecord, fixture.ParentZsk);
        Assert.False(fixture.Validator.TryAuthenticateRrset(keys, new DnsQuestion(data.Owner, 1, 1), [data], [dataSig], out _));
    }

    [Theory]
    [InlineData("example.")]
    [InlineData("outside.")]
    [InlineData("*.example.")]
    public void ChildMustBeAStrictNonWildcardDescendantOfSelectedParent(string child)
    {
        using var fixture = new DnssecChainFixture();
        Assert.False(fixture.Validator.TryAuthenticateChild(fixture.Trust(), DnsName.Parse(child), [fixture.Delegation], [fixture.DelegationSignature],
            fixture.ChildRecords, [fixture.ChildSignature], out _));
    }

    [Fact]
    public void KeysetsCannotCrossValidatorOrTrustProfileContexts()
    {
        using var fixture = new DnssecChainFixture();
        var keys = fixture.Trust();
        var other = new DnssecChainValidator(DnssecFixture.Verifier, fixture.Clock);
        Assert.Equal(0u, other.GetRemainingTtl(keys));
        Assert.False(other.TryAuthenticateChild(keys, fixture.Child, [fixture.Delegation], [fixture.DelegationSignature], fixture.ChildRecords, [fixture.ChildSignature], out _));
        var data = DnssecFixture.A();
        var sig = DnssecChainFixture.Sign([data], fixture.ParentCskRecord, fixture.ParentCsk);
        Assert.False(other.TryAuthenticateRrset(keys, new DnsQuestion(data.Owner, 1, 1), [data], [sig], out _));
    }

    [Fact]
    public void MutableInputCollectionsAndReturnedDataCannotChangeAuthenticatedEvidence()
    {
        using var fixture = new DnssecChainFixture();
        var records = fixture.ParentRecords.ToArray();
        Assert.True(fixture.Validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), records, [fixture.ParentSignature], out var keys));
        records[0] = fixture.ChildCskRecord;
        var changed = keys.Records[0].GetData();
        changed[4] ^= 1;
        Assert.Equal(fixture.ParentCskRecord.GetData(), keys.Records[0].GetData());
        Assert.True(keys.Records is System.Collections.ObjectModel.ReadOnlyCollection<DnsRecord>);
    }

    [Fact]
    public void CompleteKeysetMembersAreRequiredAndAlternativeSignaturesAreBounded()
    {
        using var fixture = new DnssecChainFixture();
        var anchor = new DnssecTrustAnchor(fixture.ParentCskRecord);
        Assert.False(fixture.Validator.TryAuthenticateAnchor(anchor, [fixture.ParentCskRecord], [fixture.ParentSignature], out _));
        var data = fixture.ParentSignature.GetData();
        data[^1] ^= 1;
        var bad = new DnsRecord(fixture.Parent, 46, 300, data);
        Assert.True(fixture.Validator.TryAuthenticateAnchor(anchor, fixture.ParentRecords, [bad, fixture.ParentSignature], out _));
        Assert.False(fixture.Validator.TryAuthenticateAnchor(anchor, fixture.ParentRecords, Enumerable.Repeat(fixture.ParentSignature, 17).ToArray(), out _));
    }

    [Fact]
    public void ThreeLevelRootToChildHierarchyAuthenticatesItsFinalAnswer()
    {
        using var fixture = new DnssecChainFixture();
        using var rootPrivate = EcdsaP256DnssecSigningKey.Create();
        var rootRecord = DnssecKeys.CreateDnskey(DnsName.Parse("."), 300, rootPrivate.GetPublicKey());
        var rootSig = DnssecChainFixture.Sign([rootRecord], rootRecord, rootPrivate);
        Assert.True(fixture.Validator.TryAuthenticateAnchor(new DnssecTrustAnchor(rootRecord), [rootRecord], [rootSig], out var root));
        var ds = DnssecKeys.CreateDs(fixture.ParentCskRecord, 300);
        var dsSig = DnssecChainFixture.Sign([ds], rootRecord, rootPrivate);
        Assert.True(fixture.Validator.TryAuthenticateChild(root, fixture.Parent, [ds], [dsSig], fixture.ParentRecords, [fixture.ParentSignature], out var parent));
        var child = fixture.AuthenticateChild(parent);
        Assert.Equal(3, child.Depth);
        var data = DnssecFixture.A("www.child.example.");
        var signature = DnssecChainFixture.Sign([data], fixture.ChildZskRecord, fixture.ChildZsk);
        Assert.True(fixture.Validator.TryAuthenticateRrset(child, new DnsQuestion(data.Owner, 1, 1), [data], [signature], out _));
    }
}
