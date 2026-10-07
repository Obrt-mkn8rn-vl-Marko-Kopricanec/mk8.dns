using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NsecAdmissionTests
{
    [Fact]
    public void ModifiedProofOrSoaSignatureCannotAuthenticateDenial()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        var sigs = fixture.SignAll([proof]);
        foreach (var index in new[] { 0, 1 })
        {
            var modified = sigs.ToArray();
            var bytes = modified[index].GetData();
            bytes[^1] ^= 1;
            modified[index] = new DnsRecord(modified[index].Owner, 46, 300, bytes);
            Assert.False(fixture.NoData("a.example.", 28, [proof], out _, modified));
        }
    }

    [Fact]
    public void RequiredProofCannotBeReplacedWithAnUnsignedHint()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        Assert.False(fixture.NoData("a.example.", 28, [proof], out _, [fixture.Sign(fixture.Soa)]));
    }

    [Fact]
    public void RequiredSoaCannotBeOmitted()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        Assert.False(fixture.Validator.TryAuthenticateNoData(fixture.Keys, NsecValidationFixture.Question("a.example.", 28), [], [proof], fixture.SignAll([proof]), out _));
    }

    [Fact]
    public void KeysetFromAnotherValidatorCannotAuthorizeDenial()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        var validator = new DnssecChainValidator(DnssecFixture.Verifier, fixture.Clock);
        Assert.False(validator.TryAuthenticateNoData(fixture.Keys, NsecValidationFixture.Question("a.example.", 28), [fixture.Soa], [proof], fixture.SignAll([proof]), out _));
    }

    [Theory]
    [InlineData("a.other.", "z.example.")]
    [InlineData("a.example.", "z.other.")]
    [InlineData("z.example.", "a.example.")]
    [InlineData("a.example.", "a.example.")]
    public void OutOfZoneAndInvalidCircularEdgesAreRejected(string owner, string next)
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec(owner, next, 1);
        var provider = new DnssecChainFixture.CountingVerifier();
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        var keys = fixture.TrustWith(validator);
        var signature = proof.Owner.IsSubdomainOf(fixture.Soa.Owner) ? fixture.Sign(proof)
            : fixture.Sign(proof.WithOwner(DnsName.Parse("a.example."))).WithOwner(proof.Owner);
        provider.Reset();
        Assert.False(validator.TryAuthenticateNoData(keys, NsecValidationFixture.Question("a.example.", 28),
            [fixture.Soa], [proof], [fixture.Sign(fixture.Soa), signature], out _));
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public void ConflictingIntervalsCannotEraseAnAuthenticatedEndpoint()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.NoData("b.example.", 28, [fixture.Nsec("a.example.", "z.example.", 1), fixture.Nsec("b.example.", "z.example.", 1)], out _));
    }

    [Fact]
    public void AOneNodeRingCannotBeCombinedWithAnotherNode()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.NameError("b.example.", [fixture.Nsec("example.", "example.", 6), fixture.Nsec("a.example.", "z.example.", 1)], out _));
    }

    [Fact]
    public void DuplicateOwnerAndExcessProofsFailBeforeCrypto()
    {
        using var fixture = new NsecValidationFixture();
        var provider = new DnssecChainFixture.CountingVerifier();
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        var keys = fixture.TrustWith(validator);
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        var signatures = fixture.SignAll([proof]);
        provider.Reset();
        foreach (var count in new[] { 2, 9 })
            Assert.False(validator.TryAuthenticateNoData(keys, NsecValidationFixture.Question("a.example.", 28), [fixture.Soa], Enumerable.Repeat(proof, count).ToArray(), signatures, out _));
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public void NullMalformedAndWrongTypeProofsFailBeforeCrypto()
    {
        using var fixture = new NsecValidationFixture();
        var signatures = new[] { fixture.Sign(fixture.Soa) };
        foreach (var proof in new[] { null, new DnsRecord(DnsName.Parse("a.example."), 47, 300, [0xc0, 0]), new DnsRecord(DnsName.Parse("a.example."), 47, 300, [0]), DnssecFixture.A("a.example.") })
            Assert.False(fixture.Validator.TryAuthenticateNoData(fixture.Keys, NsecValidationFixture.Question("a.example.", 28), [fixture.Soa], [proof!], signatures, out _));
    }

    [Fact]
    public void UnsupportedClassesTypesAndOutOfZoneQuestionsAreRefused()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        foreach (var question in new[] { new DnsQuestion(proof.Owner, 28, 3), new DnsQuestion(proof.Owner, 255, 1), new DnsQuestion(proof.Owner, 41, 1), new DnsQuestion(DnsName.Parse("outside."), 28, 1), new DnsQuestion(null!, 28, 1) })
            Assert.False(fixture.Validator.TryAuthenticateNoData(fixture.Keys, question, [fixture.Soa], [proof], fixture.SignAll([proof]), out _));
    }

    [Fact]
    public void AlreadyAuthenticatedSoaAndKeysCannotBeDeclaredAbsent()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("example.", "a.example.", 2);
        Assert.False(fixture.NoData("example.", 6, [proof], out _));
        Assert.False(fixture.NoData("example.", 48, [proof], out _));
    }

    [Fact]
    public void MixedCaseNextNameIsVerifiedAsOriginalRdata()
    {
        using var fixture = new NsecValidationFixture();
        var proof = new DnsRecord(DnsName.Parse("a.example."), 47, 300, [.. DnssecFixture.Name("z.example.", upper: true), .. NsecBitmap.Encode([1, 46, 47])]);
        Assert.True(fixture.NoData("A.EXAMPLE.", 28, [proof], out _));
    }

    [Fact]
    public void ExcessSignatureCollectionsFailBeforeCrypto()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        Assert.False(fixture.NoData("a.example.", 28, [proof], out _, Enumerable.Repeat(fixture.Sign(proof), 17).ToArray()));
    }
}
