using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RsaDnssecChainTests
{
    [Fact]
    public void RsaAuthenticatedCompleteKeysetMayDelegateDataSigningToEcdsaZsk()
    {
        using var fixture = new RsaDnssecFixture(); using var ecdsa = DnssecFixture.Key();
        var zsk = DnssecKeys.CreateDnskey(fixture.Origin, 300, ecdsa.GetPublicKey(), secureEntryPoint: false);
        DnsRecord[] records = [fixture.Key, zsk]; var validator = fixture.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), records, [fixture.Sign(records)], out var keys));
        var record = DnssecFixture.A();
        Assert.True(validator.TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record],
            [DnssecRrsetSigner.Sign([record], zsk, ecdsa, RsaDnssecFixture.Verifier, DnssecFixture.Window)], out _));
    }

    [Fact]
    public void IncludedRogueRsaKeyCannotAuthenticateWholeKeysetWithoutPinnedKey()
    {
        using var trusted = new RsaDnssecFixture(); using var rogue = new RsaDnssecFixture();
        DnsRecord[] records = [trusted.Key, rogue.Key]; var validator = trusted.Validator();
        Assert.False(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(trusted.Key), records, [rogue.Sign(records)], out _));
        Assert.False(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(DnssecKeys.CreateDs(trusted.Key, 0)), records, [rogue.Sign(records)], out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RsaChildCannotBypassParentDsOrCompleteChildKeysetAuthentication(bool corruptDs)
    {
        using var parent = new RsaDnssecFixture(); using var child = new RsaDnssecFixture(origin: "child.example.");
        var validator = parent.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(parent.Key), [parent.Key], [parent.Sign([parent.Key])], out var keys));
        var ds = DnssecKeys.CreateDs(child.Key, 300); var dsSignature = parent.Sign([ds]); var keySignature = child.Sign([child.Key]);
        var signature = corruptDs ? dsSignature : keySignature; var bytes = signature.GetData(); bytes[^1] ^= 1;
        var bad = new DnsRecord(signature.Owner, 46, 300, bytes);
        Assert.False(validator.TryAuthenticateChild(keys!, child.Origin, [ds], [corruptDs ? bad : dsSignature],
            [child.Key], [corruptDs ? keySignature : bad], out _));
    }

    [Fact]
    public void RsaKeyLeaseAndDataProofRemainCreatorBoundAndExpireAfterProviderWork()
    {
        using var fixture = new RsaDnssecFixture();
        var record = DnssecFixture.A(); var signature = fixture.Sign([record]);
        var verifier = new DelayingVerifier { After = () => fixture.Clock.Advance(301) };
        var validator = new DnssecChainValidator(verifier, fixture.Clock);
        Assert.False(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key], [fixture.Sign([fixture.Key])], out _));
        fixture.Clock.SetMonotonic(0); fixture.Clock.SetWall(100); var first = fixture.Validator();
        Assert.True(first.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key], [fixture.Sign([fixture.Key])], out var keys));
        Assert.False(fixture.Validator().TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record], [signature], out _));
        fixture.Clock.Advance(301);
        Assert.False(first.TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record], [signature], out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(300)]
    public void RsaDataAuthenticatesAtReceivedTtlWithoutCreatingZeroKeyLease(int ttl)
    {
        using var fixture = new RsaDnssecFixture(); var validator = fixture.Validator();
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key], [fixture.Sign([fixture.Key])], out var keys));
        var record = DnssecFixture.A().WithTtl((uint)ttl);
        Assert.True(validator.TryAuthenticateRrset(keys!, new DnsQuestion(record.Owner, 1, 1), [record], [fixture.Sign([record])], out var lease));
        Assert.Equal((uint)ttl, lease);
        Assert.False(fixture.Validator().TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [fixture.Key.WithTtl(0)],
            [fixture.Sign([fixture.Key])], out _));
    }

    private sealed class DelayingVerifier : IDnssecSignatureVerifier
    {
        internal Action? After { get; init; }
        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        { var result = RsaDnssecFixture.Verifier.VerifyHash(algorithm, publicKey, digest, signature); After?.Invoke(); return result; }
    }
}
