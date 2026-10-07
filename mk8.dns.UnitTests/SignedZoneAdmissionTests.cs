using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SignedZoneAdmissionTests
{
    [Fact]
    public void BundleRoundTripRetainsCompleteSignedDataAndUnsignedIntent()
    {
        var source = AuthorityFixture.Zone(DnssecFixture.A());
        var contents = SignedAuthorityFixture.Contents(source);
        var snapshot = SignedZoneBundleCodec.Compile(Guid.NewGuid(), 3, contents);
        Assert.Equal("M8Z2"u8.ToArray(), snapshot.GetPayload()[..4]);
        var decoded = SignedZoneBundleCodec.Decode(snapshot);
        var verified = SignedZoneAdmission.Verify(decoded, 1000, DnssecFixture.Verifier);
        Assert.True(verified.IsAvailable(1000));
        Assert.Equal(contents.GetAllRecords().Count, decoded.GetAllRecords().Count);
        Assert.Equal(ZoneBundleCodec.Compile(snapshot.ZoneId, 3, source).ContentHash, new ZoneBundleAdapter().CompileIntent(snapshot.ZoneId, 3, decoded.Source).ContentHash);
        Assert.Throws<FormatException>(() => ZoneBundleCodec.Decode(snapshot));
    }

    [Theory]
    [InlineData(46)]
    [InlineData(47)]
    [InlineData(48)]
    public void MissingOrDuplicateSecurityMaterialIsRejected(ushort type)
    {
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.Zone(DnssecFixture.A()));
        var item = contents.GetSecurityRecords().First(record => record.Type == type);
        var missing = new ZoneContents(contents.Source, contents.GetSecurityRecords().Where(record => !ReferenceEquals(record, item)));
        var duplicate = new ZoneContents(contents.Source, contents.GetSecurityRecords().Append(item));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(missing, 1000, DnssecFixture.Verifier));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(duplicate, 1000, DnssecFixture.Verifier));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(12)]
    [InlineData(16)]
    [InlineData(40)]
    public void MutatedSignatureFieldsOrMacCannotEnterTheCatalog(int index)
    {
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.Zone(DnssecFixture.A()));
        var original = contents.GetSecurityRecords().First(record => record.Type == 46);
        var data = original.GetData();
        data[index] ^= 1;
        var altered = SignedAuthorityFixture.Replace(contents, original, new DnsRecord(original.Owner, 46, original.Ttl, data));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(altered, 1000, DnssecFixture.Verifier));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(12)]
    public void UnsupportedOrChangedDnskeyIsRejected(int index)
    {
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.Zone(DnssecFixture.A()));
        var original = contents.GetSecurityRecords().Single(record => record.Type == 48);
        var data = original.GetData();
        data[index] ^= 1;
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(SignedAuthorityFixture.Replace(contents, original,
            new DnsRecord(original.Owner, 48, original.Ttl, data)), 1000, DnssecFixture.Verifier));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void CryptographicallyValidButWrongDenialCircleOrBitmapIsRejected(bool changeNext)
    {
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.Zone(DnssecFixture.A()));
        var nsec = contents.GetSecurityRecords().First(record => record.Type == 47);
        var data = nsec.GetData();
        var end = DnssecFixture.NameEnd(data);
        byte[] changed = changeNext ? [.. DnssecFixture.Name("wrong.example."), .. data.AsSpan(end)]
            : [.. data.AsSpan(0, end), .. NsecBitmap.Encode([47, 46, 2])];
        var replacement = new DnsRecord(nsec.Owner, 47, nsec.Ttl, changed);
        using var key = DnssecFixture.Key();
        var dnskey = contents.GetSecurityRecords().Single(record => record.Type == 48);
        var signature = DnssecRrsetSigner.Sign([replacement], dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
        Assert.True(DnssecRrsetVerifier.TryVerify([replacement], signature, dnskey, 1000, DnssecFixture.Verifier, out _));
        var oldSignature = contents.GetSecurityRecords().Single(record => record.Type == 46 && record.Owner.Equals(nsec.Owner) && DnssecFixture.CoveredType(record) == 47);
        var altered = SignedAuthorityFixture.Replace(SignedAuthorityFixture.Replace(contents, nsec, replacement), oldSignature, signature);
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(altered, 1000, DnssecFixture.Verifier));
    }

    [Fact]
    public void IndividuallyValidDifferentWindowsAreNotACompleteGeneration()
    {
        var source = AuthorityFixture.Zone(DnssecFixture.A());
        var contents = SignedAuthorityFixture.Contents(source);
        var dnskey = contents.GetSecurityRecords().Single(record => record.Type == 48);
        using var key = DnssecFixture.Key();
        var signature = DnssecRrsetSigner.Sign([source.GetRecords(DnsName.Parse("www.example."))[0]], dnskey, key, DnssecFixture.Verifier, new DnssecSignatureWindow(200, 11_000));
        var original = contents.GetSecurityRecords().Single(record => record.Type == 46 && DnssecFixture.CoveredType(record) == 1);
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(SignedAuthorityFixture.Replace(contents, original, signature), 1000, DnssecFixture.Verifier));
    }

    [Theory]
    [InlineData(99)]
    [InlineData(10_001)]
    public void InactiveRetainedIntegrityCanBeVerifiedButFreshAdmissionFails(uint now)
    {
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.Zone());
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(contents, now, DnssecFixture.Verifier));
        Assert.False(SignedZoneAdmission.VerifyRetained(contents, DnssecFixture.Verifier).IsAvailable(now));
    }

    [Theory]
    [InlineData("*.example.")]
    [InlineData("*.")]
    public void LiteralWildcardApexMathRemainsPossibleButServingAdmissionRejectsIt(string origin)
    {
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.ZoneAt(origin));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.VerifyRetained(contents, DnssecFixture.Verifier));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(contents, 1000, DnssecFixture.Verifier));
    }

    [Fact]
    public void WildcardDelegationFailsBeforePrivateSigning()
    {
        var source = AuthorityFixture.Zone(AuthorityFixture.Record("*.example.", 2, DnssecFixture.Name("ns.other.")));
        using var key = DnssecFixture.Key();
        var counter = new DnssecFixture.CountingKey(key);
        Assert.Throws<FormatException>(() => SignedAuthorityFixture.Codec(counter, new SignedAuthorityFixture.Clock()).Compile(Guid.NewGuid(), 1, source));
        Assert.Equal(0, counter.Calls);
    }

    [Fact]
    public void ACompleteSignedRrsetThatCannotFitTcpIsRejected()
    {
        var records = Enumerable.Range(0, 70).Select(index => AuthorityFixture.Record("huge.example.", 16,
            Enumerable.Range(0, 4).SelectMany(_ => new[] { (byte)255 }.Concat(Enumerable.Repeat((byte)index, 255))).ToArray())).ToArray();
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.Zone(records));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(contents, 1000, DnssecFixture.Verifier));
        using var key = DnssecFixture.Key();
        var counter = new DnssecFixture.CountingKey(key);
        Assert.Throws<FormatException>(() => SignedAuthorityFixture.Codec(counter, new SignedAuthorityFixture.Clock()).Compile(Guid.NewGuid(), 1, contents.Source));
        Assert.Equal(0, counter.Calls);
    }

    [Fact]
    public void SerialMetadataAndTrailingOrTruncatedBundleDataAreRejected()
    {
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.Zone());
        var snapshot = SignedZoneBundleCodec.Compile(Guid.NewGuid(), 1, contents);
        Assert.Throws<FormatException>(() => SignedZoneBundleCodec.Decode(new ZoneSnapshot(snapshot.ZoneId, snapshot.Origin, 1, snapshot.Serial + 1, snapshot.GetPayload())));
        foreach (var data in new[] { snapshot.GetPayload()[..^1], snapshot.GetPayload().Append((byte)0).ToArray() })
            Assert.Throws<FormatException>(() => SignedZoneBundleCodec.Decode(new ZoneSnapshot(snapshot.ZoneId, snapshot.Origin, 1, snapshot.Serial, data)));
        var wrongCount = snapshot.GetPayload();
        BinaryPrimitives.WriteUInt16BigEndian(wrongCount.AsSpan(4), ushort.MaxValue);
        Assert.Throws<FormatException>(() => SignedZoneBundleCodec.Decode(new ZoneSnapshot(snapshot.ZoneId, snapshot.Origin, 1, snapshot.Serial, wrongCount)));
    }
}
