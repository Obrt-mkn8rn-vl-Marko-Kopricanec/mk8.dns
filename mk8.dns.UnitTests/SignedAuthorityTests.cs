using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SignedAuthorityTests
{
    [Theory]
    [InlineData(46, false)]
    [InlineData(46, true)]
    [InlineData(47, false)]
    [InlineData(47, true)]
    public void ExplicitDnssecMetadataAtACnameOwnerDoesNotChaseAnOutOfGrantTarget(ushort type, bool dnssecOk)
    {
        var source = AuthorityFixture.Zone(AuthorityFixture.Record("alias.example.", 5, DnssecFixture.Name("target.other.")));
        var other = AuthorityFixture.ZoneAt("other.", DnssecFixture.A("target.other."));
        var catalog = SignedAuthorityFixture.Catalog(source, other);
        var answer = catalog.Resolve(SignedAuthorityFixture.Question("alias.example.", type), origin => origin.Equals(source.Origin), dnssecOk);
        Assert.Equal(0, answer.ResponseCode);
        Assert.True(answer.Authoritative);
        Assert.DoesNotContain(answer.Answers, record => record.Type == 5);
        Assert.Equal(type == 46 ? 2 : 1, answer.Answers.Count(record => record.Type == type));
        Assert.All(answer.Answers, record => Assert.Equal(DnsName.Parse("alias.example."), record.Owner));
    }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 1)]
    [InlineData(false, 48)]
    [InlineData(true, 48)]
    [InlineData(false, 6)]
    [InlineData(true, 6)]
    [InlineData(false, 2)]
    [InlineData(true, 2)]
    public void PositiveRrsetsHaveSignaturesOnlyWhenDoIsSet(bool dnssecOk, ushort type)
    {
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(DnssecFixture.A()));
        var question = SignedAuthorityFixture.Question(type == 1 ? "www.example." : "example.", type);
        var answer = catalog.Resolve(question, dnssecOk);
        Assert.Equal(0, answer.ResponseCode);
        Assert.True(answer.Authoritative);
        Assert.Single(answer.Answers, record => record.Type == type);
        Assert.Equal(dnssecOk ? 1 : 0, answer.Answers.Count(record => record.Type == 46));
        Assert.Empty(answer.Authority);
        if (dnssecOk)
            VerifyAnswer(catalog, answer.Answers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExplicitRrsigQueryDoesNotTryToSignTheRrsig(bool dnssecOk)
    {
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(DnssecFixture.A()));
        var answer = catalog.Resolve(SignedAuthorityFixture.Question("example.", 46), dnssecOk);
        Assert.Equal(0, answer.ResponseCode);
        Assert.Equal(4, answer.Answers.Count);
        Assert.All(answer.Answers, record => Assert.Equal(46, record.Type));
        Assert.Equal(new ushort[] { 2, 6, 47, 48 }, answer.Answers.Select(DnssecFixture.CoveredType).Order().ToArray());
    }

    [Theory]
    [InlineData("www.example.", 28, 0)]
    [InlineData("absent.example.", 1, 3)]
    [InlineData("branch.example.", 1, 0)]
    [InlineData("*.absent.example.", 1, 3)]
    public void NegativeAnswersIncludeSignedSoaAndDenialWithoutSigningEmptyNonterminals(string name, ushort type, byte code)
    {
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(DnssecFixture.A(), DnssecFixture.A("leaf.branch.example.")));
        var answer = catalog.Resolve(SignedAuthorityFixture.Question(name, type), dnssecOk: true);
        Assert.Equal(code, answer.ResponseCode);
        Assert.True(answer.Authoritative);
        Assert.Empty(answer.Answers);
        Assert.Single(answer.Authority, record => record.Type == 6);
        Assert.Contains(answer.Authority, record => record.Type == 47);
        Assert.DoesNotContain(answer.Authority, record => record.Owner.Equals(DnsName.Parse("branch.example.")));
        Assert.Equal(60U, answer.Authority.Single(record => record.Type == 6).Ttl);
        VerifyAnswer(catalog, answer.Authority);
    }

    [Theory]
    [InlineData("x.wild.example.", 1, true)]
    [InlineData("x.deep.wild.example.", 1, true)]
    [InlineData("x.wild.example.", 28, false)]
    [InlineData("x.deep.wild.example.", 28, false)]
    public void WildcardExpansionCarriesOriginalLabelsAndUnexpandedDenialProofs(string name, ushort type, bool positive)
    {
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(DnssecFixture.A("*.wild.example.")));
        var answer = catalog.Resolve(SignedAuthorityFixture.Question(name, type), dnssecOk: true);
        Assert.Equal(0, answer.ResponseCode);
        Assert.True(answer.Authoritative);
        Assert.Contains(answer.Authority, record => record.Type == 47);
        Assert.DoesNotContain(answer.Authority, record => record.Owner.Equals(DnsName.Parse(name)));
        if (positive)
        {
            var signature = Assert.Single(answer.Answers, record => record.Type == 46);
            Assert.Equal(DnsName.Parse(name), signature.Owner);
            Assert.Equal(2, signature.GetData()[3]);
            VerifyAnswer(catalog, answer.Answers);
        }
        else
        {
            Assert.Empty(answer.Answers);
            Assert.Contains(answer.Authority, record => record.Type == 47 && record.Owner.Equals(DnsName.Parse("*.wild.example.")));
        }
        VerifyAnswer(catalog, answer.Authority);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReferralContainsSignedDsOrSignedParentSideAbsenceAndUnsignedCutNsGlue(bool secure)
    {
        List<DnsRecord> records = [AuthorityFixture.Record("child.example.", 2, DnssecFixture.Name("ns.child.example.")), DnssecFixture.A("ns.child.example.")];
        if (secure)
            records.Add(AuthorityFixture.Record("child.example.", 43, AuthorityFixture.DsData(2)));
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(records.ToArray()));
        var answer = catalog.Resolve(SignedAuthorityFixture.Question("www.child.example."), dnssecOk: true);
        Assert.False(answer.Authoritative);
        Assert.Empty(answer.Answers);
        Assert.Single(answer.Authority, record => record.Type == 2);
        Assert.Contains(answer.Authority, record => record.Type == (secure ? 43 : 47));
        Assert.DoesNotContain(answer.Authority, record => record.Type == 46 && DnssecFixture.CoveredType(record) == 2);
        Assert.Single(answer.Additional);
        Assert.Equal(1, answer.Additional[0].Type);
        VerifyAnswer(catalog, answer.Authority);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DsQueriesUseTheParentSignatureAndItsExactSigningGrant(bool bothGranted)
    {
        var parent = AuthorityFixture.Zone(AuthorityFixture.Record("child.example.", 2, DnssecFixture.Name("ns.child.example.")),
            AuthorityFixture.Record("child.example.", 43, AuthorityFixture.DsData(2)));
        var child = AuthorityFixture.ZoneAt("child.example.");
        var catalog = SignedAuthorityFixture.Catalog(parent, child);
        var answer = catalog.Resolve(SignedAuthorityFixture.Question("child.example.", 43),
            origin => bothGranted || origin.Equals(child.Origin), dnssecOk: true);
        if (bothGranted)
        {
            Assert.Equal(0, answer.ResponseCode);
            Assert.Single(answer.Answers, record => record.Type == 43);
            Assert.Single(answer.Answers, record => record.Type == 46);
            VerifyAnswer(catalog, answer.Answers);
        }
        else
        {
            Assert.Equal(5, answer.ResponseCode);
            Assert.Empty(answer.Answers);
            Assert.Empty(answer.Authority);
        }
    }

    [Fact]
    public void ChildOnlyDsNodataUsesChildSoaProofContainingSoaBit()
    {
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.ZoneAt("child.example."));
        var answer = catalog.Resolve(SignedAuthorityFixture.Question("child.example.", 43), dnssecOk: true);
        Assert.Empty(answer.Answers);
        var denial = Assert.Single(answer.Authority, record => record.Type == 47);
        Assert.Contains((ushort)6, NsecBitmap.Decode(denial.GetData().AsSpan(DnssecFixture.NameEnd(denial.GetData()))));
        VerifyAnswer(catalog, answer.Authority);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void CrossZoneAliasesPreserveSelectedOriginAuthorizationAndDiscardAccumulatedProofs(bool dname, bool bothGranted)
    {
        var first = AuthorityFixture.Zone(AuthorityFixture.Record(dname ? "d.example." : "*.example.", dname ? (ushort)39 : (ushort)5, DnssecFixture.Name(dname ? "other." : "target.other.")));
        var other = AuthorityFixture.ZoneAt("other.", DnssecFixture.A("target.other."));
        var catalog = SignedAuthorityFixture.Catalog(first, other);
        var answer = catalog.Resolve(SignedAuthorityFixture.Question(dname ? "target.d.example." : "x.example."),
            origin => bothGranted || origin.Equals(first.Origin), dnssecOk: true);
        Assert.Equal(bothGranted ? 0 : 5, answer.ResponseCode);
        if (bothGranted)
            Assert.Contains(answer.Answers, record => record.Type == 1);
        else
        {
            Assert.False(answer.Authoritative);
            Assert.Empty(answer.Answers);
            Assert.Empty(answer.Authority);
            Assert.Empty(answer.Additional);
        }
    }

    [Fact]
    public void DnameSignsTheOriginalRecordAndLeavesSynthesizedCnameUnsigned()
    {
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(AuthorityFixture.Record("d.example.", 39, DnssecFixture.Name("target.example.")), DnssecFixture.A("x.target.example.")));
        var answer = catalog.Resolve(SignedAuthorityFixture.Question("x.d.example."), dnssecOk: true);
        Assert.Single(answer.Answers, record => record.Type == 5);
        Assert.DoesNotContain(answer.Answers, record => record.Type == 46 && DnssecFixture.CoveredType(record) == 5);
        Assert.Single(answer.Answers, record => record.Type == 46 && DnssecFixture.CoveredType(record) == 39);
        VerifyAnswer(catalog, answer.Answers);
    }

    [Fact]
    public async Task ExpiryAndClockRollbackFailClosedAndBoundServedTtlWithAndWithoutDo()
    {
        var clock = new SignedAuthorityFixture.Clock();
        var contents = SignedAuthorityFixture.Contents(AuthorityFixture.Zone(DnssecFixture.A()));
        var catalog = new AuthoritativeCatalog([contents], DnssecFixture.Verifier, clock);
        var app = new AuthoritativeApplication(catalog, new DnsMessageCodecAdapter(), "expiry-test");
        clock.Seconds = 9990;
        foreach (var dnssecOk in new[] { false, true })
            Assert.All(catalog.Resolve(SignedAuthorityFixture.Question("www.example."), dnssecOk).Answers, record => Assert.Equal(10U, record.Ttl));
        Assert.True((await app.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        clock.Seconds = 10_001;
        Assert.False((await app.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        var expired = catalog.Resolve(SignedAuthorityFixture.Question("www.example."), dnssecOk: true);
        Assert.Equal(2, expired.ResponseCode);
        Assert.Empty(expired.Answers);
        Assert.Empty(expired.Authority);
        clock.Seconds = 99;
        Assert.Equal(2, catalog.Resolve(SignedAuthorityFixture.Question("www.example."), dnssecOk: false).ResponseCode);
    }

    private static void VerifyAnswer(AuthoritativeCatalog catalog, IReadOnlyList<DnsRecord> records)
    {
        foreach (var signature in records.Where(record => record.Type == 46))
        {
            var data = signature.GetData();
            var offset = 18;
            while (data[offset] != 0)
                offset += data[offset] + 1;
            var signer = DnsName.FromWire(data.AsSpan(18, offset - 18 + 1));
            var dnskey = catalog.Resolve(new DnsQuestion(signer, 48, 1)).Answers.Single(record => record.Type == 48);
            var rrset = records.Where(record => record.Owner.Equals(signature.Owner) && record.Type == DnssecFixture.CoveredType(signature)).ToArray();
            Assert.True(DnssecRrsetVerifier.TryVerify(rrset, signature, dnskey, 1000, DnssecFixture.Verifier, out _));
        }
    }
}
