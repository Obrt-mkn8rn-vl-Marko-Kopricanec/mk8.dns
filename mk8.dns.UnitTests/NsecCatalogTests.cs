using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NsecCatalogTests
{
    [Theory]
    [InlineData("b.example.", 1, false, 3)]
    [InlineData("b.ent.example.", 1, false, 3)]
    [InlineData("a.example.", 28, false, 0)]
    [InlineData("ent.example.", 28, false, 0)]
    [InlineData("child.example.", 43, false, 0)]
    [InlineData("b.example.", 28, true, 0)]
    [InlineData("deep.b.example.", 28, true, 0)]
    [InlineData("b.example.", 1, true, 0)]
    [InlineData("deep.b.example.", 1, true, 0)]
    [InlineData("b.a.example.", 1, true, 0)]
    [InlineData("b.ent.example.", 1, true, 3)]
    public void AcceptedAuthorityOutputMatchesAuthenticatedDenialAndWildcardSemantics(string name, ushort type, bool wildcard, byte code)
    {
        List<DnsRecord> records = [DnssecFixture.A("a.example."), DnssecFixture.A("host.ent.example."),
            AuthorityFixture.Record("child.example.", 2, DnsName.Parse("ns.child.example.").ToWire()), DnssecFixture.A("ns.child.example.")];
        if (wildcard) records.AddRange([DnssecFixture.A("*.example."), DnssecFixture.A("*.a.example.")]);
        var source = AuthorityFixture.Zone(records.ToArray());
        var contents = SignedAuthorityFixture.Contents(source);
        var clock = new DnssecChainFixture.ClockProvider();
        var catalog = new AuthoritativeCatalog([contents], DnssecFixture.Verifier, clock);
        var validator = new DnssecChainValidator(DnssecFixture.Verifier, clock);
        var security = contents.GetSecurityRecords();
        var key = Assert.Single(security, record => record.Type == 48);
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(key), [key],
            security.Where(record => record.Type == 46 && DnssecFixture.CoveredType(record) == 48).ToArray(), out var keys));
        var question = new DnsQuestion(DnsName.Parse(name), type, 1);
        var answer = catalog.Resolve(question, dnssecOk: true);
        Assert.Equal(code, answer.ResponseCode);
        var denial = answer.Authority.Where(record => record.Type == 47).ToArray();
        var signatures = answer.Answers.Concat(answer.Authority).Where(record => record.Type == 46).ToArray();
        uint ttl;
        if (answer.Answers.Count != 0)
        {
            Assert.True(validator.TryAuthenticateWildcard(keys, question, answer.Answers.Where(record => record.Type != 46).ToArray(), denial, signatures, out ttl));
            Assert.Equal(60U, ttl);
        }
        else
        {
            var soa = answer.Authority.Where(record => record.Type == 6).ToArray();
            Assert.True(code == 3 ? validator.TryAuthenticateNameError(keys, question, soa, denial, signatures, out ttl)
                : validator.TryAuthenticateNoData(keys, question, soa, denial, signatures, out ttl));
            Assert.Equal(60U, ttl);
        }
    }
}
