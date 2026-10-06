using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthoritativeTests
{
    [Theory]
    [InlineData("www.example.", 1, 0, 1)]
    [InlineData("WWW.EXAMPLE.", 1, 0, 1)]
    [InlineData("www.example.", 28, 0, 0)]
    [InlineData("missing.example.", 1, 3, 0)]
    [InlineData("outside.test.", 1, 5, 0)]
    [InlineData("ent.example.", 1, 0, 0)]
    public void ExactNegativeAndOutsideAnswers(string name, ushort type, byte code, int count)
    {
        var zone = AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 1]), AuthorityFixture.Record("x.ent.example.", 1, [192, 0, 2, 2]));
        var result = new AuthoritativeCatalog([zone]).Resolve(new DnsQuestion(DnsName.Parse(name), type, 1));
        Assert.Equal(code, result.ResponseCode);
        Assert.Equal(count, result.Answers.Count);
        Assert.Equal(code != 5, result.Authoritative);
        if (count == 0 && code != 5)
        {
            Assert.Equal((ushort)6, Assert.Single(result.Authority).Type);
            Assert.Equal(60u, result.Authority[0].Ttl);
        }
    }

    [Theory]
    [InlineData("x.example.", 0, 1)]
    [InlineData("y.x.example.", 0, 1)]
    [InlineData("known.example.", 0, 0)]
    [InlineData("x.known.example.", 3, 0)]
    [InlineData("ent.example.", 0, 0)]
    [InlineData("x.ent.example.", 3, 0)]
    public void WildcardsUseClosestEncloserAndRespectEmptyNonterminals(string name, byte code, int count)
    {
        var zone = AuthorityFixture.Zone(AuthorityFixture.Record("*.example.", 1, [192, 0, 2, 1]), AuthorityFixture.Record("known.example.", 16, [1, 120]), AuthorityFixture.Record("leaf.ent.example.", 16, [1, 120]));
        var result = new AuthoritativeCatalog([zone]).Resolve(new DnsQuestion(DnsName.Parse(name), 1, 1));
        Assert.Equal(code, result.ResponseCode);
        Assert.Equal(count, result.Answers.Count);
        if (count != 0)
            Assert.Equal(DnsName.Parse(name), result.Answers[0].Owner);
    }

    [Fact]
    public void AliasesFollowLocalTargetsAndStopAtExternalNames()
    {
        var zone = AuthorityFixture.Zone(AuthorityFixture.Record("alias.example.", 5, DnsName.Parse("www.example.").ToWire()), AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 1]), AuthorityFixture.Record("external.example.", 5, DnsName.Parse("outside.test.").ToWire()));
        var catalog = new AuthoritativeCatalog([zone]);
        var local = catalog.Resolve(new DnsQuestion(DnsName.Parse("alias.example."), 1, 1));
        Assert.Equal(new ushort[] { 5, 1 }, local.Answers.Select(record => record.Type));
        var external = catalog.Resolve(new DnsQuestion(DnsName.Parse("external.example."), 1, 1));
        Assert.Equal((byte)0, external.ResponseCode);
        Assert.Equal((ushort)5, Assert.Single(external.Answers).Type);
        Assert.True(external.Authoritative);
    }

    [Fact]
    public void AliasCyclesReturnServfailWithoutInventingData()
    {
        var catalog = new AuthoritativeCatalog([AuthorityFixture.Zone(AuthorityFixture.Record("a.example.", 5, DnsName.Parse("b.example.").ToWire()), AuthorityFixture.Record("b.example.", 5, DnsName.Parse("a.example.").ToWire()))]);
        var result = catalog.Resolve(new DnsQuestion(DnsName.Parse("a.example."), 1, 1));
        Assert.Equal((byte)2, result.ResponseCode);
        Assert.Empty(result.Answers);
    }

    [Fact]
    public void DelegationReturnsGlueAndNeverAuthoritativeChildData()
    {
        var parent = AuthorityFixture.Zone(AuthorityFixture.Record("child.example.", 2, DnsName.Parse("ns.child.example.").ToWire()), AuthorityFixture.Record("ns.child.example.", 1, [192, 0, 2, 3]), AuthorityFixture.Record("www.child.example.", 1, [192, 0, 2, 4]));
        var result = new AuthoritativeCatalog([parent]).Resolve(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1));
        Assert.False(result.Authoritative);
        Assert.Empty(result.Answers);
        Assert.Equal(DnsName.Parse("child.example."), Assert.Single(result.Authority).Owner);
        Assert.Equal(DnsName.Parse("ns.child.example."), Assert.Single(result.Additional).Owner);
        var ds = new AuthoritativeCatalog([parent]).Resolve(new DnsQuestion(DnsName.Parse("child.example."), 43, 1));
        Assert.True(ds.Authoritative);
        Assert.Equal((ushort)6, Assert.Single(ds.Authority).Type);
    }

    [Fact]
    public void LocallyServedChildWinsWhileItsApexDsComesFromParent()
    {
        var parent = AuthorityFixture.Zone(AuthorityFixture.Record("child.example.", 2, DnsName.Parse("ns.child.example.").ToWire()), AuthorityFixture.Record("child.example.", 43, AuthorityFixture.DsData(1)));
        var child = AuthorityFixture.ZoneAt("child.example.", AuthorityFixture.Record("www.child.example.", 1, [192, 0, 2, 4]), AuthorityFixture.Record("nested.child.example.", 2, DnsName.Parse("ns.nested.child.example.").ToWire()), AuthorityFixture.Record("nested.child.example.", 43, AuthorityFixture.DsData(2)));
        var catalog = new AuthoritativeCatalog([parent, child]);
        Assert.Equal((ushort)1, Assert.Single(catalog.Resolve(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1)).Answers).Type);
        Assert.Equal(AuthorityFixture.DsData(1), Assert.Single(catalog.Resolve(new DnsQuestion(child.Origin, 43, 1)).Answers).GetData());
        Assert.Equal(AuthorityFixture.DsData(2), Assert.Single(catalog.Resolve(new DnsQuestion(DnsName.Parse("nested.child.example."), 43, 1)).Answers).GetData());
    }

    [Fact]
    public void ChildOnlyApexDsQueryReturnsAuthoritativeNoDataWithItsOwnSoa()
    {
        var child = AuthorityFixture.ZoneAt("child.example.", AuthorityFixture.Record("nested.child.example.", 2, DnsName.Parse("ns.nested.child.example.").ToWire()), AuthorityFixture.Record("nested.child.example.", 43, AuthorityFixture.DsData(2)));
        var result = new AuthoritativeCatalog([child]).Resolve(new DnsQuestion(child.Origin, 43, 1));
        Assert.Equal((byte)0, result.ResponseCode);
        Assert.True(result.Authoritative);
        Assert.Empty(result.Answers);
        var soa = Assert.Single(result.Authority);
        Assert.Equal((ushort)6, soa.Type);
        Assert.Equal(child.Origin, soa.Owner);
        Assert.Equal(60u, soa.Ttl);
        Assert.Empty(result.Additional);
    }

    [Fact]
    public void DnameSynthesizesCnameButDoesNotRedirectItsOwner()
    {
        var catalog = new AuthoritativeCatalog([AuthorityFixture.Zone(AuthorityFixture.Record("old.example.", 39, DnsName.Parse("new.example.").ToWire()), AuthorityFixture.Record("www.new.example.", 1, [192, 0, 2, 5]))]);
        var result = catalog.Resolve(new DnsQuestion(DnsName.Parse("www.old.example."), 1, 1));
        Assert.Equal(new ushort[] { 39, 5, 1 }, result.Answers.Select(record => record.Type));
        Assert.Equal(DnsName.Parse("www.new.example."), result.Answers[1].GetTarget());
        Assert.Empty(catalog.Resolve(new DnsQuestion(DnsName.Parse("old.example."), 1, 1)).Answers);
    }

    [Fact]
    public void AnyIsMinimalAndTransfersAndForeignClassesAreRefused()
    {
        var catalog = new AuthoritativeCatalog([AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 1]), AuthorityFixture.Record("www.example.", 16, [1, 120]))]);
        Assert.Equal((ushort)1, Assert.Single(catalog.Resolve(new DnsQuestion(DnsName.Parse("www.example."), 255, 1)).Answers).Type);
        Assert.Equal((byte)5, catalog.Resolve(new DnsQuestion(DnsName.Parse("example."), 252, 1)).ResponseCode);
        Assert.Equal((byte)5, catalog.Resolve(new DnsQuestion(DnsName.Parse("example."), 1, 3)).ResponseCode);
    }

    [Fact]
    public void DnameOverflowReturnsYxdomainWithTheDnameOnly()
    {
        var target = DnsName.Parse(new string('a', 63) + "." + new string('b', 63) + "." + new string('c', 63) + "." + new string('d', 60) + ".");
        var catalog = new AuthoritativeCatalog([AuthorityFixture.Zone(AuthorityFixture.Record("old.example.", 39, target.ToWire()))]);
        var result = catalog.Resolve(new DnsQuestion(DnsName.Parse("www.old.example."), 1, 1));
        Assert.Equal((byte)6, result.ResponseCode);
        Assert.Equal((ushort)39, Assert.Single(result.Answers).Type);
    }

    [Fact]
    public void AliasToMissingNameRetainsCnameAndNxDomainSoa()
    {
        var catalog = new AuthoritativeCatalog([AuthorityFixture.Zone(AuthorityFixture.Record("alias.example.", 5, DnsName.Parse("missing.example.").ToWire()))]);
        var result = catalog.Resolve(new DnsQuestion(DnsName.Parse("alias.example."), 1, 1));
        Assert.Equal((byte)3, result.ResponseCode);
        Assert.Equal((ushort)5, Assert.Single(result.Answers).Type);
        Assert.Equal((ushort)6, Assert.Single(result.Authority).Type);
    }

    [Fact]
    public void SiblingGlueBreaksCrossDelegationAddressDependencies()
    {
        var zone = AuthorityFixture.Zone(AuthorityFixture.Record("foo.example.", 2, DnsName.Parse("ns.bar.example.").ToWire()), AuthorityFixture.Record("bar.example.", 2, DnsName.Parse("ns.foo.example.").ToWire()), AuthorityFixture.Record("ns.foo.example.", 1, [192, 0, 2, 1]), AuthorityFixture.Record("ns.bar.example.", 1, [192, 0, 2, 2]));
        var answer = new AuthoritativeCatalog([zone]).Resolve(new DnsQuestion(DnsName.Parse("www.foo.example."), 1, 1));
        Assert.Equal(DnsName.Parse("ns.bar.example."), Assert.Single(answer.Additional).Owner);
        Assert.False(answer.Authoritative);
    }

    [Fact]
    public void BinaryLabelHierarchyCannotConfuseEmbeddedLabelOctetsWithSuffixes()
    {
        var name = DnsName.Parse("\\001a.example.");
        Assert.True(name.IsSubdomainOf(DnsName.Parse("example.")));
        Assert.False(name.IsSubdomainOf(DnsName.Parse("a.example.")));
        Assert.Equal(DnsName.Parse("example."), name.Parent);
        Assert.Equal(2, name.LabelCount);
        Assert.Equal(DnsName.Parse("\\000\\255a.example."), DnsName.Parse("example.").PrependLabel([0, 255, 65]));
        Assert.Equal(DnsName.Parse("."), DnsName.Parse(".").Parent);
    }
}
