using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecZoneTests
{
    [Fact]
    public void CompleteGenerationSignsApexAliasesWildcardsAndExistingOwners()
    {
        using var key = DnssecFixture.Key();
        var zone = AuthorityFixture.Zone(DnssecFixture.A(), DnssecFixture.A("ns.example."), DnssecFixture.A("*.example."), DnssecFixture.A("leaf.ent.example."),
            AuthorityFixture.Record("alias.example.", 5, DnssecFixture.Name("www.example.")), AuthorityFixture.Record("old.example.", 39, DnssecFixture.Name("new.example.")),
            AuthorityFixture.Record("www.example.", 16, [1, (byte)'Z'], 900), AuthorityFixture.Record("svc.example.", 65, [0, 1, .. DnssecFixture.Name("target.example.", upper: true)]),
            AuthorityFixture.Record("opaque.example.", 65280, [0, 255, (byte)'A']));
        var original = zone.GetAllRecords().Select(record => record.GetData()).ToArray();
        var signed = Sign(zone, key);
        Assert.Same(zone, signed.Source);
        Assert.Equal(zone.Origin, signed.Origin);
        Assert.Same(DnssecFixture.Window, signed.Window);
        Assert.Equal(zone.Origin, signed.ParentDs.Owner);
        Assert.DoesNotContain(signed.GetAllRecords(), record => record.Type == 43);
        var nsec = signed.GetAllRecords().Where(record => record.Type == 47).ToArray();
        Assert.Equal(zone.GetAllRecords().Select(record => record.Owner).Distinct().OrderBy(name => name, DnssecNameOrder.Instance), nsec.Select(record => record.Owner));
        Assert.DoesNotContain(nsec, record => record.Owner.Equals(DnsName.Parse("ent.example.")));
        CheckChain(nsec);
        foreach (var denial in nsec)
        {
            var data = denial.GetData();
            var bitmap = NsecBitmap.Decode(data.AsSpan(DnssecFixture.NameEnd(data)));
            Assert.Equal(signed.GetAllRecords().Where(record => record.Owner.Equals(denial.Owner)).Select(record => record.Type).Distinct().Order(), bitmap);
            Assert.Equal(60u, denial.Ttl);
        }
        CheckAllSignatures(signed);
        Assert.Equal(original.Length, zone.GetAllRecords().Count);
        for (var index = 0; index < original.Length; index++)
            Assert.Equal(original[index], zone.GetAllRecords()[index].GetData());
        Assert.Throws<NotSupportedException>(() => ((IList<DnsRecord>)signed.GetAllRecords())[0] = DnssecFixture.A());
        var copy = signed.Dnskey.GetData();
        copy[4] ^= 1;
        CheckAllSignatures(signed);
        Assert.All(signed.GetAllRecords().Where(record => record.Type == 46 && DnssecFixture.CoveredType(record) == 5), record => Assert.Equal(DnsName.Parse("alias.example."), record.Owner));
    }

    [Fact]
    public void DelegationNsGlueOccludedRecordsAndNestedCutsRemainUnsigned()
    {
        using var key = DnssecFixture.Key();
        var zone = AuthorityFixture.Zone(
            AuthorityFixture.Record("child.example.", 2, DnssecFixture.Name("ns.child.example.")),
            AuthorityFixture.Record("child.example.", 43, AuthorityFixture.DsData(7)),
            DnssecFixture.A("child.example."), DnssecFixture.A("ns.child.example."), DnssecFixture.A("www.child.example."),
            AuthorityFixture.Record("nested.child.example.", 2, DnssecFixture.Name("ns.nested.child.example.")),
            AuthorityFixture.Record("child.example.", 16, [1, (byte)'X']), DnssecFixture.A("ns.example."));
        var signed = Sign(zone, key);
        var records = signed.GetAllRecords();
        var cut = DnsName.Parse("child.example.");
        var denial = Assert.Single(records, record => record.Owner.Equals(cut) && record.Type == 47);
        var data = denial.GetData();
        Assert.Equal(new ushort[] { 2, 43, 46, 47 }, NsecBitmap.Decode(data.AsSpan(DnssecFixture.NameEnd(data))));
        Assert.Equal(new ushort[] { 43, 47 }, records.Where(record => record.Type == 46 && record.Owner.Equals(cut)).Select(DnssecFixture.CoveredType).Order());
        Assert.DoesNotContain(records, record => record.Type is 46 or 47 && !record.Owner.Equals(cut) && record.Owner.IsSubdomainOf(cut));
        Assert.Contains(records, record => record.Type == 1 && record.Owner.Equals(DnsName.Parse("ns.child.example.")));
        Assert.Contains(records, record => record.Type == 16 && record.Owner.Equals(cut));
        Assert.Contains(records, record => record.Type == 2 && record.Owner.Equals(DnsName.Parse("nested.child.example.")));
        Assert.Contains(records, record => record.Type == 46 && DnssecFixture.CoveredType(record) == 1 && record.Owner.Equals(DnsName.Parse("ns.example.")));
        CheckAllSignatures(signed);
        CheckChain(records.Where(record => record.Type == 47).ToArray());
    }

    [Fact]
    public void InsecureDelegationBitmapOmitsDsAndOnlyDenialIsSigned()
    {
        using var key = DnssecFixture.Key();
        var signed = Sign(AuthorityFixture.Zone(AuthorityFixture.Record("child.example.", 2, DnssecFixture.Name("ns.child.example.")), DnssecFixture.A("ns.child.example.")), key);
        var owner = DnsName.Parse("child.example.");
        var denial = Assert.Single(signed.GetAllRecords(), record => record.Type == 47 && record.Owner.Equals(owner));
        var data = denial.GetData();
        Assert.Equal(new ushort[] { 2, 46, 47 }, NsecBitmap.Decode(data.AsSpan(DnssecFixture.NameEnd(data))));
        Assert.Equal((ushort)47, DnssecFixture.CoveredType(Assert.Single(signed.GetAllRecords(), record => record.Type == 46 && record.Owner.Equals(owner))));
    }

    [Fact]
    public void ApexOnlyAndRootZonesHaveClosedDenialCycles()
    {
        using var key = DnssecFixture.Key();
        var basic = AuthorityFixture.Zone();
        foreach (var origin in new[] { DnssecFixture.Origin, DnsName.Parse(".") })
        {
            var zone = new AuthoritativeZone(origin, basic.GetAllRecords().Select(record => record.WithOwner(origin)));
            var signed = Sign(zone, key);
            var denial = Assert.Single(signed.GetAllRecords(), record => record.Type == 47);
            var data = denial.GetData();
            Assert.Equal(origin, DnsName.FromWire(data.AsSpan(0, DnssecFixture.NameEnd(data))));
            Assert.Equal(new ushort[] { 2, 6, 46, 47, 48 }, NsecBitmap.Decode(data.AsSpan(DnssecFixture.NameEnd(data))));
            CheckAllSignatures(signed);
        }
    }

    [Theory]
    [InlineData("*.example.", false)]
    [InlineData("*.example.", true)]
    [InlineData("*.", false)]
    [InlineData("*.", true)]
    public void LiteralWildcardZoneApexAuthenticatesWithoutBecomingASynthesisSource(string text, bool includeChild)
    {
        using var key = DnssecFixture.Key();
        var origin = DnsName.Parse(text);
        var original = AuthorityFixture.Zone();
        var records = original.GetAllRecords().Select(record => record.WithOwner(origin));
        if (includeChild)
            records = records.Append(DnssecFixture.A("www." + text));
        var signed = Sign(new AuthoritativeZone(origin, records), key);
        CheckAllSignatures(signed);
        CheckChain(signed.GetAllRecords().Where(record => record.Type == 47).ToArray());
        var soa = Assert.Single(signed.GetAllRecords(), record => record.Type == 6);
        var signature = Assert.Single(signed.GetAllRecords(), record => record.Type == 46 && DnssecFixture.CoveredType(record) == 6);
        Assert.Equal((byte)(origin.LabelCount - 1), signature.GetData()[3]);
        var expanded = DnsName.Parse("invented." + text);
        Assert.False(DnssecRrsetVerifier.TryVerify([soa.WithOwner(expanded)], signature.WithOwner(expanded), signed.Dnskey, 100, DnssecFixture.Verifier, out _));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(30u)]
    [InlineData(60u)]
    [InlineData(3600u)]
    public void DenialTtlUsesMinimumOfSoaTtlAndNegativeMinimum(uint ttl)
    {
        using var key = DnssecFixture.Key();
        var original = AuthorityFixture.Zone();
        var zone = new AuthoritativeZone(original.Origin, original.GetAllRecords().Select(record => record.Type == 6 ? record.WithTtl(ttl) : record));
        var signed = Sign(zone, key);
        Assert.All(signed.GetAllRecords().Where(record => record.Type == 47 || record.Type == 46 && DnssecFixture.CoveredType(record) == 47), record => Assert.Equal(Math.Min(ttl, 60u), record.Ttl));
    }

    [Fact]
    public void CancellationAndProviderFailureReturnNoCompleteGeneration()
    {
        using var key = DnssecFixture.Key();
        using var cancel = new CancellationTokenSource();
        var zone = AuthorityFixture.Zone(DnssecFixture.A());
        var spy = new DnssecFixture.CountingKey(key);
        cancel.Cancel();
        Assert.Throws<OperationCanceledException>(() => NsecZoneSigner.Sign(zone, spy, DnssecFixture.Verifier, DnssecFixture.Window, cancellationToken: cancel.Token));
        Assert.Equal(0, spy.Calls);
        using var during = new CancellationTokenSource();
        var midway = new DnssecFixture.CountingKey(key) { AfterSign = during.Cancel };
        Assert.Throws<OperationCanceledException>(() => NsecZoneSigner.Sign(zone, midway, DnssecFixture.Verifier, DnssecFixture.Window, cancellationToken: during.Token));
        Assert.Equal(1, midway.Calls);
        var bad = new DnssecFixture.CountingKey(key) { CorruptSignature = true };
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => Sign(zone, bad));
        Assert.Equal(1, bad.Calls);
        Assert.Equal(3, zone.GetAllRecords().Count);
    }

    [Fact]
    public void OversizedGeneratedPlanIsRejectedBeforeSigning()
    {
        using var key = DnssecFixture.Key();
        var spy = new DnssecFixture.CountingKey(key);
        var records = Enumerable.Range(0, 4000).Select(index => DnssecFixture.A(index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture) + new string('a', 59) + "." + new string('b', 63) + "." + new string('c', 63) + ".example.")).ToArray();
        var zone = AuthorityFixture.Zone(records);
        Assert.Throws<ArgumentException>(() => Sign(zone, spy));
        Assert.Equal(0, spy.Calls);
        Assert.Equal(4002, zone.GetAllRecords().Count);
    }

    [Fact]
    public void GenericExportIsCompleteAndUnsignedAdmissionStillRefusesIt()
    {
        using var key = DnssecFixture.Key();
        var signed = Sign(AuthorityFixture.Zone(DnssecFixture.A("*.example."), AuthorityFixture.Record("alias.example.", 5, DnssecFixture.Name("target.example."))), key);
        var export = signed.ExportMasterFile();
        Assert.Equal(signed.GetAllRecords().Count, export.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
        Assert.Contains(" IN TYPE48 \\# 68 ", export, StringComparison.Ordinal);
        Assert.Contains(" IN TYPE46 \\# ", export, StringComparison.Ordinal);
        Assert.Contains(" IN TYPE47 \\# ", export, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", export, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => new AuthoritativeZone(signed.Origin, signed.GetAllRecords()));
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(signed.Origin, export));
    }

    private static SignedZone Sign(AuthoritativeZone zone, IDnssecSigningKey key) => NsecZoneSigner.Sign(zone, key, DnssecFixture.Verifier, DnssecFixture.Window);

    private static void CheckAllSignatures(SignedZone signed)
    {
        foreach (var signature in signed.GetAllRecords().Where(record => record.Type == 46))
        {
            var covered = signed.GetAllRecords().Where(record => record.Owner.Equals(signature.Owner) && record.Type == DnssecFixture.CoveredType(signature)).ToArray();
            Assert.NotEmpty(covered);
            Assert.True(DnssecRrsetVerifier.TryVerify(covered, signature, signed.Dnskey, 100, DnssecFixture.Verifier, out _));
        }
    }

    private static void CheckChain(DnsRecord[] nsec)
    {
        for (var index = 0; index < nsec.Length; index++)
        {
            var data = nsec[index].GetData();
            Assert.Equal(nsec[(index + 1) % nsec.Length].Owner, DnsName.FromWire(data.AsSpan(0, DnssecFixture.NameEnd(data))));
        }
    }
}
