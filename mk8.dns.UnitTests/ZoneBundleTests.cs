using System.Buffers.Binary;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ZoneBundleTests
{
    [Fact]
    public async Task CompiledZoneSurvivesDurablePublicationAndReopen()
    {
        using var temporary = new TemporaryDirectory();
        var state = Path.Combine(temporary.Path, "state");
        var id = Guid.NewGuid();
        var snapshot = ZoneBundleCodec.Compile(id, 1, AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 1])));
        Assert.Equal("M8Z1"u8.ToArray(), snapshot.GetPayload()[..4]);
        Assert.Equal(10u, snapshot.Serial);
        var store = new FileZoneSnapshotStore(state);
        await using (store.ConfigureAwait(true))
            await store.ActivateAsync(snapshot, CancellationToken.None).ConfigureAwait(true);
        var reopened = new FileZoneSnapshotStore(state);
        await using var lifetime = reopened.ConfigureAwait(true);
        var active = await reopened.ReadActiveAsync(id, CancellationToken.None).ConfigureAwait(true);
        var restored = ZoneBundleCodec.Decode(Assert.IsType<ZoneSnapshot>(active));
        Assert.Equal(snapshot.ContentHash, active!.ContentHash);
        Assert.Equal(new byte[] { 192, 0, 2, 1 }, Assert.Single(restored.GetRecords(DnsName.Parse("www.example."))).GetData());
    }

    [Fact]
    public void CompilerIsDeterministicAndDataIsImmutable()
    {
        var id = Guid.NewGuid();
        var source = new byte[] { 192, 0, 2, 1 };
        var record = AuthorityFixture.Record("www.example.", 1, source);
        var first = AuthorityFixture.Zone(record);
        source[0] = 1;
        record.GetData()[0] = 2;
        var second = new AuthoritativeZone(first.Origin, first.GetAllRecords().Reverse());
        var one = ZoneBundleCodec.Compile(id, 1, first);
        var two = ZoneBundleCodec.Compile(id, 1, second);
        Assert.Equal(one.ContentHash, two.ContentHash);
        Assert.Equal((byte)192, record.GetData()[0]);
        Assert.Equal(one.GetPayload(), two.GetPayload());
    }

    [Fact]
    public void SerialOriginFormatAndTrailingDataCannotBeTrustedFromMetadataAlone()
    {
        var id = Guid.NewGuid();
        var valid = ZoneBundleCodec.Compile(id, 1, AuthorityFixture.Zone());
        Assert.Throws<FormatException>(() => ZoneBundleCodec.Decode(new ZoneSnapshot(id, valid.Origin, 1, 11, valid.GetPayload())));
        Assert.Throws<FormatException>(() => ZoneBundleCodec.Decode(new ZoneSnapshot(id, DnsName.Parse("other."), 1, 10, valid.GetPayload())));
        Assert.Throws<FormatException>(() => ZoneBundleCodec.Decode(new ZoneSnapshot(id, valid.Origin, 1, 10, valid.GetPayload().Concat(new byte[] { 0 }).ToArray())));
        var bad = valid.GetPayload();
        bad[3] = (byte)'2';
        Assert.Throws<FormatException>(() => ZoneBundleCodec.Decode(new ZoneSnapshot(id, valid.Origin, 1, 10, bad)));
        for (var length = 1; length < valid.GetPayload().Length; length++)
        {
            var cut = new ZoneSnapshot(id, valid.Origin, 1, 10, valid.GetPayload().AsSpan(0, length));
            Assert.Throws<FormatException>(() => ZoneBundleCodec.Decode(cut));
        }
    }

    [Fact]
    public void RecordSetValidationRejectsInvalidZoneStructure()
    {
        Assert.Throws<ArgumentException>(() => AuthorityFixture.Zone(AuthorityFixture.Record("outside.", 1, [192, 0, 2, 1])));
        Assert.Throws<ArgumentException>(() => AuthorityFixture.Zone(AuthorityFixture.Record("x.example.", 1, [192, 0, 2, 1], 1), AuthorityFixture.Record("x.example.", 1, [192, 0, 2, 2], 2)));
        Assert.Throws<ArgumentException>(() => AuthorityFixture.Zone(AuthorityFixture.Record("x.example.", 1, [192, 0, 2, 1]), AuthorityFixture.Record("x.example.", 1, [192, 0, 2, 1])));
        Assert.Throws<ArgumentException>(() => AuthorityFixture.Zone(AuthorityFixture.Record("x.example.", 5, DnsName.Parse("target.example.").ToWire()), AuthorityFixture.Record("x.example.", 1, [192, 0, 2, 1])));
        Assert.Throws<ArgumentException>(() => AuthorityFixture.Zone(AuthorityFixture.Record("cut.example.", 39, DnsName.Parse("target.example.").ToWire()), AuthorityFixture.Record("cut.example.", 2, DnsName.Parse("ns.example.").ToWire())));
        Assert.Throws<ArgumentException>(() => AuthorityFixture.Zone(AuthorityFixture.Record("old.example.", 39, DnsName.Parse("new.example.").ToWire()), AuthorityFixture.Record("leaf.old.example.", 1, [192, 0, 2, 1])));
        Assert.Throws<ArgumentException>(() => AuthorityFixture.Zone(AuthorityFixture.Record("example.", 48, [1])));
        Assert.Throws<ArgumentException>(() => new AuthoritativeZone(DnsName.Parse("example."), []));
    }

    [Theory]
    [InlineData(1, "000000")]
    [InlineData(28, "00000000")]
    [InlineData(2, "c00c")]
    [InlineData(5, "00ff")]
    [InlineData(16, "0278")]
    [InlineData(15, "0001c00c")]
    [InlineData(33, "000000000001c00c")]
    [InlineData(65, "0001000001000100")]
    [InlineData(65, "000100000000020001")]
    [InlineData(64, "000000")]
    public void StructuredRdataRejectsBadLengthsPointersAndSvcParameters(ushort type, string data) => Assert.Throws<FormatException>(() => AuthorityFixture.Record("example.", type, Convert.FromHexString(data)));

    [Fact]
    public void ModernAndUnknownTypesRoundTripWithoutInterpretationLoss()
    {
        var https = new byte[] { 0, 1, 0, 0, 1, 0, 3, 2, 104, 50, 0, 3, 0, 2, 1, 187 };
        var zone = AuthorityFixture.Zone(AuthorityFixture.Record("example.", 65, https), AuthorityFixture.Record("example.", 65280, [0xc0, 0x0c, 0, 255]));
        var decoded = ZoneBundleCodec.Decode(ZoneBundleCodec.Compile(Guid.NewGuid(), 1, zone));
        Assert.Equal(https, decoded.GetRecords(zone.Origin).Single(record => record.Type == 65).GetData());
        Assert.Equal(new byte[] { 0xc0, 0x0c, 0, 255 }, decoded.GetRecords(zone.Origin).Single(record => record.Type == 65280).GetData());
    }

    [Fact]
    public void BundleRecordCountIsBoundedBeforeAllocation()
    {
        var valid = ZoneBundleCodec.Compile(Guid.NewGuid(), 1, AuthorityFixture.Zone());
        var payload = valid.GetPayload();
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(4), ushort.MaxValue);
        Assert.Throws<FormatException>(() => ZoneBundleCodec.Decode(new ZoneSnapshot(valid.ZoneId, valid.Origin, 1, 10, payload)));
    }

    [Fact]
    public void NameBearingRdataDuplicatesAreComparedCaseInsensitively()
    {
        var upperName = AuthorityFixture.Query("NS.EXAMPLE.")[12..^4];
        Assert.Throws<ArgumentException>(() => AuthorityFixture.Zone(AuthorityFixture.Record("example.", 2, upperName)));
    }

    [Fact]
    public void StoredOwnerSpellingSurvivesBundleRoundTripAndNegativeTtlChanges()
    {
        var original = AuthorityFixture.Query("WWW.Example.")[12..^4];
        var record = new DnsRecord(original, 1, 300, new byte[] { 192, 0, 2, 1 });
        var zone = AuthorityFixture.Zone(record);
        original[1] = (byte)'X';
        var restored = ZoneBundleCodec.Decode(ZoneBundleCodec.Compile(Guid.NewGuid(), 1, zone));
        var owner = Assert.Single(restored.GetRecords(DnsName.Parse("www.example.")));
        Assert.Equal(AuthorityFixture.Query("WWW.Example.")[12..^4], owner.GetOwnerWire());
        Assert.Equal(owner.GetOwnerWire(), owner.WithTtl(60).GetOwnerWire());
    }
}
