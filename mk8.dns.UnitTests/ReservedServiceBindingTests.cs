using System.Globalization;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ReservedServiceBindingTests
{
    [Theory]
    [InlineData((ushort)64)]
    [InlineData((ushort)65)]
    public void ReservedKeyRefusesDirectGenericAndBundleButUnknownKeySurvives(ushort type)
    {
        var owner = DnsName.Parse("svc.example.");
        var origin = DnsName.Parse("example.");
        Assert.Throws<FormatException>(() => new DnsRecord(owner, type, 300, Convert.FromHexString("000100ffff0000")));
        var typeName = type.ToString(CultureInfo.InvariantCulture);
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(origin,
            SvcbMasterFileTests.Header + $"svc TYPE{typeName} \\# 7 000100ffff0000\n"));
        var unknown = new DnsRecord(owner, type, 300, Convert.FromHexString("000100fffe0000"));
        var zone = AuthorityFixture.Zone(unknown);
        var snapshot = ZoneBundleCodec.Compile(Guid.NewGuid(), 1, zone);
        Assert.Equal(unknown.GetData(), Assert.Single(ZoneBundleCodec.Decode(snapshot).GetRecords(owner)).GetData());
        var payload = snapshot.GetPayload();
        var offset = payload.AsSpan().IndexOf(unknown.GetData());
        Assert.True(offset >= 0);
        payload[offset + 4] = 255;
        var corrupt = new ZoneSnapshot(snapshot.ZoneId, snapshot.Origin, snapshot.Revision, snapshot.Serial, payload);
        Assert.Throws<FormatException>(() => ZoneBundleCodec.Decode(corrupt));
    }
}
