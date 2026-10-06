using Mk8.Dns.Application.BLL;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class QueryApplicationTests
{
    [Fact]
    public async Task ServingRoleReportsItsPinnedCatalogAndMalformedQueriesHaveBoundedErrors()
    {
        var application = new AuthoritativeApplication(new AuthoritativeCatalog([AuthorityFixture.Zone()]), new DnsMessageCodecAdapter(), "test");
        var status = await application.GetStatusAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.True(status.DnsReady);
        Assert.Equal(1u, status.ActiveSnapshots);
        var response = await application.ExchangeAsync(AuthorityFixture.Query(flags: 0x2900), false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal((byte)4, (byte)(response[3] & 15));
        Assert.Empty(await application.ExchangeAsync(new byte[11], false, new byte[4], CancellationToken.None).ConfigureAwait(true));
        using var canceled = new CancellationTokenSource();
        await canceled.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => application.ExchangeAsync(AuthorityFixture.Query(), false, new byte[4], canceled.Token).AsTask()).ConfigureAwait(true);
        Assert.Throws<ArgumentException>(() => new AuthoritativeApplication(new AuthoritativeCatalog([]), new DnsMessageCodecAdapter(), "test"));
    }
}
