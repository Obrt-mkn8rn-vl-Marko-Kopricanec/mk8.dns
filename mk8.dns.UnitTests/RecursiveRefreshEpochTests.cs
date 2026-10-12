using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecursiveRefreshEpochTests
{
    [Fact]
    public async Task AcknowledgedScheduledRefreshRetiresStillLiveOldProofCacheBeforeNextDelivery()
    {
        var f = new RecursiveRefreshFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var guard = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        using var stop = new CancellationTokenSource();
        f.Inputs.DataTtl = 9000;
        f.Inputs.Anchors.Records = [f.Inputs.Anchors.Keys.Key(f.Inputs.Anchors.Keys.A, 20000),
            f.Inputs.Anchors.Keys.Key(f.Inputs.Anchors.Keys.B, 20000)];
        var host = await f.CreateAsync().ConfigureAwait(true);
        var clock = new AnchorPollingFixture.ClockProvider(f.Inputs.Anchors.Keys.Clock);
        var running = f.RunAsync(host, f.Inputs.Refresh,
            new DnssecAnchorPollingPolicy(TimeSpan.FromHours(1), TimeSpan.FromHours(1), 2), clock, stop.Token);
        try
        {
            var endpoint = await host.WaitForBoundAsync(guard.Token).ConfigureAwait(true);
            _ = await clock.NextTimerAsync().ConfigureAwait(true);
            var request = ClientRequestFixture.Request();
            var first = await NativeClientListenerFixture.UdpAsync(endpoint, request, guard.Token).ConfigureAwait(true);
            var decoded = UpstreamMessageCodec.DecodeDnssecResponse(first, BinaryPrimitives.ReadUInt16BigEndian(request),
                f.Inputs.Question, new DnsServerEndpoint(endpoint.Address.GetAddressBytes(), (ushort)endpoint.Port));
            Assert.False(decoded.Truncated);
            Assert.True(Assert.Single(decoded.Evidence.Answers, record => record.Type == 1).Ttl > 3600);
            var before = f.Inputs.Calls.Count;
            Assert.Equal(first, await NativeClientListenerFixture.UdpAsync(endpoint, request, guard.Token).ConfigureAwait(true));
            Assert.Equal(before, f.Inputs.Calls.Count);
            clock.Set(3600); f.Inputs.Timers.WallTime = f.Inputs.Anchors.Keys.Clock.GetUtcNow();
            f.Inputs.Timers.Set(TimeSpan.FromSeconds(3600));
            _ = await clock.NextTimerAsync().ConfigureAwait(true); Assert.Equal(2, f.Inputs.Refresh.Current.Revision);
            f.Inputs.LastOctet = 2;
            var next = await NativeClientListenerFixture.UdpAsync(endpoint, request, guard.Token).ConfigureAwait(true);
            var answer = UpstreamMessageCodec.DecodeDnssecResponse(next, BinaryPrimitives.ReadUInt16BigEndian(request),
                f.Inputs.Question, new DnsServerEndpoint(endpoint.Address.GetAddressBytes(), (ushort)endpoint.Port));
            Assert.False(answer.Truncated);
            Assert.Equal([192, 0, 2, 2], Assert.Single(answer.Evidence.Answers, record => record.Type == 1).GetData());
            Assert.Equal(before + 2, f.Inputs.Calls.Count); Assert.Equal(1, f.Inputs.Anchors.Store.Commits);
            await stop.CancelAsync().ConfigureAwait(true);
            await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(0, clock.ActiveTimers); Assert.Equal(0, host.ActiveWorkers); Assert.Equal(0, host.ActiveRequests);
        }
        finally { await stop.CancelAsync().ConfigureAwait(true); }
    }
}
