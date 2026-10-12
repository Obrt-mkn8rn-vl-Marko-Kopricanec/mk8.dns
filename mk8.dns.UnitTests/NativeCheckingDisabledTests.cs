using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeCheckingDisabledTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(false, true, true)]
    [InlineData(true, false, false)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    public async Task ExplicitNativeProfilesKeepUncheckedMaterialOutOfAdAndAuthenticatedCache(bool material, bool dnssecOk, bool tcp)
    {
        var f = new NativeCheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync(material).ConfigureAwait(true); var running = host.RunAsync(deadline.Token);
        var endpoint = await host.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        var before = f.Inputs.Epoch.Verifier.Calls;
        var request = CheckingDisabledMaterialFixture.Request(dnssecOk: dnssecOk);
        var first = await QueryAsync(endpoint, request, tcp, deadline.Token).ConfigureAwait(true);
        if (!material && dnssecOk)
        {
            ClientRequestFixture.AssertError(request, first, 4); Assert.Empty(f.Inputs.Upstream.Calls);
        }
        else
        {
            var question = Assert.IsType<DnsQuestion>(DnsMessageCodec.DecodeQuery(request).Question);
            var answer = UpstreamMessageCodec.DecodeResponse(first, 0xabcd, question).Answer;
            Assert.Equal(0, answer.ResponseCode); Assert.Single(answer.Answers, record => record.Type == 1);
            Assert.Equal(dnssecOk, answer.Answers.Any(record => record.Type == 46));
            Assert.Equal(0x8190, BinaryPrimitives.ReadUInt16BigEndian(first.AsSpan(2)));
            _ = await QueryAsync(endpoint, request, tcp, deadline.Token).ConfigureAwait(true);
            Assert.Equal(2, f.Inputs.Upstream.Calls.Count); // Unchecked answers are never stored in the validating cache.
        }
        Assert.Empty(f.Inputs.Epoch.Calls); Assert.Equal(before, f.Inputs.Epoch.Verifier.Calls);
        var checkedPacket = ClientRequestFixture.Request();
        var checkedFirst = await QueryAsync(endpoint, checkedPacket, tcp, deadline.Token).ConfigureAwait(true);
        Assert.Equal(0x81a0, BinaryPrimitives.ReadUInt16BigEndian(checkedFirst.AsSpan(2)));
        var calls = f.Inputs.Epoch.Calls.Count; var verified = f.Inputs.Epoch.Verifier.Calls;
        Assert.Equal(checkedFirst, await QueryAsync(endpoint, checkedPacket, tcp, deadline.Token).ConfigureAwait(true));
        Assert.Equal(calls, f.Inputs.Epoch.Calls.Count); Assert.Equal(verified, f.Inputs.Epoch.Verifier.Calls);
        await Task.WhenAll(host.DisposeAsync().AsTask(), host.DisposeAsync().AsTask(), running)
            .WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers); Assert.Equal(0, host.ActiveTcpConnections);
        Assert.Equal(1, f.Inputs.Epoch.Refresh.Current.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UncheckedBorrowedCancellationRemainsNonSuccessfulThroughRepeatedClosure(bool tcp)
    {
        var f = new NativeCheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync().ConfigureAwait(true); var running = host.RunAsync(deadline.Token);
        var endpoint = await host.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        var failure = new OperationCanceledException("Controlled unchecked borrowed source cancellation.");
        f.ExpectedFailure = failure;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Inputs.Override = (_, _, _) => { entered.TrySetResult(); return ValueTask.FromException<DnsUpstreamEvidence>(failure); };
        using var peer = new UdpClient();
        if (tcp)
        {
            using var client = new TcpClient(); await client.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(true);
            var stream = client.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
            await stream.WriteAsync(TcpSessionFixture.Frame(CheckingDisabledMaterialFixture.Request()), deadline.Token).ConfigureAwait(true);
            try { _ = await stream.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(true); }
            catch (IOException) { }
        }
        else { peer.Connect(endpoint); _ = await peer.SendAsync(CheckingDisabledMaterialFixture.Request(), deadline.Token).ConfigureAwait(true); }
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var initial = await Assert.ThrowsAnyAsync<Exception>(() => running.WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.True(NativeClientListenerFixture.OnlyExpected(initial, failure));
        foreach (var pending in new[] { running, host.DisposeAsync().AsTask(), host.DisposeAsync().AsTask() })
        {
            var observed = await Assert.ThrowsAnyAsync<Exception>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout,
                TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.True(NativeClientListenerFixture.OnlyExpected(observed, failure)); Assert.False(pending.IsCompletedSuccessfully);
        }
        Assert.False(deadline.IsCancellationRequested); Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers);
        Assert.Empty(f.Inputs.Epoch.Calls); Assert.Equal(1, f.Inputs.Epoch.Refresh.Current.Revision);
    }

    internal static async Task<byte[]> QueryAsync(IPEndPoint endpoint, byte[] packet, bool tcp, CancellationToken token)
    {
        if (!tcp) return await NativeClientListenerFixture.UdpAsync(endpoint, packet, token).ConfigureAwait(true);
        using var peer = new TcpClient(endpoint.AddressFamily); await peer.ConnectAsync(endpoint, token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var lifetime = stream.ConfigureAwait(true);
        await stream.WriteAsync(TcpSessionFixture.Frame(packet), token).ConfigureAwait(true);
        return await NativeClientListenerFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
    }
}
