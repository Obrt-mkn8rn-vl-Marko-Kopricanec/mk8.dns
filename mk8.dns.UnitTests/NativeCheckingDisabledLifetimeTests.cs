using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeCheckingDisabledLifetimeTests
{
    [Fact]
    public async Task HostCloseJoinsActualUncheckedProviderBeforeBorrowedInputsClose()
    {
        var f = new NativeCheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync().ConfigureAwait(true); var running = host.RunAsync(deadline.Token);
        var endpoint = await host.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Inputs.Override = (_, _, _) => { entered.TrySetResult(); return new ValueTask<DnsUpstreamEvidence>(held.Task); };
        using var peer = new UdpClient(); peer.Connect(endpoint);
        Task? first = null; Task? repeated = null;
        try
        {
            _ = await peer.SendAsync(CheckingDisabledMaterialFixture.Request(), deadline.Token).ConfigureAwait(true);
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers);
            first = host.DisposeAsync().AsTask(); repeated = host.DisposeAsync().AsTask();
            Assert.False(first.IsCompleted); Assert.False(repeated.IsCompleted); Assert.False(running.IsCompleted);
            Assert.Equal(1, host.ActiveRequests); Assert.Empty(f.Inputs.Epoch.Calls);
        }
        finally
        {
            var question = f.Inputs.Epoch.Question;
            var record = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 42]);
            held.TrySetResult(CheckingDisabledMaterialFixture.Reply(question, AnchorRefreshFixture.Server, [record]));
            await Task.WhenAll(running, first ?? host.DisposeAsync().AsTask(), repeated ?? host.DisposeAsync().AsTask())
                .WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        }
        Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers); Assert.Equal(1, f.Inputs.Epoch.Refresh.Current.Revision);
        Assert.False(deadline.IsCancellationRequested);
    }
}
