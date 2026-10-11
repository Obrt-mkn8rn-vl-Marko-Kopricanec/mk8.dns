using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientListener
{
    private async Task ExecuteAsync(CancellationToken external)
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        CancellationTokenSource lifetime;
        lock (gate) lifetime = cancellation ?? throw new InvalidOperationException("Missing native listener lifetime.");
        var served = ObserveExternalAndServeAsync(external, lifetime.Token);
        var failure = await CaptureAsync(served, expectedCancellation: true, lifetime.Token).ConfigureAwait(false);
        RequestStop();
        Task? dispatch;
        lock (gate) { finishing = true; dispatch = cancellationDispatch; }
        var cleanup = dispatch is null ? null
            : await CaptureAsync(dispatch, expectedCancellation: false, lifetime.Token).ConfigureAwait(false);
        failure = Combine(failure, cleanup);
        if (failure is not null)
        {
            bound.TrySetException(failure);
            _ = bound.Task.Exception;
        }
        else
        {
            bound.TrySetCanceled(new CancellationToken(canceled: true));
        }
        ThrowFailure(failure);
    }

    private async Task ObserveExternalAndServeAsync(CancellationToken external, CancellationToken token)
    {
        await using var registration = external.Register(RequestStop).ConfigureAwait(false);
        await BindAndServeAsync(token).ConfigureAwait(false);
    }

    private async Task BindAndServeAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var tcp = new TcpListener(Copy(endpoint));
        using var udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
        {
            tcp.Server.DualMode = false;
            udp.DualMode = false;
        }
        tcp.Start(maximumTcpConnections);
        var actual = (IPEndPoint)tcp.LocalEndpoint;
        udp.Bind(actual);
        token.ThrowIfCancellationRequested();
        bound.TrySetResult(Copy(actual));
        await ServeBoundAsync(udp, tcp, token).ConfigureAwait(false);
    }

    private async Task ServeBoundAsync(Socket udp, TcpListener tcp, CancellationToken token)
    {
        var tasks = Enumerable.Range(0, udpWorkers)
            .Select(_ => ObserveChildAsync(ServeUdpAsync(udp, token), token))
            .Append(ObserveChildAsync(AcceptTcpAsync(tcp, token), token)).ToArray();
        var all = Task.WhenAll(tasks);
        await Task.WhenAny(tasks).ConfigureAwait(false);
        RequestStop();
        ThrowFailure(await CaptureAsync(all, expectedCancellation: true, token).ConfigureAwait(false));
    }

    // Observe each child before its completion can initiate sibling teardown.
    // A fault marker retains unsolicited cancellation across every later drain,
    // even though those drains now see the requested listener token.
    private static async Task ObserveChildAsync(Task child, CancellationToken token)
    {
        var outcome = await CaptureAsync(child, expectedCancellation: true, token)
            .WaitAsync(CancellationToken.None).ConfigureAwait(false);
        if (outcome is OperationCanceledException canceled)
        {
            throw new AggregateException("Child cancellation was not an observed listener stop.", canceled);
        }
        ThrowFailure(outcome);
    }

    private static async Task<Exception?> CaptureAsync(Task task, bool expectedCancellation, CancellationToken token)
    {
        try { await task.WaitAsync(CancellationToken.None).ConfigureAwait(false); return null; }
        catch (OperationCanceledException canceled) when (expectedCancellation && token.IsCancellationRequested
            && canceled.CancellationToken == token && !task.IsFaulted)
        {
            return null;
        }
        catch (Exception error) when (task.IsFaulted || task.IsCanceled)
        {
            if (task.Exception is { InnerExceptions.Count: 1 } single) return single.InnerExceptions[0];
            return task.Exception ?? error;
        }
    }

    private static Exception? Combine(Exception? first, Exception? second)
        => first is null ? second : second is null ? first : new AggregateException(first, second);

    private static void ThrowFailure(Exception? failure)
    {
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private async Task FinishDisposalAsync()
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        Task? pending;
        lock (gate) pending = execution;
        try { if (pending is not null) await pending.ConfigureAwait(false); }
        finally { cancellation?.Dispose(); }
    }
}
