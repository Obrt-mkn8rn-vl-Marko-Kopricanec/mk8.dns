using System.Net;
using System.Net.Sockets;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientListener
{
    private async Task AcceptTcpAsync(TcpListener listener, CancellationToken token)
    {
        using var admission = new SemaphoreSlim(maximumTcpConnections, maximumTcpConnections);
        await AcceptAndDrainAsync(listener, admission, token).ConfigureAwait(false);
    }

    private async Task AcceptAndDrainAsync(TcpListener listener, SemaphoreSlim admission, CancellationToken token)
    {
        List<Task> connections = [];
        var accepting = AcceptConnectionsAsync(listener, admission, connections, token);
        var failure = await CaptureAsync(accepting, expectedCancellation: true, token).ConfigureAwait(false);
        RequestStop();
        var all = Task.WhenAll(connections);
        var cleanup = await CaptureAsync(all, expectedCancellation: true, token).ConfigureAwait(false);
        ThrowFailure(Combine(failure, cleanup));
    }

    private async Task AcceptConnectionsAsync(TcpListener listener, SemaphoreSlim admission, List<Task> connections,
        CancellationToken token)
    {
        while (true)
        {
            foreach (var done in connections.Where(task => task.IsCompleted).ToArray())
            {
                await done.ConfigureAwait(false); connections.Remove(done);
            }
            // Reserve before accept: no unbounded accepted-socket/task queue.
            await admission.WaitAsync(token).ConfigureAwait(false);
            Socket socket;
            try { socket = await listener.AcceptSocketAsync(token).ConfigureAwait(false); }
            catch { admission.Release(); throw; }
            Interlocked.Increment(ref activeTcp);
            connections.Add(ServeConnectionAsync(socket, admission, token));
        }
    }

    private async Task ServeConnectionAsync(Socket socket, SemaphoreSlim admission, CancellationToken token)
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        var serving = ServeAndClosePeerAsync(socket, token);
        try { await serving.ConfigureAwait(false); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception) when (serving.IsFaulted || serving.IsCanceled) { RequestStop(); throw; }
        finally { Interlocked.Decrement(ref activeTcp); admission.Release(); }
    }

    private async Task ServeAndClosePeerAsync(Socket socket, CancellationToken token)
    {
        using (socket)
        {
            if (socket.RemoteEndPoint is not IPEndPoint peer) throw new IOException("Missing native TCP peer.");
            DnssecNativePeerStream? stream = null;
            try
            {
                await using var streamLifetime = (stream = new DnssecNativePeerStream(socket)).ConfigureAwait(false);
                try
                {
                    var session = new DnssecClientTcpSession(processor, stream, peer.Address.GetAddressBytes(), maximumTcpMessages);
                    await using var sessionLifetime = session.ConfigureAwait(false);
                    _ = await session.RunAsync(token).ConfigureAwait(false);
                }
                catch (IOException error) when (stream.IsPeerFailure(error)) { }
            }
            // Only failure before construction is native stream admission.
            // Once owned, source/clock errors remain outside this filter.
            catch (IOException) when (stream is null) { }
        }
    }

}
