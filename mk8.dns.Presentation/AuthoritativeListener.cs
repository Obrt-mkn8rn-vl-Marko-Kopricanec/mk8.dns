using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Grpc.Core;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Presentation;

public sealed class AuthoritativeListener
{
    private readonly IPEndPoint endpoint;
    private readonly IDnsExchange exchange;
    private readonly int maximumTcpConnections;
    private readonly int maximumTcpMessages;
    private readonly TimeSpan frameTimeout;

    public AuthoritativeListener(IPEndPoint endpoint, IDnsExchange exchange)
        : this(endpoint, exchange, 16, 100, TimeSpan.FromSeconds(2)) { }

    public AuthoritativeListener(IPEndPoint endpoint, IDnsExchange exchange,
        int maximumTcpConnections, int maximumTcpMessages, TimeSpan frameTimeout)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(exchange);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumTcpConnections, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumTcpConnections, 16);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumTcpMessages, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumTcpMessages, 100);
        ArgumentOutOfRangeException.ThrowIfLessThan(frameTimeout, TimeSpan.FromMilliseconds(1));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(frameTimeout, TimeSpan.FromSeconds(2));
        if (endpoint.Port == 0)
            throw new ArgumentException("An explicit DNS port is required.", nameof(endpoint));
        if (endpoint.Address.GetAddressBytes().AsSpan().IndexOfAnyExcept((byte)0) < 0 || (endpoint.Address.IsIPv4MappedToIPv6 && endpoint.Address.MapToIPv4().Equals(IPAddress.Any)))
            throw new ArgumentException("DNS requires a specific bind address to preserve UDP reply source identity.", nameof(endpoint));
        this.endpoint = new IPEndPoint(endpoint.Address, endpoint.Port);
        this.exchange = exchange;
        this.maximumTcpConnections = maximumTcpConnections;
        this.maximumTcpMessages = maximumTcpMessages;
        this.frameTimeout = frameTimeout;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using var tcp = new TcpListener(endpoint);
        if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
        {
            udp.DualMode = false;
            tcp.Server.DualMode = false;
        }
        udp.Bind(endpoint);
        tcp.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, optionValue: true);
        tcp.Start(maximumTcpConnections);
        await PropagateCancellationAsync(RunServersAsync(udp, tcp, lifetime), cancellationToken, lifetime.Token).ConfigureAwait(false);
    }

    private static async Task PropagateCancellationAsync(Task actual, CancellationToken owner, CancellationToken linked)
    {
        try { await actual.WaitAsync(CancellationToken.None).ConfigureAwait(false); }
        catch (OperationCanceledException error) when (actual.IsCanceled && owner.IsCancellationRequested
            && linked.IsCancellationRequested && error.CancellationToken == linked)
        {
            // Retire the linked source only after its real operation settles.
            // Expose the requesting owner's token, retaining the inner outcome.
            throw new OperationCanceledException("Authoritative listener stopped.", error, owner);
        }
    }

    private async Task RunServersAsync(Socket udp, TcpListener tcp, CancellationTokenSource lifetime)
    {
        var tasks = new[] { ServeUdpAsync(udp, lifetime.Token), AcceptTcpAsync(tcp, lifetime.Token) };
        var finished = await Task.WhenAny(tasks).ConfigureAwait(false);
        List<Exception> errors = [];
        await CaptureAsync(finished, errors).ConfigureAwait(false);
        await StopAndDrainAsync(lifetime, tasks.Where(task => !ReferenceEquals(task, finished)), errors).ConfigureAwait(false);
    }

    private static async Task CaptureAsync(Task task, List<Exception> errors)
    {
        try { await task.WaitAsync(CancellationToken.None).ConfigureAwait(false); }
        catch (Exception error) when (task.IsFaulted || task.IsCanceled) { errors.Add(error); }
    }

    private static async Task StopAndDrainAsync(CancellationTokenSource lifetime, IEnumerable<Task> tasks, List<Exception> errors)
    {
        var stopping = CancelAsync(lifetime);
        // Callback dispatch and admitted work are independent owned operations.
        // A failed dispatcher must not skip a still-live server or connection.
        await CaptureAsync(stopping, errors).ConfigureAwait(false);
        foreach (var task in tasks) await CaptureAsync(task, errors).ConfigureAwait(false);
        if (errors.Count == 1 || (errors.Count != 0 && lifetime.IsCancellationRequested
            && errors.TrueForAll(error => error is OperationCanceledException canceled && canceled.CancellationToken == lifetime.Token)))
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(errors[0]).Throw();
        }
        if (errors.Count != 0) throw new AggregateException(errors);
    }

    private static async Task CancelAsync(CancellationTokenSource lifetime)
        => await lifetime.CancelAsync().ConfigureAwait(false);

    private async Task ServeUdpAsync(Socket socket, CancellationToken token)
    {
        var buffer = new byte[ushort.MaxValue];
        var any = new IPEndPoint(endpoint.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
        while (true)
        {
            try
            {
                var received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, token).ConfigureAwait(false);
                var peer = (IPEndPoint)received.RemoteEndPoint;
                var reply = await exchange.ExchangeAsync(buffer.AsMemory(0, received.ReceivedBytes), tcp: false, peer.Address.GetAddressBytes(), token).ConfigureAwait(false);
                if (reply.Length > 1232)
                    throw new InvalidDataException("Application exceeded the UDP response bound.");
                if (reply.Length != 0)
                    _ = await socket.SendToAsync(reply, SocketFlags.None, peer, token).ConfigureAwait(false);
            }
            catch (RpcException)
            {
                // An unavailable Application causes UDP loss, never fabricated answer data.
            }
            catch (SocketException exception) when (exception.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
            {
                // A vanished UDP peer must not terminate the listener.
            }
        }
    }

    private async Task AcceptTcpAsync(TcpListener listener, CancellationToken token)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var admission = new SemaphoreSlim(maximumTcpConnections, maximumTcpConnections);
        await PropagateCancellationAsync(AcceptConnectionsAsync(listener, admission, lifetime), token, lifetime.Token).ConfigureAwait(false);
    }

    private async Task AcceptConnectionsAsync(TcpListener listener, SemaphoreSlim admission, CancellationTokenSource lifetime)
    {
        List<Task> connections = [];
        Task<Socket>? pendingAccept = null;
        var accepting = AcceptLoopAsync();
        List<Exception> errors = [];
        await CaptureAsync(accepting, errors).ConfigureAwait(false);
        // A child can finish while accept is suspended. The outstanding accept
        // still owns any socket it returns, even when that child faults first.
        if (pendingAccept is not null) connections.Add(RetireAcceptAsync(pendingAccept));
        await StopAndDrainAsync(lifetime, connections, errors).ConfigureAwait(false);

        async Task AcceptLoopAsync()
        {
            while (true)
            {
                foreach (var finished in connections.Where(task => task.IsCompleted).ToArray())
                {
                    connections.Remove(finished);
                    await finished.ConfigureAwait(false);
                }
                pendingAccept ??= listener.AcceptSocketAsync(lifetime.Token).AsTask();
                var completed = await Task.WhenAny(connections.Append(pendingAccept)).ConfigureAwait(false);
                if (!ReferenceEquals(completed, pendingAccept)) continue;
                var accepted = pendingAccept;
                pendingAccept = null;
                var socket = await accepted.ConfigureAwait(false);
                connections.Add(AdmitAndServeAsync(socket, admission, lifetime.Token));
            }
        }
    }

    private static async Task RetireAcceptAsync(Task<Socket> accept)
    {
        using var socket = await accept.WaitAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private async Task AdmitAndServeAsync(Socket socket, SemaphoreSlim admission, CancellationToken token)
    {
        using (socket)
        {
            if (await admission.WaitAsync(0, token).ConfigureAwait(false))
                await ServeTcpAsync(socket, admission, token).ConfigureAwait(false);
        }
    }

    private async Task ServeTcpAsync(Socket socket, SemaphoreSlim admission, CancellationToken token)
    {
        try
        {
            var stream = new NetworkStream(socket, ownsSocket: true);
            await using var streamLifetime = stream.ConfigureAwait(false);
            var peer = ((IPEndPoint)socket.RemoteEndPoint!).Address.GetAddressBytes();
            var prefix = new byte[2];
            for (var count = 0; count < maximumTcpMessages; count++)
            {
                using var frame = CancellationTokenSource.CreateLinkedTokenSource(token);
                frame.CancelAfter(frameTimeout);
                await stream.ReadExactlyAsync(prefix, frame.Token).ConfigureAwait(false);
                var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
                if (length == 0)
                    return;
                var message = new byte[length];
                await stream.ReadExactlyAsync(message, frame.Token).ConfigureAwait(false);
                var reply = await exchange.ExchangeAsync(message, tcp: true, peer, frame.Token).ConfigureAwait(false);
                if (reply.Length == 0)
                    return;
                if (reply.Length > ushort.MaxValue)
                    throw new InvalidDataException("Application exceeded the TCP response bound.");
                BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)reply.Length);
                await stream.WriteAsync(prefix, frame.Token).ConfigureAwait(false);
                await stream.WriteAsync(reply, frame.Token).ConfigureAwait(false);
            }
        }
        catch (IOException) { }
        catch (SocketException) { }
        catch (RpcException) { }
        catch (OperationCanceledException) { }
        finally
        {
            socket.Dispose();
            admission.Release();
        }
    }
}
