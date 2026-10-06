using System.Collections.Concurrent;
using Grpc.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ControlAdmissionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AdmissionIsBoundedAndInFlightHandlersCanCompleteAfterHostDisposal(bool publication)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var root = Path.Combine(Path.GetTempPath(), "m8control-" + Guid.NewGuid().ToString("N"));
        using var socket = new PrivateUnixSocket(Path.Combine(root, "app.sock"));
        var source = new BlockingPort();
        var errors = new ExceptionLog();
        using var errorsLifetime = errors;
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(errors);
        builder.WebHost.ConfigureKestrel(options => options.ListenUnixSocket(socket.Path, endpoint => endpoint.Protocols = HttpProtocols.Http2));
        if (publication)
            builder.Services.AddZonePublication(source);
        else
            builder.Services.AddZoneManagement(source);
        var host = builder.Build();
        await using var hostLifetime = host.ConfigureAwait(true);
        try
        {
            if (publication)
                host.MapZonePublication();
            else
                host.MapZoneManagement();
            await host.StartAsync(timeout.Token).ConfigureAwait(true);
            socket.SetSocketPermissions();
            await CheckShutdownAsync(host, socket.Path, source, errors, publication, timeout.Token).ConfigureAwait(true);
        }
        finally
        {
            source.Resume.TrySetResult();
            await host.DisposeAsync().ConfigureAwait(true);
            socket.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task CheckShutdownAsync(WebApplication host, string socketPath, BlockingPort source, ExceptionLog errors, bool publication, CancellationToken token)
    {
        using var client = new UnixControlClient(socketPath);
        IZoneManagement managementPort = client;
        IZonePublication publicationPort = client;
        var calls = Enumerable.Range(0, 4).Select(_ => CallAsync(managementPort, publicationPort, publication, token)).ToArray();
        await source.Entered.Task.WaitAsync(token).ConfigureAwait(true);
        var rejected = await Assert.ThrowsAsync<RpcException>(() => CallAsync(managementPort, publicationPort, publication, token)).ConfigureAwait(true);
        Assert.Equal(StatusCode.ResourceExhausted, rejected.StatusCode);
        using var shutdown = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await host.StopAsync(shutdown.Token).ConfigureAwait(true);
        await host.DisposeAsync().ConfigureAwait(true);
        source.Resume.SetResult();
        await source.Returned.Task.WaitAsync(token).ConfigureAwait(true);
        foreach (var call in calls)
        {
            try { await call.WaitAsync(token).ConfigureAwait(true); }
            catch (RpcException) { }
        }
        // Let the server finish reporting the abandoned responses after the controlled ports return.
        await Task.Delay(TimeSpan.FromMilliseconds(200), token).ConfigureAwait(true);
        Assert.DoesNotContain(errors.Exceptions, error => error.ToString().Contains(nameof(SemaphoreSlim), StringComparison.Ordinal));
    }

    private static async Task CallAsync(IZoneManagement management, IZonePublication publisher, bool publication, CancellationToken token)
    {
        if (publication)
            _ = await publisher.ExecuteAsync(new PublicationRequest("prepare", ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, new string('0', 64)), token).ConfigureAwait(true);
        else
            _ = await management.ExecuteAsync(new ManagementRequest("edit", Guid.Empty, Guid.Empty, Guid.Empty, 0, ReadOnlyMemory<byte>.Empty, Array.Empty<ZoneRecordData>(), ReadOnlyMemory<byte>.Empty), token).ConfigureAwait(true);
    }

    private sealed class BlockingPort : IZoneManagement, IZonePublication
    {
        private int entered;
        private int returned;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Returned { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<ManagementReply> ExecuteAsync(ManagementRequest request, CancellationToken cancellationToken)
        {
            await WaitAsync().ConfigureAwait(true);
            return new ManagementReply(request.OperationId, 1, 1, new string('0', 64), "accepted");
        }

        public async ValueTask<PublicationReply> ExecuteAsync(PublicationRequest request, CancellationToken cancellationToken)
        {
            await WaitAsync().ConfigureAwait(true);
            return new PublicationReply("node", Guid.Empty, 1, new string('0', 64), request.PublicationId, "prepared");
        }

        private async Task WaitAsync()
        {
            if (Interlocked.Increment(ref entered) == 4)
                Entered.SetResult();
            await Resume.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            if (Interlocked.Increment(ref returned) == 4)
                Returned.SetResult();
        }
    }

    private sealed class ExceptionLog : ILoggerProvider
    {
        internal ConcurrentQueue<Exception> Exceptions { get; } = new();
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(Exceptions);
        public void Dispose() { }

        private sealed class CaptureLogger(ConcurrentQueue<Exception> exceptions) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (exception is not null)
                    exceptions.Enqueue(exception);
            }
        }
    }
}
