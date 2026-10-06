using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Mk8.Dns.Contracts;
using Mk8.Dns.Presentation;
using Mk8.Dns.Transport;

namespace Mk8.Dns.UnitTests;

internal sealed class ManagementHttpFixture : IAsyncDisposable
{
    private readonly TemporaryDirectory directory = new();
    private readonly PrivateUnixSocket lease;
    private readonly WebApplication app;
    private readonly SocketsHttpHandler handler;
    internal ManagementHttpApi Api { get; }
    internal HttpClient Client { get; }
    internal string SocketPath => lease.Path;

    internal ManagementHttpFixture(IZoneManagement source, RequestDelegate? response = null)
    {
        lease = new PrivateUnixSocket(Path.Combine(directory.Path, "api.sock"));
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.ListenUnixSocket(lease.Path, endpoint => endpoint.Protocols = HttpProtocols.Http1));
        app = builder.Build();
        Api = new ManagementHttpApi(source);
        if (response is null)
            Api.Map(app);
        else
            app.Run(response);
        handler = new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            ConnectCallback = async (_, token) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(lease.Path), token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        Client = new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri("http://localhost"), Timeout = TimeSpan.FromSeconds(15) };
    }

    internal async Task StartAsync()
    {
        await app.StartAsync().ConfigureAwait(true);
        lease.SetSocketPermissions();
    }

    public async ValueTask DisposeAsync()
    {
        await Api.DisposeAsync().ConfigureAwait(true);
        await app.StopAsync().ConfigureAwait(true);
        await app.DisposeAsync().ConfigureAwait(true);
        Client.Dispose();
        handler.Dispose();
        lease.Dispose();
        directory.Dispose();
    }
}
