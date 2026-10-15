using Microsoft.AspNetCore.Server.Kestrel.Core;
using Mk8.Dns.Application;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Transport;
using Mk8.Dns.Wire;

if (args.Length != 0) throw new ArgumentException("ServiceArgumentsForbidden", nameof(args));
var secrets = await DnsServiceSecrets.LoadAsync("Application", CancellationToken.None).ConfigureAwait(false);
var mode = secrets.Text("Mode", 64);
if (mode is "recursive" or "recursive-refresh" or "recursive-checking-disabled")
{
    await RecursiveStartup.RunAsync(secrets, mode).ConfigureAwait(false);
    return;
}
if (mode is not "authority") throw new InvalidDataException("SecretModeInvalid");
var settings = ApplicationSettings.FromSecrets(secrets);
var policy = ServiceHostPolicy.FromSecrets(secrets);
var limits = settings.UdpResponseLimits;
var limiter = string.Equals(settings.Role, "authoritative-replica", StringComparison.Ordinal)
    ? new DnsResponseLimiter(TimeProvider.System, limits.ResponsesPerSecond, limits.ResponseBurst, limits.BytesPerSecond, limits.ByteBurst,
        limits.GlobalResponsesPerSecond, limits.GlobalResponseBurst, limits.GlobalBytesPerSecond, limits.GlobalByteBurst, limits.MaximumPrefixes)
    : null;
using var cookies = string.Equals(settings.Role, "authoritative-replica", StringComparison.Ordinal) ? CookieSecrets.Load(settings, secrets) : null;
using var tsig = string.Equals(settings.Role, "authoritative-replica", StringComparison.Ordinal) ? TsigKeys.Load(settings, secrets) : null;
var control = new ControlRuntime();
await using var controlLifetime = control.ConfigureAwait(false);
control.Prepare(settings, secrets);
using var socket = new PrivateUnixSocket(settings.SocketPath);
var snapshots = control.OpenSnapshots(settings.StateDirectory);
await control.InitializeAsync(settings, snapshots, cookies, tsig, limiter).ConfigureAwait(false);
AuthoritativeApplication? authority = control.Authority;
if (settings.ZoneIds.Count != 0)
{
    _ = await snapshots.CountActiveAsync(CancellationToken.None).ConfigureAwait(false);
    List<ZoneContents> zones = [];
    foreach (var id in settings.ZoneIds)
    {
        var snapshot = await snapshots.ReadActiveAsync(id, CancellationToken.None).ConfigureAwait(false)
            ?? throw new InvalidDataException("A configured authoritative zone has no active generation.");
        zones.Add(SignedZoneBundleCodec.Decode(snapshot));
    }
    authority = new AuthoritativeApplication(new AuthoritativeCatalog(zones, new EcdsaP256DnssecVerifier(), TimeProvider.System), new DnsMessageCodecAdapter(), settings.NodeId, cookies, tsig, limiter);
}

var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions { Args = [], EnvironmentName = "Production", ContentRootPath = AppContext.BaseDirectory });
builder.Configuration.Sources.Clear();
builder.WebHost.UseKestrelCore();
builder.Services.AddRouting();
builder.Host.UseConsoleLifetime();
builder.Configuration.AddInMemoryCollection([new KeyValuePair<string, string?>(WebHostDefaults.PreventHostingStartupKey, "true")]);
builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(policy.ShutdownSeconds));
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestHeadersTotalSize = policy.HeaderBytes;
    options.Limits.MaxRequestHeaderCount = policy.HeaderCount;
    options.Limits.MaxRequestLineSize = policy.RequestLineBytes;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(policy.HeaderTimeoutSeconds);
    options.Limits.MaxConcurrentConnections = policy.Connections;
    options.Limits.MaxRequestBodySize = (control.Management is not null ? ControlHostingExtensions.MaximumManagementBytes : authority is null ? ProtocolVersion.MaximumMessageBytes : QueryHostingExtensions.MaximumExchangeBytes) + 5;
    options.Limits.Http2.MaxStreamsPerConnection = policy.ApplicationStreams;
    options.ListenUnixSocket(socket.Path, endpoint => endpoint.Protocols = HttpProtocols.Http2);
});
IApplicationStatusSource statusSource = authority ?? (IApplicationStatusSource)new ApplicationStatusSource(snapshots, settings.NodeId, settings.Role);
builder.Services.AddApplicationProbe(statusSource);
if (authority is not null)
    builder.Services.AddAuthoritativeQuery(authority);
if (control.Management is not null)
    builder.Services.AddZoneManagement(control.Management);

var application = builder.Build();
await using (application.ConfigureAwait(false))
{
    application.MapApplicationProbe();
    if (authority is not null)
        application.MapAuthoritativeQuery();
    if (control.Management is not null)
        application.MapZoneManagement();
    using var publicationSocket = settings.PublicationSocket is null ? null : new PrivateUnixSocket(settings.PublicationSocket);
    WebApplication? publicationHost = null;
    using var shutdown = new CancellationTokenSource();
    Task publishing = Task.CompletedTask;
    try
    {
        if (publicationSocket is not null && control.Publication is not null)
        {
            var publicationBuilder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions { Args = [], EnvironmentName = "Production", ContentRootPath = AppContext.BaseDirectory });
            publicationBuilder.Configuration.Sources.Clear();
            publicationBuilder.WebHost.UseKestrelCore();
            publicationBuilder.Services.AddRouting();
            publicationBuilder.Host.UseConsoleLifetime();
            publicationBuilder.Configuration.AddInMemoryCollection([new KeyValuePair<string, string?>(WebHostDefaults.PreventHostingStartupKey, "true")]);
            publicationBuilder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(policy.ShutdownSeconds));
            publicationBuilder.Logging.ClearProviders();
            publicationBuilder.Logging.AddJsonConsole();
            publicationBuilder.WebHost.ConfigureKestrel(options =>
            {
                options.AddServerHeader = false;
                options.Limits.MaxRequestHeadersTotalSize = policy.HeaderBytes;
                options.Limits.MaxRequestHeaderCount = policy.HeaderCount;
                options.Limits.MaxRequestLineSize = policy.RequestLineBytes;
                options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(policy.HeaderTimeoutSeconds);
                options.Limits.MaxConcurrentConnections = policy.Connections;
                options.Limits.MaxRequestBodySize = ControlHostingExtensions.MaximumPublicationBytes + 5;
                options.Limits.Http2.MaxStreamsPerConnection = policy.PublicationStreams;
                options.ListenUnixSocket(publicationSocket.Path, endpoint => endpoint.Protocols = HttpProtocols.Http2);
            });
            publicationBuilder.Services.AddZonePublication(control.Publication);
            publicationHost = publicationBuilder.Build();
            publicationHost.MapZonePublication();
            await publicationHost.StartAsync().ConfigureAwait(false);
            publicationSocket.SetSocketPermissions();
        }
        await application.StartAsync().ConfigureAwait(false);
        socket.SetSocketPermissions();
        publishing = PublishAndStopOnFailureAsync(control, application.Logger, application.Lifetime, shutdown.Token);
        await application.WaitForShutdownAsync().ConfigureAwait(false);
    }
    finally
    {
        await shutdown.CancelAsync().ConfigureAwait(false);
        if (publicationHost is not null)
        {
            await publicationHost.StopAsync().ConfigureAwait(false);
            await publicationHost.DisposeAsync().ConfigureAwait(false);
        }
        await publishing.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        if (limiter is not null)
        {
            var (admitted, dropped, trackedPrefixes) = limiter.Statistics;
            UdpBudgetLogs.Totals(application.Logger, admitted, dropped, trackedPrefixes);
        }
    }
}

static async Task PublishAndStopOnFailureAsync(ControlRuntime control, ILogger logger, IHostApplicationLifetime lifetime, CancellationToken cancellationToken)
{
    try
    {
        await control.PublishAsync(logger, cancellationToken).ConfigureAwait(false);
    }
    catch
    {
        lifetime.StopApplication();
        throw;
    }
}
