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
if (mode is "recursive" or "recursive-refresh" or "recursive-checking-disabled" or "recursive-refresh-checking-disabled")
{
    await RecursiveStartup.RunAsync(secrets, mode).ConfigureAwait(false);
    return;
}
if (mode is not "authority") throw new InvalidDataException("SecretModeInvalid");
var settings = ApplicationSettings.FromSecrets(secrets);
PrivateUnixSocket.ValidatePath(settings.SocketPath);
if (settings.PublicationSocket is { } publicationPath) PrivateUnixSocket.ValidatePath(publicationPath);
var policy = ServiceHostPolicy.FromSecrets(secrets);
var limits = settings.UdpResponseLimits;
var limiter = string.Equals(settings.Role, "authoritative-replica", StringComparison.Ordinal)
    ? new DnsResponseLimiter(TimeProvider.System, limits.ResponsesPerSecond, limits.ResponseBurst, limits.BytesPerSecond, limits.ByteBurst,
        limits.GlobalResponsesPerSecond, limits.GlobalResponseBurst, limits.GlobalBytesPerSecond, limits.GlobalByteBurst, limits.MaximumPrefixes)
    : null;
using var cookies = string.Equals(settings.Role, "authoritative-replica", StringComparison.Ordinal) ? CookieSecrets.Load(settings, secrets) : null;
using var tsig = string.Equals(settings.Role, "authoritative-replica", StringComparison.Ordinal) ? TsigKeys.Load(settings, secrets) : null;
var control = new ControlRuntime();
PrivateUnixSocket? socket = null;
PrivateUnixSocket? publicationSocket = null;
List<Exception?> failures = [];
try
{
    failures.Add(await ServiceExecution.CaptureAsync(RunAuthorityAsync, CancellationToken.None).ConfigureAwait(false));
}
finally
{
    // ControlRuntime returns its retained close task; that task joins the actual
    // publication tail and snapshot owner before either IPC lease is released.
    var closing = control.DisposeAsync().AsTask();
    failures.Add(await ServiceExecution.CaptureAsync(() => closing.WaitAsync(CancellationToken.None), CancellationToken.None).ConfigureAwait(false));
    failures.Add(await ServiceExecution.CaptureAsync(() => { publicationSocket?.Dispose(); return Task.CompletedTask; }, CancellationToken.None).ConfigureAwait(false));
    failures.Add(await ServiceExecution.CaptureAsync(() => { socket?.Dispose(); return Task.CompletedTask; }, CancellationToken.None).ConfigureAwait(false));
}
ServiceExecution.ThrowFailures(failures);

async Task RunAuthorityAsync()
{
    control.Prepare(settings, secrets);
    socket = new PrivateUnixSocket(settings.SocketPath);
    var snapshots = control.OpenSnapshots(settings.StateDirectory);
    await control.InitializeAsync(settings, snapshots, cookies, tsig, limiter).ConfigureAwait(false);
    var authority = await ReadAuthorityAsync(snapshots).ConfigureAwait(false);

    var maximumRequestBytes = (control.Management is not null ? ControlHostingExtensions.MaximumManagementBytes
        : authority is null ? ProtocolVersion.MaximumMessageBytes : QueryHostingExtensions.MaximumExchangeBytes) + 5;
    var builder = AuthorityHostBuilder.Create(socket, policy, maximumRequestBytes, policy.ApplicationStreams);
    IApplicationStatusSource statusSource = authority ?? (IApplicationStatusSource)new ApplicationStatusSource(snapshots, settings.NodeId, settings.Role);
    builder.Services.AddApplicationProbe(statusSource);
    if (authority is not null)
        builder.Services.AddAuthoritativeQuery(authority);
    if (control.Management is not null)
        builder.Services.AddZoneManagement(control.Management);

    var application = builder.Build();
    await ServiceExecution.RunAsync(async () =>
    {
        application.MapApplicationProbe();
        if (authority is not null)
            application.MapAuthoritativeQuery();
        if (control.Management is not null)
            application.MapZoneManagement();
        publicationSocket = settings.PublicationSocket is null ? null : new PrivateUnixSocket(settings.PublicationSocket);
        WebApplication? publicationHost = null;
        await ServiceExecution.RunAsync(async () =>
        {
            if (publicationSocket is not null && control.Publication is not null)
            {
                var publicationBuilder = AuthorityHostBuilder.Create(publicationSocket, policy,
                    ControlHostingExtensions.MaximumPublicationBytes + 5, policy.PublicationStreams);
                publicationBuilder.Services.AddZonePublication(control.Publication);
                publicationHost = publicationBuilder.Build();
                publicationHost.MapZonePublication();
            }
            await PublicationHostExecution.RunAsync(application, publicationHost, socket.SetSocketPermissions,
                () => publicationSocket?.SetSocketPermissions(),
                token => control.PublishAsync(application.Logger, token)).ConfigureAwait(false);
        }, async () =>
        {
            if (publicationHost is not null) await publicationHost.DisposeAsync().ConfigureAwait(false);
        }, () =>
        {
            if (limiter is not null)
            {
                var (admitted, dropped, trackedPrefixes) = limiter.Statistics;
                UdpBudgetLogs.Totals(application.Logger, admitted, dropped, trackedPrefixes);
            }
            return Task.CompletedTask;
        }).ConfigureAwait(false);
    }, () => application.DisposeAsync().AsTask()).ConfigureAwait(false);
}

async Task<AuthoritativeApplication?> ReadAuthorityAsync(FileZoneSnapshotStore snapshots)
{
    if (settings.ZoneIds.Count == 0) return control.Authority;
    _ = await snapshots.CountActiveAsync(CancellationToken.None).ConfigureAwait(false);
    List<ZoneContents> zones = [];
    foreach (var id in settings.ZoneIds)
    {
        var snapshot = await snapshots.ReadActiveAsync(id, CancellationToken.None).ConfigureAwait(false)
            ?? throw new InvalidDataException("A configured authoritative zone has no active generation.");
        zones.Add(SignedZoneBundleCodec.Decode(snapshot));
    }
    return new AuthoritativeApplication(new AuthoritativeCatalog(zones, new EcdsaP256DnssecVerifier(), TimeProvider.System),
        new DnsMessageCodecAdapter(), settings.NodeId, cookies, tsig, limiter);
}
