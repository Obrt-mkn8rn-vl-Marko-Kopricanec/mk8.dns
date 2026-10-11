using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Configuration;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.Application;

internal static class RecursiveStartup
{
    internal static async Task RunAsync(string configurationPath)
    {
        var settings = RecursiveStartupConfiguration.Load(configurationPath);
        var verifier = new DnssecSignatureVerifier();
        var time = TimeProvider.System;
        var key = PrivateFile.Read(settings.KeyFile, 32);
        FileAnchorCheckpointStore store;
        try
        {
            if (key.Length != 32) throw new InvalidDataException("Anchor authentication key must contain exactly thirty-two raw bytes.");
            // Open only: no provisioning, inferred floor, legacy migration or retention maintenance.
            store = settings.Retention
                ? FileAnchorCheckpointStore.OpenWithRetention(settings.StoreDirectory, settings.StoreIdentity, settings.Origin, key,
                    settings.MinimumRevision, verifier, time)
                : FileAnchorCheckpointStore.Open(settings.StoreDirectory, settings.StoreIdentity, settings.Origin, key,
                    settings.MinimumRevision, verifier, time);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        using var storeLifetime = store;
        var upstream = new DnssecUpstreamClient(endpoint => RecursiveStartupConfiguration.Permits(endpoint, settings.Egress, settings.AuthorityPort),
            settings.UpstreamTimeout, time);
        var refresher = new DnssecAnchorRefresher(settings.Origin, store, upstream, verifier, settings.RefreshServer, time);
        await using var refreshLifetime = refresher.ConfigureAwait(false);
        using var shutdown = new RecursiveShutdown();
        var host = await DnssecClientHost.CreateAsync(refresher, upstream, verifier, settings.Roots,
            new DnssecTrustEpochPolicy(maximumActiveRequests: settings.MaximumRequests), settings.Access, settings.Binding,
            settings.Work, time, settings.AuthorityPort, settings.MaximumRequests, settings.UdpWorkers,
            settings.MaximumTcpConnections, settings.MaximumTcpMessages).ConfigureAwait(false);
        // Signals only request stop. Retain and join actual CancelAsync dispatch before CTS disposal.
        var initiating = await CaptureAsync(RunHostAsync(host, shutdown.Token)).ConfigureAwait(false);
        var cleanup = await CaptureAsync(CloseHostAsync(host)).ConfigureAwait(false);
        var dispatch = await CaptureAsync(JoinShutdownAsync(shutdown)).ConfigureAwait(false);
        var failures = new[] { initiating, cleanup, dispatch }.OfType<Exception>().ToArray();
        if (failures.Length == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Length > 1) throw new AggregateException(failures);
    }

    private static async Task RunHostAsync(DnssecClientHost host, CancellationToken token)
        => await host.RunAsync(token).ConfigureAwait(false);

    private static async Task CloseHostAsync(DnssecClientHost host)
        => await host.DisposeAsync().ConfigureAwait(false);

    private static async Task JoinShutdownAsync(RecursiveShutdown shutdown)
        => await shutdown.JoinAsync().ConfigureAwait(false);

    private static async Task<Exception?> CaptureAsync(Task task)
    {
        try { await task.WaitAsync(CancellationToken.None).ConfigureAwait(false); return null; }
        catch (Exception error) when (task.IsFaulted || task.IsCanceled)
        {
            if (task.Exception is { InnerExceptions.Count: 1 } single) return single.InnerExceptions[0];
            return task.Exception ?? error;
        }
    }
}
