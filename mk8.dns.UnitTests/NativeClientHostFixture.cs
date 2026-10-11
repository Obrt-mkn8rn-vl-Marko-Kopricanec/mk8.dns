using System.Net;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class NativeClientHostFixture : IAsyncDisposable
{
    internal ClientProofEpochFixture Inputs { get; } = new();
    internal DnssecClientHost? Host { get; private set; }
    internal Exception? ExpectedFailure { get; set; }

    internal async Task<DnssecClientHost> CreateAsync(bool ipv6 = false, IPEndPoint? endpoint = null)
    {
        var address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        var bytes = address.GetAddressBytes();
        Host = await DnssecClientHost.CreateAsync(Inputs.Refresh, new Source(Inputs), Inputs.Verifier,
            [AnchorRefreshFixture.Server], new DnssecTrustEpochPolicy(),
            new DnssecClientAccessPolicy([new DnssecClientNetwork(bytes, bytes.Length * 8)], authenticatedDataAllowed: true),
            endpoint ?? new IPEndPoint(address, 0), new DnssecWorkPolicy(resolutionTimeout: AnchorRefreshFixture.Timeout),
            Inputs.Timers).ConfigureAwait(true);
        return Host;
    }

    public async ValueTask DisposeAsync()
    {
        Inputs.Clock.BeforeTimestamp = null;
        try
        {
            if (Host is not null)
            {
                try { await Host.DisposeAsync().AsTask().WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
                catch (Exception error) when (ExpectedFailure is not null && NativeClientListenerFixture.OnlyExpected(error, ExpectedFailure)) { }
            }
        }
        finally { await Inputs.DisposeAsync().ConfigureAwait(true); }
    }

    private sealed class Source(ClientProofEpochFixture inputs) : IDnssecUpstream
    {
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken token)
        {
            inputs.Calls.Enqueue(question);
            return inputs.Override is null ? ValueTask.FromResult(inputs.Default(question, server)) : inputs.Override(question, server, token);
        }
    }
}
