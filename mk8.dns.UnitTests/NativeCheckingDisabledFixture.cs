using System.Net;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class NativeCheckingDisabledFixture : IAsyncDisposable
{
    internal CheckingDisabledMaterialFixture Inputs { get; } = new();
    internal DnssecClientHost? Host { get; private set; }
    internal Exception? ExpectedFailure { get; set; }

    internal async Task<DnssecClientHost> CreateAsync(bool material = true, int requests = 64)
    {
        var ordinary = material ? Inputs.Resolver : new NonValidatingIterativeResolver(new Ordinary(Inputs),
            [AnchorRefreshFixture.Server], time: Inputs.Epoch.Anchors.Keys.Clock);
        Host = await DnssecClientHost.CreateWithCheckingDisabledSourceAsync(Inputs.Epoch.Refresh,
            new Validating(Inputs.Epoch), Inputs.Epoch.Verifier, [AnchorRefreshFixture.Server], ordinary,
            new DnssecTrustEpochPolicy(), new DnssecClientAccessPolicy(
                [new DnssecClientNetwork(IPAddress.Loopback.GetAddressBytes(), 32)], authenticatedDataAllowed: true),
            new IPEndPoint(IPAddress.Loopback, 0), new DnssecWorkPolicy(resolutionTimeout: AnchorRefreshFixture.Timeout),
            Inputs.Epoch.Anchors.Keys.Clock, maximumRequests: requests).ConfigureAwait(true);
        return Host;
    }

    public async ValueTask DisposeAsync()
    {
        await TestTaskSettlement.InOrderAsync(async () =>
        {
            if (Host is not null)
            {
                await TestTaskSettlement.WaitAsync(Host.DisposeAsync().AsTask().WaitAsync(CancellationToken.None),
                    AnchorRefreshFixture.Timeout, error => ExpectedFailure is not null
                        && NativeClientListenerFixture.OnlyExpected(error, ExpectedFailure)).ConfigureAwait(true);
            }
        }, async () => await Inputs.DisposeAsync().ConfigureAwait(true)).ConfigureAwait(true);
    }

    private sealed class Ordinary(CheckingDisabledMaterialFixture inputs) : IDnsUpstream
    {
        public async ValueTask<DnsAnswer> ExchangeAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken token)
        {
            var reply = await inputs.Upstream.ExchangeDnssecAsync(question, server, token).ConfigureAwait(true);
            return new DnsAnswer((byte)reply.ResponseCode, reply.Authoritative, reply.Answers, reply.Authority, reply.Additional);
        }
    }

    private sealed class Validating(ClientProofEpochFixture inputs) : IDnssecUpstream
    {
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); inputs.Calls.Enqueue(question);
            return ValueTask.FromResult(inputs.Default(question, server));
        }
    }
}
