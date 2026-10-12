using System.Net;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientHost
{
    // Explicit unchecked CD path. The ordinary resolver remains borrowed and
    // contributes no validation epoch, receipt, proof cache or authentication.
    public static async ValueTask<DnssecClientHost> CreateWithCheckingDisabledSourceAsync(DnssecAnchorRefresher refresher,
        IDnssecUpstream upstream, IDnssecSignatureVerifier verifier, IEnumerable<DnsServerEndpoint> roots,
        NonValidatingIterativeResolver checkingDisabledSource, DnssecTrustEpochPolicy epochPolicy,
        DnssecClientAccessPolicy access, IPEndPoint endpoint, DnssecWorkPolicy workPolicy, TimeProvider time,
        ushort authorityPort = 53, int maximumRequests = 64, int udpWorkers = 4,
        int maximumTcpConnections = 16, int maximumTcpMessages = 16)
    {
        ArgumentNullException.ThrowIfNull(checkingDisabledSource);
        var host = new DnssecClientHost();
        try
        {
            host.epoch = DnssecTrustEpochResolver.CreateWithClientProofAndCoalescing(refresher, upstream, verifier,
                roots, epochPolicy, workPolicy, time, authorityPort);
            host.processor = DnssecClientRequestProcessor.CreateWithCheckingDisabledSource(host.epoch, checkingDisabledSource,
                access, time, completeTcpAnswers: true, maximumRequests);
            host.listener = new DnssecClientListener(host.processor, endpoint, udpWorkers, maximumTcpConnections, maximumTcpMessages);
            return host;
        }
        catch (Exception error)
        {
            var cleanupError = await CaptureAsync(host.DisposeAsync().AsTask()).ConfigureAwait(false);
            if (cleanupError is not null) throw new AggregateException(error, cleanupError);
            throw;
        }
    }
}
