using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

// Only a successful store acknowledgement publishes this receipt. It carries
// historical scheduling data, never key/proof/provider graphs or data authority.
public sealed class DnssecAnchorRefreshTiming
{
    internal DnssecAnchorRefreshTiming(long revision, DnssecAnchorProofTiming proof, DateTimeOffset receivedUtc, TimeSpan charged)
    {
        Revision = revision; Proof = proof; ReceivedUtc = receivedUtc; ChargedElapsed = charged;
        RemainingQueryInterval = proof.QueryInterval > charged ? proof.QueryInterval - charged : TimeSpan.Zero;
        RemainingRetryInterval = proof.RetryInterval > charged ? proof.RetryInterval - charged : TimeSpan.Zero;
    }
    public DnsName Origin => Proof.Origin;
    public long Revision { get; }
    public DateTimeOffset ReceivedUtc { get; }
    public DnssecAnchorProofTiming Proof { get; }
    public TimeSpan ChargedElapsed { get; }
    public TimeSpan RemainingQueryInterval { get; }
    public TimeSpan RemainingRetryInterval { get; }
}
