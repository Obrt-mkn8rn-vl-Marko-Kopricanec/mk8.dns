using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

// Capture at receipt, before queued/provider work. A capture can be consumed once
// by its creator; it is not an authenticated result or a reusable key lease.
public sealed class DnssecAnchorObservation
{
    internal DnssecAnchorObservation(DnssecTrustAnchorTracker creator, long sequence, long timestamp, long seconds,
        DnsRecord[] records, DnsRecord[] signatures)
    {
        Creator = creator;
        Sequence = sequence;
        Timestamp = timestamp;
        Seconds = seconds;
        Records = records;
        Signatures = signatures;
    }

    internal DnssecTrustAnchorTracker Creator { get; }
    internal long Sequence { get; }
    internal long Timestamp { get; }
    internal long Seconds { get; }
    internal DnsRecord[] Records { get; private set; }
    internal DnsRecord[] Signatures { get; private set; }
    internal DnssecAnchorProofTiming? Timing { get; set; }
    internal void Release() { Records = []; Signatures = []; }
}
