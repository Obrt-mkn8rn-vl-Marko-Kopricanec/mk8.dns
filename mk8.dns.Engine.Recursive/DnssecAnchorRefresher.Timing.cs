namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecAnchorRefresher
{
    private TimingReceipt? timingReceipt;

    public DnssecAnchorRefreshTiming? CurrentTiming
    {
        get
        {
            lock (gate)
            {
                RequireUsable();
                if (timingReceipt is not { } receipt) return null;
                var elapsed = Math.Max(Math.Max(0, clock.GetElapsedTime(receipt.Timestamp, clock.GetTimestamp()).Ticks),
                    Math.Max(0, (clock.GetUtcNow() - receipt.Wall).Ticks));
                return new(current.Revision, receipt.Proof, receipt.Wall, TimeSpan.FromTicks(elapsed));
            }
        }
    }

    private sealed record TimingReceipt(Mk8.Dns.Engine.Dnssec.DnssecAnchorProofTiming Proof, long Timestamp, DateTimeOffset Wall);
}
