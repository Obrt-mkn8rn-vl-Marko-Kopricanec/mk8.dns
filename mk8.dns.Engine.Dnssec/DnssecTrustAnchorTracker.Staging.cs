namespace Mk8.Dns.Engine.Dnssec;

public sealed partial class DnssecTrustAnchorTracker
{
    // Live staging preserves both clock histories; recovery deliberately rebases
    // hold-down. Neither one-use captures nor mutable entry objects are shared.
    public DnssecTrustAnchorTracker CreateStagedTracker()
    {
        lock (gate)
        {
            if (applying) throw new InvalidOperationException("Cannot stage during verification.");
            _ = ReadClock();
            var staged = new DnssecTrustAnchorTracker(Origin, verifier, time)
            {
                latestTimestamp = latestTimestamp,
                latestSeconds = latestSeconds,
                clockStarted = clockStarted,
            };
            foreach (var pair in entries)
            {
                staged.entries.Add(pair.Key, new Entry(pair.Value.Key, pair.Value.State)
                {
                    Timestamp = pair.Value.Timestamp,
                    Seconds = pair.Value.Seconds,
                    HoldDown = pair.Value.HoldDown,
                    Sponsors = (string[])pair.Value.Sponsors.Clone(),
                    EarlyRevocations = new HashSet<string>(pair.Value.EarlyRevocations, StringComparer.Ordinal),
                    RevokedAt = pair.Value.RevokedAt,
                });
            }

            return staged;
        }
    }
}
