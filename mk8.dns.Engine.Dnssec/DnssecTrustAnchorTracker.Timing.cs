using System.Diagnostics.CodeAnalysis;

namespace Mk8.Dns.Engine.Dnssec;

public sealed partial class DnssecTrustAnchorTracker
{
    public bool TryApplyWithTiming(DnssecAnchorObservation observation,
        [NotNullWhen(true)] out DnssecAnchorProofTiming? timing)
    {
        timing = null;
        if (!TryApply(observation)) return false;
        timing = observation.Timing ?? throw new InvalidOperationException("Applied anchor observation has no authenticated timing.");
        return true;
    }

    private void RecordTiming(DnssecAnchorObservation observation, Dictionary<string, DnssecAnchorProof.Verified> sponsors,
        Dictionary<string, DnssecAnchorProof.Verified> revocations, Stamp final)
    {
        var proofs = sponsors.Values.Concat(revocations.Where(pair => entries[pair.Key].State == DnssecAnchorState.Revoked
            && Fresh(pair.Value, observation, final)).Select(pair => pair.Value)).ToArray();
        if (proofs.Length == 0) throw new InvalidOperationException("Successful anchor update has no live authenticated proof.");
        observation.Timing = new DnssecAnchorProofTiming(Origin, observation.Seconds, proofs.Min(proof => proof.OriginalTtl),
            proofs.Min(proof => unchecked(proof.Window.Expiration - (uint)observation.Seconds)));
    }
}
