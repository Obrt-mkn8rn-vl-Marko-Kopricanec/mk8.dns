using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private DnsQuestion DiscoveryQuestion(DnsQuestion original, AuthorityFrame frame)
    {
        // DS is parent-side: never descend through its queried owner just to locate its parent.
        var target = original.Type == 43 ? original.Name.Parent : original.Name;
        if (minimisation is null || target.LabelCount <= frame.Exposed.LabelCount) return original;
        var next = target;
        while (next.Parent.LabelCount > frame.Exposed.LabelCount) next = next.Parent;
        return new DnsQuestion(next, 2, 1);
    }

    private static void ObserveDiscovery(DnsQuestion question, AuthorityFrame frame, DnssecReceivedEvidence reply, DnssecResolutionWork work)
    {
        var observed = Terminal(question, frame.Context, reply, work);
        if (observed is null || observed.Target is not null || observed.Code != 0
            || observed.Proof.Kind is not (DnssecResolutionProofKind.Exact or DnssecResolutionProofKind.NoData)) return;
        work.DiscoveryProofs.Add(observed.Proof);
        frame.Exposed = question.Name;
        frame.NextServer = 0;
    }
}
