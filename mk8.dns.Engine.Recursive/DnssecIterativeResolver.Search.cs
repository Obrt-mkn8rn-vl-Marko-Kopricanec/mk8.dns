using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private async ValueTask<AuthorityChoice?> SearchAsync(DnsQuestion question, AuthorityContext bootstrap,
        DnssecResolutionWork work, CancellationToken token, bool routing = false)
    {
        var start = (Routing: work.RoutingProofs.Count, Discovery: work.DiscoveryProofs.Count);
        var selected = false;
        Stack<AuthorityFrame> pending = new();
        pending.Push(new AuthorityFrame(bootstrap, start));
        try
        {
            while (pending.Count != 0 && !work.Exhausted)
            {
                token.ThrowIfCancellationRequested();
                var frame = pending.Peek();
                if (frame.NextServer == frame.Context.Servers.Length || work.Validator.GetRemainingTtl(frame.Context.Keys) == 0)
                {
                    RetireFrame(pending, work);
                    continue;
                }
                var server = frame.Context.Servers[frame.NextServer++];
                var outgoing = DiscoveryQuestion(question, frame);
                var discovery = !outgoing.Equals(question);
                var reply = await ReadFrameAsync(outgoing, server, frame, work, discovery, token).ConfigureAwait(false);
                if (reply is null) { AbandonDiscovery(frame, work); continue; }
                if (reply.Evidence.Authoritative)
                {
                    var step = SelectTerminal(outgoing, frame, reply, work, discovery, routing);
                    if (step is null) continue;
                    selected = true;
                    return new AuthorityChoice(step, frame.Context.Keys.Origin, Unsigned: null);
                }
                var nextStart = (Routing: work.RoutingProofs.Count, Discovery: work.DiscoveryProofs.Count);
                var transition = await FollowFrameAsync(outgoing, frame, server, reply, bootstrap, work, routing, token).ConfigureAwait(false);
                if (transition?.Unsigned is not null && !routing)
                {
                    selected = true;
                    return new AuthorityChoice(Step: null, frame.Context.Keys.Origin, transition.Unsigned);
                }
                if (transition?.Next is not null)
                {
                    pending.Push(new AuthorityFrame(transition.Next, nextStart));
                }
                else { DiscardBranch(work, nextStart); AbandonDiscovery(frame, work); }
            }
            return null;
        }
        finally { if (!selected) DiscardBranch(work, start); }
    }

    private static void RetireFrame(Stack<AuthorityFrame> pending, DnssecResolutionWork work)
    {
        var frame = pending.Pop();
        DiscardBranch(work, frame.ProofStart);
        if (pending.TryPeek(out var parent)) AbandonDiscovery(parent, work);
    }

    private async ValueTask<ReferralTransition?> FollowFrameAsync(DnsQuestion outgoing, AuthorityFrame frame,
        DnsServerEndpoint server, DnssecReceivedEvidence reply, AuthorityContext bootstrap, DnssecResolutionWork work,
        bool routing, CancellationToken token)
    {
        var cut = SelectCut(outgoing, frame.Context.Keys.Origin, reply.Evidence);
        if (cut is null || work.CrossesCut(frame.Context.Keys.Origin, outgoing, cut)) return null;
        return await FollowAsync(outgoing, frame.Context, server, reply, bootstrap, work, token, routing).ConfigureAwait(false);
    }

    private async ValueTask<DnssecReceivedEvidence?> ReadFrameAsync(DnsQuestion outgoing, DnsServerEndpoint server,
        AuthorityFrame frame, DnssecResolutionWork work, bool discovery, CancellationToken token)
    {
        if (discovery && !work.TakeMinimisationStep()) return null;
        var reply = await ReadAsync(outgoing, server, work, token).ConfigureAwait(false);
        return reply is null || work.Exhausted || work.Validator.GetRemainingTtl(frame.Context.Keys) == 0 ? null : reply;
    }

    private static void AbandonDiscovery(AuthorityFrame frame, DnssecResolutionWork work)
    {
        work.DiscoveryProofs.RemoveRange(frame.ProofStart.Discovery, work.DiscoveryProofs.Count - frame.ProofStart.Discovery);
        frame.Exposed = frame.Context.Keys.Origin;
    }

    private static ResolutionStep? SelectTerminal(DnsQuestion question, AuthorityFrame frame, DnssecReceivedEvidence reply,
        DnssecResolutionWork work, bool discovery, bool routing)
    {
        if (work.CrossesCut(frame.Context.Keys.Origin, question)) { AbandonDiscovery(frame, work); return null; }
        if (discovery)
        {
            if (!ObserveDiscovery(question, frame, reply, work)) AbandonDiscovery(frame, work);
            return null;
        }
        var step = Terminal(question, frame.Context, reply, work);
        if (step is not null && (!routing || AddressStep(question, step))) return step;
        AbandonDiscovery(frame, work);
        return null;
    }

    private static bool AddressStep(DnsQuestion question, ResolutionStep step)
        => step.Code == 0 && step.Target is null && step.Proof.Question.Equals(question)
            && step.Proof.Kind is DnssecResolutionProofKind.Exact or DnssecResolutionProofKind.Wildcard;

    private static void DiscardBranch(DnssecResolutionWork work, (int Routing, int Discovery) start)
    {
        work.RoutingProofs.RemoveRange(start.Routing, work.RoutingProofs.Count - start.Routing);
        work.DiscoveryProofs.RemoveRange(start.Discovery, work.DiscoveryProofs.Count - start.Discovery);
    }

    private sealed class AuthorityFrame(AuthorityContext context, (int Routing, int Discovery) proofStart)
    {
        internal AuthorityContext Context { get; } = context;
        internal (int Routing, int Discovery) ProofStart { get; } = proofStart;
        internal int NextServer { get; set; }
        internal DnsName Exposed { get; set; } = context.Keys.Origin;
    }

    private sealed record AuthorityChoice(ResolutionStep? Step, DnsName Origin, DnsName? Unsigned);
}
