using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private async ValueTask<AuthorityChoice?> SearchAsync(DnsQuestion question, AuthorityContext bootstrap,
        DnssecResolutionWork work, CancellationToken token, bool routing = false)
    {
        var start = work.RoutingProofs.Count;
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
                    pending.Pop(); DiscardRouting(work, frame.RoutingStart); continue;
                }
                var server = frame.Context.Servers[frame.NextServer++];
                var reply = await ReadAsync(question, server, work, token).ConfigureAwait(false);
                if (reply is null || work.Exhausted || work.Validator.GetRemainingTtl(frame.Context.Keys) == 0) continue;
                if (reply.Evidence.Authoritative)
                {
                    if (work.CrossesCut(frame.Context.Keys.Origin, question)) continue;
                    var step = Terminal(question, frame.Context, reply, work);
                    if (step is null || routing && !AddressStep(question, step)) continue;
                    selected = true;
                    return new AuthorityChoice(step, frame.Context.Keys.Origin, null);
                }
                var routingStart = work.RoutingProofs.Count;
                var cut = SelectCut(question, frame.Context.Keys.Origin, reply.Evidence);
                if (cut is null || work.CrossesCut(frame.Context.Keys.Origin, question, cut)) continue;
                var transition = await FollowAsync(question, frame.Context, server, reply, bootstrap, work, token, routing).ConfigureAwait(false);
                if (transition?.Unsigned is not null && !routing)
                {
                    selected = true;
                    return new AuthorityChoice(null, frame.Context.Keys.Origin, transition.Unsigned);
                }
                if (transition?.Next is not null) pending.Push(new AuthorityFrame(transition.Next, routingStart));
            }
            return null;
        }
        finally { if (!selected) DiscardRouting(work, start); }
    }

    private static bool AddressStep(DnsQuestion question, ResolutionStep step)
        => step.Code == 0 && step.Target is null && step.Proof.Question.Equals(question)
            && step.Proof.Kind is DnssecResolutionProofKind.Exact or DnssecResolutionProofKind.Wildcard;

    private static void DiscardRouting(DnssecResolutionWork work, int start)
        => work.RoutingProofs.RemoveRange(start, work.RoutingProofs.Count - start);

    private sealed class AuthorityFrame(AuthorityContext context, int routingStart)
    {
        internal AuthorityContext Context { get; } = context;
        internal int RoutingStart { get; } = routingStart;
        internal int NextServer { get; set; }
    }

    private sealed record AuthorityChoice(ResolutionStep? Step, DnsName Origin, DnsName? Unsigned);
}
