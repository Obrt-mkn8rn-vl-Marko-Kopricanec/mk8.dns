using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private async ValueTask<DnsServerEndpoint[]> FindServersAsync(DnsName cut, DnsUpstreamEvidence referral,
        AuthorityContext bootstrap, DnssecResolutionWork work, CancellationToken cancellationToken)
    {
        var glue = Glue(cut, referral);
        if (glue.Length != 0) return glue;
        var targets = referral.Authority.Where(record => record.Type == 2).Select(record => record.GetTarget()).Distinct().ToArray();
        List<DnsServerEndpoint> servers = [];
        foreach (var target in targets)
        {
            // Missing in-child glue cannot be repaired through a circular dependency.
            if (target.IsSubdomainOf(cut) || !target.IsSubdomainOf(anchor.Origin)) continue;
            foreach (var type in new ushort[] { 1, 28 })
            {
                var routingStart = work.RoutingProofs.Count;
                var proof = await ResolveAddressAsync(new DnsQuestion(target, type, 1), bootstrap, work, cancellationToken).ConfigureAwait(false);
                if (proof is null) continue;
                var before = servers.Count;
                foreach (var record in proof.Output(clock, clock.GetTimestamp()))
                {
                    try { servers.Add(new DnsServerEndpoint(record.GetData(), authorityPort)); }
                    catch (ArgumentException) { continue; }
                    if (servers.Count == 16) break;
                }
                if (servers.Count != before) { work.RoutingProofs.Add(proof); break; }
                else work.RoutingProofs.RemoveRange(routingStart, work.RoutingProofs.Count - routingStart);
                if (servers.Count == 16 || work.Exhausted) break;
            }
            if (servers.Count == 16 || work.Exhausted) break;
        }
        return servers.Distinct().ToArray();
    }

    private async ValueTask<DnssecResolutionProof?> ResolveAddressAsync(DnsQuestion question, AuthorityContext bootstrap,
        DnssecResolutionWork work, CancellationToken cancellationToken)
    {
        if (!Supported(question)) return null;
        var choice = await SearchAsync(question, bootstrap, work, cancellationToken, routing: true).ConfigureAwait(false);
        return choice?.Step?.Proof;
    }
}
