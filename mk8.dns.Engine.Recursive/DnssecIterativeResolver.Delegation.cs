using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private async ValueTask<AuthorityContext?> BootstrapAsync(DnssecResolutionWork work, CancellationToken cancellationToken)
    {
        var question = new DnsQuestion(anchor.Origin, 48, 1);
        foreach (var server in roots)
        {
            var reply = await ReadAsync(question, server, work, cancellationToken).ConfigureAwait(false);
            if (work.Exhausted) break;
            if (reply is null || !reply.Evidence.Authoritative || reply.Evidence.ResponseCode != 0) continue;
            var records = Rrset(reply.Evidence.Answers, anchor.Origin, 48);
            var signatures = Signatures(reply.Evidence.Answers, records);
            if (work.Validator.TryAuthenticateAnchor(anchor, reply.Age(records, clock), reply.Age(signatures, clock), out var keys))
                return new AuthorityContext(keys, roots);
        }
        return null;
    }

    private async ValueTask<ReferralTransition?> FollowAsync(DnsQuestion question, AuthorityContext context, DnsServerEndpoint parent,
        DnssecReceivedEvidence referral, AuthorityContext bootstrap, DnssecResolutionWork work, CancellationToken cancellationToken,
        bool routing = false)
    {
        var cut = SelectCut(question, context.Keys.Origin, referral.Evidence);
        if (cut is null || !work.EnterDelegation(cut)) return null;
        var routingStart = work.RoutingProofs.Count;
        var followed = false;
        try
        {
            var dsQuestion = new DnsQuestion(cut, 43, 1);
            var dsReply = await ReadAsync(dsQuestion, parent, work, cancellationToken).ConfigureAwait(false);
            if (dsReply is null || !dsReply.Evidence.Authoritative || dsReply.Evidence.ResponseCode != 0) return null;
            var ds = Rrset(dsReply.Evidence.Answers, cut, 43);
            if (ds.Length == 0)
                return ProvesUnsigned(dsQuestion, context, dsReply, work, retain: !routing) ? new ReferralTransition(null, cut) : null;
            if (ds.Length > DnssecChainValidator.MaximumKeys || dsReply.Evidence.Answers.Any(record => record.Owner.Equals(cut)
                && record.Type is not (43 or 46))) return null;
            var dsSignatures = Signatures(dsReply.Evidence.Answers, ds);
            if (!work.Validator.TryAuthenticateRrset(context.Keys, dsQuestion, dsReply.Age(ds, clock), dsReply.Age(dsSignatures, clock), out _))
                return null;
            var servers = await FindServersAsync(cut, referral.Evidence, bootstrap, work, cancellationToken).ConfigureAwait(false);
            var child = await AuthenticateChildAsync(context.Keys, cut, servers, dsReply, ds, dsSignatures, work, cancellationToken).ConfigureAwait(false);
            followed = child is not null;
            return child is null ? null : new ReferralTransition(child, null);
        }
        finally
        {
            if (!followed) work.RoutingProofs.RemoveRange(routingStart, work.RoutingProofs.Count - routingStart);
            work.ExitDelegation(cut);
        }
    }

    private async ValueTask<AuthorityContext?> AuthenticateChildAsync(AuthenticatedDnskeySet parent, DnsName cut,
        DnsServerEndpoint[] servers, DnssecReceivedEvidence dsReply, DnsRecord[] ds, DnsRecord[] dsSignatures,
        DnssecResolutionWork work, CancellationToken cancellationToken)
    {
        var question = new DnsQuestion(cut, 48, 1);
        foreach (var server in servers)
        {
            var reply = await ReadAsync(question, server, work, cancellationToken).ConfigureAwait(false);
            if (work.Exhausted) break;
            if (reply is null || !reply.Evidence.Authoritative || reply.Evidence.ResponseCode != 0) continue;
            var keys = Rrset(reply.Evidence.Answers, cut, 48);
            var signatures = Signatures(reply.Evidence.Answers, keys);
            if (work.Validator.TryAuthenticateChild(parent, cut, dsReply.Age(ds, clock), dsReply.Age(dsSignatures, clock),
                reply.Age(keys, clock), reply.Age(signatures, clock), out var authenticated))
                return new AuthorityContext(authenticated, servers);
        }
        return null;
    }

    private static bool ProvesUnsigned(DnsQuestion question, AuthorityContext context, DnssecReceivedEvidence reply,
        DnssecResolutionWork work, bool retain = true)
    {
        if (reply.Evidence.Answers.Count != 0) return false;
        var soa = Rrset(reply.Evidence.Authority, context.Keys.Origin, 6);
        if (soa.Length != 1) return false;
        var nsecs = reply.Evidence.Authority.Where(record => record.Type is 47 or 50).ToArray();
        var soaSignatures = Signatures(reply.Evidence.Authority, soa);
        var denialSignatures = Signatures(reply.Evidence.Authority, nsecs);
        if (!DnssecResolutionProof.TryCreate(DnssecResolutionProofKind.Exact, context.Keys, new DnsQuestion(context.Keys.Origin, 6, 1),
            soa, [], [], soaSignatures, reply.Received, out var soaProof) || !soaProof.Authenticate(work.Validator, work.Clock)
            || !DnssecResolutionProof.TryCreate(DnssecResolutionProofKind.DsAbsence, context.Keys, question, [], soa, nsecs,
                denialSignatures, reply.Received, out var denial) || !denial.Authenticate(work.Validator, work.Clock)) return false;
        if (retain)
        {
            work.Proofs.Add(soaProof);
            work.Proofs.Add(denial);
        }
        return true;
    }

    private static DnsName? SelectCut(DnsQuestion question, DnsName current, DnsUpstreamEvidence reply)
    {
        if (reply.ResponseCode != 0 || reply.Answers.Count != 0) return null;
        var names = reply.Authority.Where(record => record.Type == 2).ToArray();
        if (names.Length is < 1 or > 16 || names.Select(record => record.Owner).Distinct().Count() != 1) return null;
        var next = names[0].Owner;
        return !next.Equals(current) && next.IsSubdomainOf(current) && question.Name.IsSubdomainOf(next)
            && !(question.Type == 43 && question.Name.Equals(next)) ? next : null;
    }

    private DnsServerEndpoint[] Glue(DnsName cut, DnsUpstreamEvidence reply)
    {
        var targets = reply.Authority.Where(record => record.Type == 2).Select(record => record.GetTarget())
            .Where(name => name.IsSubdomainOf(cut)).ToHashSet();
        List<DnsServerEndpoint> addresses = [];
        foreach (var record in reply.Additional.Where(record => record.Type is 1 or 28 && targets.Contains(record.Owner)))
        {
            try { addresses.Add(new DnsServerEndpoint(record.GetData(), authorityPort)); }
            catch (ArgumentException) { continue; }
            if (addresses.Count == 16) break;
        }
        return addresses.Distinct().ToArray();
    }
}
