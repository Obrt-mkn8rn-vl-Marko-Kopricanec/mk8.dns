using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed class NonValidatingIterativeResolver
{
    private static readonly DnsName Root = DnsName.Parse(".");
    private readonly IDnsUpstream upstream;
    private readonly DnsServerEndpoint[] roots;
    private readonly ushort authorityPort;
    private readonly int maximumExchanges;
    private readonly int maximumAliasHops;
    private readonly int maximumDependencyDepth;
    private readonly TimeProvider time;

    public NonValidatingIterativeResolver(IDnsUpstream upstream, IEnumerable<DnsServerEndpoint> roots, ushort authorityPort = 53,
        int maximumExchanges = 64, int maximumAliasHops = 16, int maximumDependencyDepth = 8, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(roots);
        if (authorityPort == 0 || maximumExchanges is < 1 or > 256 || maximumAliasHops is < 1 or > 32 || maximumDependencyDepth is < 1 or > 16)
            throw new ArgumentOutOfRangeException(nameof(maximumExchanges), "Invalid iterative resource limits.");
        this.roots = roots.Take(17).ToArray();
        if (this.roots.Length is < 1 or > 16 || this.roots.Any(server => server is null) || this.roots.Distinct().Count() != this.roots.Length)
            throw new ArgumentException("Supply one to sixteen distinct bootstrap servers.", nameof(roots));
        this.upstream = upstream;
        this.authorityPort = authorityPort;
        this.maximumExchanges = maximumExchanges;
        this.maximumAliasHops = maximumAliasHops;
        this.maximumDependencyDepth = maximumDependencyDepth;
        this.time = time ?? TimeProvider.System;
    }

    public async ValueTask<DnsAnswer> ResolveAsync(DnsQuestion question, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (question.Name is null)
            throw new ArgumentException("An iterative question needs a name.", nameof(question));
        cancellationToken.ThrowIfCancellationRequested();
        if (question.Class != 1 || question.Type is 0 or 41 or (>= 249 and <= 255))
            return Empty(5);
        var work = new Work(maximumExchanges, maximumAliasHops);
        return await ResolveCoreAsync(question, work, 0, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<DnsAnswer> ResolveCoreAsync(DnsQuestion original, Work work, int depth, CancellationToken cancellationToken)
    {
        if (depth > maximumDependencyDepth || !work.Active.Add(original))
            return Empty(2);
        try
        {
            return await ResolveQuestionAsync(original, work, depth, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            work.Active.Remove(original);
        }
    }

    private async ValueTask<DnsAnswer> ResolveQuestionAsync(DnsQuestion question, Work work, int depth, CancellationToken cancellationToken)
    {
        var cut = Root;
        var servers = roots;
        HashSet<DnsName> aliases = [question.Name];
        List<(DnsRecord Record, long Received)> chain = [];
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var advanced = false;
            foreach (var server in servers)
            {
                var reply = await ReadReplyAsync(question, server, work, cancellationToken).ConfigureAwait(false);
                if (work.Exhausted)
                    return Empty(2);
                if (reply is null)
                    continue;
                var received = time.GetTimestamp();
                if (reply.Authoritative)
                {
                    var step = AnalyzeAuthoritative(question, cut, reply);
                    if (step is null)
                        continue;
                    if (step.Target is null)
                        return new DnsAnswer(step.Answer.ResponseCode, false, AgeChain(chain).Concat(step.Answer.Answers), step.Answer.Authority, []);
                    if (!work.TakeAlias() || !aliases.Add(step.Target))
                        return Empty(2);
                    chain.AddRange(step.Answer.Answers.Select(record => (record, received)));
                    question = question with { Name = step.Target };
                    // Never trust inline target data from a previous authority, even in the same packet.
                    cut = Root;
                    servers = roots;
                    advanced = true;
                    break;
                }
                var next = await FollowReferralAsync(question, cut, reply, work, depth, cancellationToken).ConfigureAwait(false);
                if (work.Exhausted)
                    return Empty(2);
                if (next is null)
                    continue;
                (cut, servers) = next.Value;
                advanced = true;
                break;
            }
            if (!advanced)
                return Empty(2);
        }
    }

    private async ValueTask<DnsAnswer?> ReadReplyAsync(DnsQuestion question, DnsServerEndpoint server, Work work, CancellationToken cancellationToken)
    {
        if (!work.TakeExchange())
            return null;
        var reply = await ExchangeAsync(question, server, cancellationToken).ConfigureAwait(false);
        if (reply is null)
            return null;
        return work.TakeRecords(reply.Answers.Count + reply.Authority.Count + reply.Additional.Count) && reply.ResponseCode is 0 or 3 or 6 ? reply : null;
    }

    private async ValueTask<(DnsName Cut, DnsServerEndpoint[] Servers)?> FollowReferralAsync(DnsQuestion question, DnsName cut,
        DnsAnswer reply, Work work, int depth, CancellationToken cancellationToken)
    {
        var delegation = SelectDelegation(question, cut, reply);
        if (delegation is null)
            return null;
        var addresses = await FindServersAsync(delegation.Value.Cut, delegation.Value.Names, reply.Additional, work, depth, cancellationToken).ConfigureAwait(false);
        return addresses.Length == 0 ? null : (delegation.Value.Cut, addresses);
    }

    private async ValueTask<DnsAnswer?> ExchangeAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        try
        {
            return await upstream.ExchangeAsync(question, server, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or TimeoutException or FormatException)
        {
            return null;
        }
    }

    private static Step? AnalyzeAuthoritative(DnsQuestion question, DnsName cut, DnsAnswer reply)
    {
        if (!question.Name.IsSubdomainOf(cut))
            return null;
        var atName = reply.Answers.Where(record => record.Owner.Equals(question.Name)).ToArray();
        var cnames = atName.Where(record => record.Type == 5).ToArray();
        if (cnames.Length != 0 && (cnames.Select(record => record.GetTarget()).Distinct().Count() != 1 || atName.Any(record => record.Type is not (5 or 46))))
            return null;
        // A DNAME does not alias its owner. Prefer the closest strict ancestor.
        var dnames = reply.Answers.Where(record => record.Type == 39 && !record.Owner.Equals(question.Name)
            && question.Name.IsSubdomainOf(record.Owner) && record.Owner.IsSubdomainOf(cut)).ToArray();
        if (dnames.Length != 0)
        {
            var owner = dnames.MaxBy(record => record.Owner.LabelCount)!.Owner;
            var values = dnames.Where(record => record.Owner.Equals(owner)).ToArray();
            if (values.Select(record => record.GetTarget()).Distinct().Count() != 1)
                return null;
            var dname = values[0].WithTtl(values.Min(record => record.Ttl));
            var name = question.Name.ToWire();
            var prefix = name.Length - owner.ToWire().Length;
            var target = dname.GetTarget().ToWire();
            if (prefix + target.Length > 255)
                return reply.ResponseCode is 0 or 6 ? new Step(new DnsAnswer(6, false, [dname], [], []), null) : null;
            if (reply.ResponseCode == 6)
                return null;
            var synthesized = DnsName.FromWire([.. name.AsSpan(0, prefix), .. target]);
            if (cnames.Any(record => !record.GetTarget().Equals(synthesized)) || atName.Any(record => record.Type is not (5 or 46)))
                return null;
            return new Step(new DnsAnswer(0, false, [dname, new DnsRecord(question.Name, 5, dname.Ttl, synthesized.ToWire())], [], []), question.Type == 5 ? null : synthesized);
        }
        if (reply.ResponseCode == 6)
            return null;
        if (cnames.Length != 0 && question.Type != 5)
        {
            var cname = cnames[0].WithTtl(cnames.Min(record => record.Ttl));
            return new Step(new DnsAnswer(0, false, [cname], [], []), cname.GetTarget());
        }
        var result = atName.Where(record => record.Type == question.Type).ToArray();
        if (result.Length != 0)
            return reply.ResponseCode == 0 ? new Step(new DnsAnswer(0, false, NormalizeTtl(result), [], []), null) : null;
        var soa = reply.Authority.Where(record => record.Type == 6 && record.Owner.Equals(cut)).ToArray();
        if (soa.Length != 1 || reply.Answers.Count != 0)
            return null;
        return new Step(new DnsAnswer(reply.ResponseCode, false, [], [soa[0].WithTtl(Math.Min(soa[0].Ttl, soa[0].GetSoaMinimum()))], []), null);
    }

    private static (DnsName Cut, DnsName[] Names)? SelectDelegation(DnsQuestion question, DnsName cut, DnsAnswer reply)
    {
        if (reply.ResponseCode != 0 || reply.Answers.Count != 0)
            return null;
        var records = reply.Authority.Where(record => record.Type == 2).ToArray();
        if (records.Length is < 1 or > 16 || records.Select(record => record.Owner).Distinct().Count() != 1)
            return null;
        var next = records[0].Owner;
        if (next.Equals(cut) || !next.IsSubdomainOf(cut) || !question.Name.IsSubdomainOf(next)
            || question.Type == 43 && question.Name.Equals(next))
            return null;
        return (next, records.Select(record => record.GetTarget()).Distinct().ToArray());
    }

    private async ValueTask<DnsServerEndpoint[]> FindServersAsync(DnsName cut, DnsName[] names, IReadOnlyList<DnsRecord> glue,
        Work work, int depth, CancellationToken cancellationToken)
    {
        List<DnsServerEndpoint> result = [];
        foreach (var name in names)
        {
            // Only exact NS-target addresses inside the delegated child are usable glue.
            if (name.IsSubdomainOf(cut))
                AddAddresses(result, glue.Where(record => record.Owner.Equals(name) && record.Type is 1 or 28));
            else
                foreach (var type in new ushort[] { 1, 28 })
                {
                    var resolved = await ResolveCoreAsync(new DnsQuestion(name, type, 1), work, depth + 1, cancellationToken).ConfigureAwait(false);
                    if (resolved.ResponseCode == 0 && resolved.Answers.All(record => record.Type != 5 && record.Type != 39))
                        AddAddresses(result, resolved.Answers.Where(record => record.Owner.Equals(name) && record.Type == type));
                }
            if (result.Count >= 16)
                break;
        }
        return result.Distinct().Take(16).ToArray();
    }

    private void AddAddresses(List<DnsServerEndpoint> result, IEnumerable<DnsRecord> records)
    {
        foreach (var record in records)
        {
            try
            {
                result.Add(new DnsServerEndpoint(record.GetData(), authorityPort));
            }
            catch (ArgumentException)
            {
                // Unusable/multicast/mapped addresses cannot become an egress endpoint.
            }
            if (result.Count >= 16)
                return;
        }
    }

    private static IEnumerable<DnsRecord> NormalizeTtl(DnsRecord[] records)
    {
        var ttl = records.Min(record => record.Ttl);
        return records.DistinctBy(record => Convert.ToHexString(record.GetCanonicalData()), StringComparer.Ordinal).Select(record => record.WithTtl(ttl));
    }

    private IEnumerable<DnsRecord> AgeChain(List<(DnsRecord Record, long Received)> chain)
    {
        var now = time.GetTimestamp();
        return chain.Select(item =>
        {
            var elapsed = Math.Max(0, time.GetElapsedTime(item.Received, now).TotalSeconds);
            // Round up elapsed time: an earlier alias never receives extra lifetime during dependencies.
            return item.Record.WithTtl(elapsed >= item.Record.Ttl ? 0 : item.Record.Ttl - (uint)Math.Ceiling(elapsed));
        });
    }

    private static DnsAnswer Empty(byte code) => new(code, false, [], [], []);
    private sealed record Step(DnsAnswer Answer, DnsName? Target);
    private sealed class Work(int exchanges, int aliases)
    {
        private int exchangesLeft = exchanges;
        private int aliasesLeft = aliases;
        private int recordsLeft = 8192;
        public HashSet<DnsQuestion> Active { get; } = [];
        public bool Exhausted { get; private set; }
        public bool TakeExchange() => Check(--exchangesLeft >= 0);
        public bool TakeAlias() => Check(--aliasesLeft >= 0);
        public bool TakeRecords(int count) => Check(count <= 512 && (recordsLeft -= count) >= 0);
        private bool Check(bool allowed) { Exhausted |= !allowed; return !Exhausted; }
    }
}
