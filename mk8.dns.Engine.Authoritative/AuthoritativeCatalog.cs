using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Authoritative;

public sealed class AuthoritativeCatalog
{
    private readonly AuthorityZoneView[] zones;
    private readonly TimeProvider time;

    public uint ZoneCount => (uint)zones.Length;
    public bool IsAvailable
    {
        get
        {
            var now = Now();
            return zones.All(zone => zone.Security?.IsAvailable(now) != false);
        }
    }

    public DnsName? GetZoneOrigin(DnsName name, ushort type)
    {
        ArgumentNullException.ThrowIfNull(name);
        return SelectZone(name, type)?.Origin;
    }

    public AuthoritativeCatalog(IEnumerable<AuthoritativeZone> zones)
        : this(Unsigned(zones), null, TimeProvider.System) { }

    public AuthoritativeCatalog(IEnumerable<ZoneContents> zones, IDnssecSignatureVerifier? verifier, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(zones);
        ArgumentNullException.ThrowIfNull(time);
        this.time = time;
        var contents = zones.Take(65).ToArray();
        if (contents.Length > 64 || contents.Select(zone => zone.Source.Origin).Distinct().Count() != contents.Length)
            throw new ArgumentException("Catalog exceeds its bounds or has duplicate origins.", nameof(zones));
        this.zones = contents.Select(zone => new AuthorityZoneView(zone, verifier)).OrderByDescending(zone => zone.Origin.LabelCount).ToArray();
        foreach (var zone in this.zones)
        {
            if (this.zones.Where(parent => !parent.Origin.Equals(zone.Origin)).SelectMany(parent => parent.Source.GetAllRecords())
                .Any(record => record.Type == 39 && zone.Origin.IsSubdomainOf(record.Owner) && !zone.Origin.Equals(record.Owner)))
                throw new ArgumentException("A served zone cannot be below another zone's DNAME.", nameof(zones));
        }
    }

    private static IEnumerable<ZoneContents> Unsigned(IEnumerable<AuthoritativeZone> zones)
    {
        ArgumentNullException.ThrowIfNull(zones);
        return zones.Select(zone => new ZoneContents(zone));
    }

    private uint Now() => unchecked((uint)time.GetUtcNow().ToUnixTimeSeconds());
    public DnsAnswer Resolve(DnsQuestion question) => ResolveCore(question, null, dnssecOk: false);
    public DnsAnswer Resolve(DnsQuestion question, bool dnssecOk) => ResolveCore(question, null, dnssecOk);

    public DnsAnswer Resolve(DnsQuestion question, Func<DnsName, bool> authorizeZone) => Resolve(question, authorizeZone, dnssecOk: false);

    public DnsAnswer Resolve(DnsQuestion question, Func<DnsName, bool> authorizeZone, bool dnssecOk)
    {
        ArgumentNullException.ThrowIfNull(authorizeZone);
        return ResolveCore(question, authorizeZone, dnssecOk);
    }

    private DnsAnswer ResolveCore(DnsQuestion question, Func<DnsName, bool>? authorizeZone, bool dnssecOk)
    {
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(question.Name, nameof(question));
        if (question.Type == 0)
            return Failure(1);
        if (question.Class is not (1 or 255) || question.Type is >= 249 and <= 254)
            return Failure(5);
        return ResolveName(new AuthorityResolution(question, authorizeZone, dnssecOk, Now()), question.Name);
    }

    private DnsAnswer ResolveName(AuthorityResolution state, DnsName name)
    {
        if (state.Aliases.Count >= 16 || !state.Aliases.Add(name))
            return Failure(2);
        var zone = SelectZone(name, state.Question.Type);
        if (zone is null)
            return state.Complete(state.Answers.Count == 0 ? (byte)5 : (byte)0, state.Answers.Count != 0);
        if (state.Authorize is not null && !state.Authorize(zone.Origin))
            return Failure(5);
        if (zone.Security?.IsAvailable(state.Now) == false)
            return Failure(2);
        var cut = FindCut(zone, name, state.Question.Type);
        if (cut is not null)
            return Referral(zone, cut, state);
        var dname = Ancestors(zone, name).Where(ancestor => !ancestor.Equals(name))
            .SelectMany(zone.Source.GetRecords).FirstOrDefault(record => record.Type == 39);
        if (dname is not null)
            return RedirectDname(zone, name, dname, state);
        var match = Match(zone, name);
        if (match.Records is null)
            return Negative(zone, name, match, state, 3);
        if (match.Wildcard)
        {
            zone.AddProof(state.Authority, name, state.Now, state.DnssecOk);
            zone.AddProof(state.Authority, NextCloser(name, match.Closest), state.Now, state.DnssecOk);
        }
        var alias = match.Records.FirstOrDefault(record => record.Type == 5);
        if (alias is not null && state.Question.Type is not (5 or 46 or 47 or 255))
        {
            zone.AddRrset(state.Answers, [alias], name, state.Now, state.DnssecOk);
            return ResolveName(state, alias.GetTarget());
        }
        // RFC 8482: one available RRset for ANY, never enumerate the zone.
        var selectedType = state.Question.Type == 255 && match.Records.Count != 0 ? match.Records.Min(record => record.Type) : state.Question.Type;
        var selected = match.Records.Where(record => record.Type == selectedType).ToArray();
        if (selected.Length == 0)
            return Negative(zone, name, match, state, 0);
        zone.AddRrset(state.Answers, selected, name, state.Now, state.DnssecOk);
        return state.Complete(0, authoritative: true);
    }

    private DnsAnswer RedirectDname(AuthorityZoneView zone, DnsName name, DnsRecord dname, AuthorityResolution state)
    {
        zone.AddRrset(state.Answers, [dname], dname.Owner, state.Now, state.DnssecOk);
        var source = name.ToWire();
        var prefixLength = source.Length - dname.Owner.ToWire().Length;
        var target = dname.GetTarget().ToWire();
        if (prefixLength + target.Length > 255)
            return state.Complete(6, authoritative: true);
        var synthesized = new byte[prefixLength + target.Length];
        source.AsSpan(0, prefixLength).CopyTo(synthesized);
        target.CopyTo(synthesized, prefixLength);
        var cname = new DnsRecord(name, 5, zone.Security?.BoundTtl(dname.Ttl, state.Now) ?? dname.Ttl, synthesized);
        state.Answers.Add(cname);
        return state.Question.Type == 5 ? state.Complete(0, authoritative: true) : ResolveName(state, cname.GetTarget());
    }

    private AuthorityZoneView? SelectZone(DnsName name, ushort type)
    {
        var selected = zones.FirstOrDefault(zone => name.IsSubdomainOf(zone.Origin));
        if (type == 43 && selected is not null && name.Equals(selected.Origin))
        {
            var parent = zones.FirstOrDefault(zone => !name.Equals(zone.Origin) && name.IsSubdomainOf(zone.Origin));
            if (parent is not null)
                return parent;
        }
        return selected;
    }

    private static List<DnsName> Ancestors(AuthorityZoneView zone, DnsName name)
    {
        List<DnsName> path = [];
        for (var ancestor = name; !ancestor.Equals(zone.Origin); ancestor = ancestor.Parent)
            path.Add(ancestor);
        path.Add(zone.Origin);
        path.Reverse();
        return path;
    }

    private static DnsName? FindCut(AuthorityZoneView zone, DnsName name, ushort type) => Ancestors(zone, name)
        .FirstOrDefault(ancestor => !ancestor.Equals(zone.Origin) && !(ancestor.Equals(name) && type == 43) && zone.Source.GetRecords(ancestor).Any(record => record.Type == 2));

    private static DnsAnswer Referral(AuthorityZoneView zone, DnsName cut, AuthorityResolution state)
    {
        var ns = zone.Source.GetRecords(cut).Where(record => record.Type == 2).ToArray();
        zone.AddRrset(state.Authority, ns, cut, state.Now, state.DnssecOk);
        if (state.DnssecOk && zone.Security is not null)
        {
            var ds = zone.Source.GetRecords(cut).Where(record => record.Type == 43).ToArray();
            if (ds.Length == 0)
                zone.AddProof(state.Authority, cut, state.Now, dnssecOk: true);
            else
                zone.AddRrset(state.Authority, ds, cut, state.Now, dnssecOk: true);
        }
        List<DnsRecord> glue = [];
        foreach (var target in ns.Select(record => record.GetTarget()).Distinct())
            if (target.IsSubdomainOf(zone.Origin))
                foreach (var rrset in zone.Source.GetRecords(target).Where(record => record.Type is 1 or 28).GroupBy(record => record.Type))
                    zone.AddRrset(glue, rrset.ToArray(), target, state.Now, state.DnssecOk);
        return state.Complete(0, state.Answers.Count != 0, glue);
    }

    private static MatchResult Match(AuthorityZoneView zone, DnsName name)
    {
        if (zone.Source.ContainsName(name))
            return new MatchResult(name, name, zone.GetRecords(name), Wildcard: false);
        var closest = name.Parent;
        while (!zone.Source.ContainsName(closest))
            closest = closest.Parent;
        var wildcard = closest.PrependLabel([(byte)'*']);
        return new MatchResult(closest, wildcard, zone.Source.ContainsName(wildcard) ? zone.GetRecords(wildcard) : null, Wildcard: true);
    }

    private static DnsAnswer Negative(AuthorityZoneView zone, DnsName name, MatchResult match, AuthorityResolution state, byte code)
    {
        var soa = zone.Source.Soa.WithTtl(Math.Min(zone.Source.Soa.Ttl, zone.Source.Soa.GetSoaMinimum()));
        zone.AddRrset(state.Authority, [soa], soa.Owner, state.Now, state.DnssecOk);
        zone.AddProof(state.Authority, name, state.Now, state.DnssecOk);
        if (match.Wildcard)
            zone.AddProof(state.Authority, match.Owner, state.Now, state.DnssecOk);
        return state.Complete(code, authoritative: true);
    }

    private static DnsName NextCloser(DnsName name, DnsName closest)
    {
        while (!name.Parent.Equals(closest))
            name = name.Parent;
        return name;
    }

    private static DnsAnswer Failure(byte code) => new(code, false, [], [], []);
    private sealed record MatchResult(DnsName Closest, DnsName Owner, IReadOnlyList<DnsRecord>? Records, bool Wildcard);
}
