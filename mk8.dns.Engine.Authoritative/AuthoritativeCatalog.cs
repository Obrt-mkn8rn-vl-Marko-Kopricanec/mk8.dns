using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Authoritative;

public sealed class AuthoritativeCatalog
{
    private readonly AuthoritativeZone[] zones;

    public uint ZoneCount => (uint)zones.Length;

    public DnsName? GetZoneOrigin(DnsName name, ushort type)
    {
        ArgumentNullException.ThrowIfNull(name);
        return SelectZone(name, type)?.Origin;
    }

    public AuthoritativeCatalog(IEnumerable<AuthoritativeZone> zones)
    {
        ArgumentNullException.ThrowIfNull(zones);
        this.zones = zones.Take(65).OrderByDescending(zone => zone.Origin.LabelCount).ToArray();
        if (this.zones.Length > 64 || this.zones.Select(zone => zone.Origin).Distinct().Count() != this.zones.Length)
            throw new ArgumentException("Catalog exceeds its bounds or has duplicate origins.", nameof(zones));
        foreach (var zone in this.zones)
        {
            if (this.zones.Where(parent => !parent.Origin.Equals(zone.Origin)).SelectMany(parent => parent.GetAllRecords())
                .Any(record => record.Type == 39 && zone.Origin.IsSubdomainOf(record.Owner) && !zone.Origin.Equals(record.Owner)))
                throw new ArgumentException("A served zone cannot be below another zone's DNAME.", nameof(zones));
        }
    }

    public DnsAnswer Resolve(DnsQuestion question) => ResolveCore(question, null);

    public DnsAnswer Resolve(DnsQuestion question, Func<DnsName, bool> authorizeZone)
    {
        ArgumentNullException.ThrowIfNull(authorizeZone);
        return ResolveCore(question, authorizeZone);
    }

    private DnsAnswer ResolveCore(DnsQuestion question, Func<DnsName, bool>? authorizeZone)
    {
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(question.Name, nameof(question));
        if (question.Type == 0)
            return new DnsAnswer(1, false, [], [], []);
        if (question.Class is not (1 or 255) || question.Type is >= 249 and <= 254)
            return new DnsAnswer(5, false, [], [], []);
        return ResolveName(question, question.Name, [], [], authorizeZone);
    }

    private DnsAnswer ResolveName(DnsQuestion question, DnsName name, List<DnsRecord> answers, HashSet<DnsName> aliases, Func<DnsName, bool>? authorizeZone)
    {
        if (aliases.Count >= 16 || !aliases.Add(name))
            return new DnsAnswer(2, false, [], [], []);
        var zone = SelectZone(name, question.Type);
        if (zone is null)
            return new DnsAnswer(answers.Count == 0 ? (byte)5 : (byte)0, answers.Count != 0, answers, [], []);
        if (authorizeZone is not null && !authorizeZone(zone.Origin))
            return new DnsAnswer(5, false, [], [], []);
        var cut = FindCut(zone, name, question.Type);
        if (cut is not null)
            return Referral(zone, cut, answers);
        var dname = Ancestors(zone, name).Where(ancestor => !ancestor.Equals(name))
            .SelectMany(zone.GetRecords).FirstOrDefault(record => record.Type == 39);
        if (dname is not null)
            return RedirectDname(question, name, dname, answers, aliases, authorizeZone);
        var records = Match(zone, name);
        if (records is null)
            return Negative(zone, answers, 3);
        var alias = records.SingleOrDefault(record => record.Type == 5);
        if (alias is not null && question.Type is not (5 or 255))
        {
            answers.Add(alias);
            return ResolveName(question, alias.GetTarget(), answers, aliases, authorizeZone);
        }
        // RFC 8482: answer ANY with one available RRset, never enumerate the zone.
        var selectedType = question.Type == 255 && records.Count != 0 ? records.Min(record => record.Type) : question.Type;
        var selected = records.Where(record => record.Type == selectedType).ToArray();
        if (selected.Length == 0)
            return Negative(zone, answers, 0);
        answers.AddRange(selected);
        return new DnsAnswer(0, true, answers, [], []);
    }

    private DnsAnswer RedirectDname(DnsQuestion question, DnsName name, DnsRecord dname, List<DnsRecord> answers, HashSet<DnsName> aliases, Func<DnsName, bool>? authorizeZone)
    {
        answers.Add(dname);
        var source = name.ToWire();
        var prefixLength = source.Length - dname.Owner.ToWire().Length;
        var target = dname.GetTarget().ToWire();
        if (prefixLength + target.Length > 255)
            return new DnsAnswer(6, true, answers, [], []);
        var synthesized = new byte[prefixLength + target.Length];
        source.AsSpan(0, prefixLength).CopyTo(synthesized);
        target.CopyTo(synthesized, prefixLength);
        var cname = new DnsRecord(name, 5, dname.Ttl, synthesized);
        answers.Add(cname);
        return question.Type == 5 ? new DnsAnswer(0, true, answers, [], []) : ResolveName(question, cname.GetTarget(), answers, aliases, authorizeZone);
    }

    private AuthoritativeZone? SelectZone(DnsName name, ushort type)
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

    private static List<DnsName> Ancestors(AuthoritativeZone zone, DnsName name)
    {
        List<DnsName> path = [];
        for (var ancestor = name; !ancestor.Equals(zone.Origin); ancestor = ancestor.Parent)
            path.Add(ancestor);
        path.Add(zone.Origin);
        path.Reverse();
        return path;
    }

    private static DnsName? FindCut(AuthoritativeZone zone, DnsName name, ushort type) => Ancestors(zone, name)
        .FirstOrDefault(ancestor => !ancestor.Equals(zone.Origin) && !(ancestor.Equals(name) && type == 43) && zone.GetRecords(ancestor).Any(record => record.Type == 2));

    private static DnsAnswer Referral(AuthoritativeZone zone, DnsName cut, List<DnsRecord> answers)
    {
        var ns = zone.GetRecords(cut).Where(record => record.Type == 2).ToArray();
        List<DnsRecord> glue = [];
        foreach (var target in ns.Select(record => record.GetTarget()).Distinct())
            if (target.IsSubdomainOf(zone.Origin))
                glue.AddRange(zone.GetRecords(target).Where(record => record.Type is 1 or 28));
        return new DnsAnswer(0, answers.Count != 0, answers, ns, glue);
    }

    private static IReadOnlyList<DnsRecord>? Match(AuthoritativeZone zone, DnsName name)
    {
        if (zone.ContainsName(name))
            return zone.GetRecords(name);
        var closest = name.Parent;
        while (!zone.ContainsName(closest))
            closest = closest.Parent;
        var wildcard = closest.PrependLabel([(byte)'*']);
        return zone.ContainsName(wildcard) ? Array.AsReadOnly(zone.GetRecords(wildcard).Select(record => record.WithOwner(name)).ToArray()) : null;
    }

    private static DnsAnswer Negative(AuthoritativeZone zone, List<DnsRecord> answers, byte responseCode)
    {
        var soa = zone.Soa.WithTtl(Math.Min(zone.Soa.Ttl, zone.Soa.GetSoaMinimum()));
        return new DnsAnswer(responseCode, true, answers, [soa], []);
    }
}
