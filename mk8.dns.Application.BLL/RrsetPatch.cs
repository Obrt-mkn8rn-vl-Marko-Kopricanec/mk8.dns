using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

internal sealed class RrsetPatch
{
    private readonly Change[] changes;

    internal RrsetPatch(ManagementRequest request, DnsName origin)
    {
        changes = request.Changes.Select(item => Normalize(item, origin)).OrderBy(item => Convert.ToHexString(item.Owner.ToWire()), StringComparer.Ordinal).ThenBy(item => item.Type).ToArray();
        if (changes.Select(change => (change.Owner, change.Type)).Distinct().Count() != changes.Length)
            throw new ArgumentException("An RRset may be changed once per batch.", nameof(request));
    }

    internal AuthoritativeZone Apply(AuthoritativeZone zone)
    {
        var records = zone.GetAllRecords().ToList();
        foreach (var change in changes)
        {
            var current = records.Where(record => record.Owner.Equals(change.Owner) && record.Type == change.Type).ToArray();
            if (!change.Replace && change.Add.Length != 0 && current.Length != 0 && current[0].Ttl != change.Ttl)
                throw new InvalidOperationException("Adding values cannot change an existing RRset TTL.");
            records.RemoveAll(record => record.Owner.Equals(change.Owner) && record.Type == change.Type);
            var removed = change.Remove.Select(DataKey).ToHashSet(StringComparer.Ordinal);
            var retained = change.Replace ? [] : current.Where(record => !removed.Contains(DataKey(record))).ToArray();
            var present = retained.Select(DataKey).ToHashSet(StringComparer.Ordinal);
            records.AddRange(retained);
            records.AddRange(change.Add.Where(record => present.Add(DataKey(record))));
        }
        return new AuthoritativeZone(zone.Origin, records);
    }

    internal void WriteIntent(BinaryWriter writer)
    {
        writer.Write((ushort)changes.Length);
        foreach (var change in changes)
        {
            var wire = change.Owner.ToWire();
            writer.Write((ushort)wire.Length);
            writer.Write(wire);
            writer.Write(change.Type);
            writer.Write(change.Replace || change.Add.Length != 0 ? change.Ttl : 0U);
            writer.Write(change.Replace);
            WriteValues(writer, change.Add);
            WriteValues(writer, change.Remove);
        }
    }

    private static Change Normalize(RrsetChange change, DnsName origin)
    {
        var owner = DnsName.FromWire(change.Owner.Span);
        if (!owner.IsSubdomainOf(origin) || change.Type == 6 || change.Replace && change.Remove.Count != 0
            || !change.Replace && change.Add.Count + change.Remove.Count == 0)
            throw new ArgumentException("Invalid RRset change.", nameof(change));
        var added = Values(change.Add, owner, change);
        var removed = Values(change.Remove, owner, change);
        var removeKeys = removed.Select(DataKey).ToHashSet(StringComparer.Ordinal);
        if (added.Any(record => removeKeys.Contains(DataKey(record))))
            throw new ArgumentException("An RDATA value cannot be added and removed together.", nameof(change));
        return new Change(owner, change.Type, change.Ttl, change.Replace, added, removed);
    }

    private static DnsRecord[] Values(IReadOnlyList<ReadOnlyMemory<byte>> values, DnsName owner, RrsetChange change)
    {
        // Constructing an empty RRset still validates its type and TTL.
        if (values.Count == 0 && (change.Type is 0 or 41 or (>= 249 and <= 255) || change.Ttl > int.MaxValue))
            throw new ArgumentException("Invalid RRset type or TTL.", nameof(change));
        var records = values.Select(data => new DnsRecord(owner, change.Type, change.Ttl, data.Span)).OrderBy(record => Convert.ToHexString(record.GetCanonicalData()), StringComparer.Ordinal).ToArray();
        if (records.Select(record => Convert.ToHexString(record.GetCanonicalData())).Distinct(StringComparer.Ordinal).Count() != records.Length)
            throw new ArgumentException("RRset values must be canonically distinct.", nameof(values));
        return records;
    }

    private static string DataKey(DnsRecord record) => Convert.ToHexString(record.GetCanonicalData());

    private static void WriteValues(BinaryWriter writer, DnsRecord[] values)
    {
        writer.Write((ushort)values.Length);
        foreach (var record in values)
        {
            var data = record.GetCanonicalData();
            writer.Write((ushort)data.Length);
            writer.Write(data);
        }
    }

    private sealed record Change(DnsName Owner, ushort Type, uint Ttl, bool Replace, DnsRecord[] Add, DnsRecord[] Remove);
}
