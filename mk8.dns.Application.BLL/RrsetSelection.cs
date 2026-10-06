using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

internal static class RrsetSelection
{
    internal static void Validate(ManagementRequest request, DnsName origin)
    {
        HashSet<(DnsName, ushort)> keys = [];
        foreach (var key in request.Selection)
            if (!DnsName.FromWire(key.Owner.Span).IsSubdomainOf(origin) || key.Type is 0 or 41 or (>= 249 and <= 255)
                || !keys.Add((DnsName.FromWire(key.Owner.Span), key.Type)))
                throw new ArgumentException("Invalid or duplicate RRset selection.", nameof(request));
    }

    internal static IReadOnlyList<ZoneRecordData> Read(AuthoritativeZone zone, ManagementRequest request)
    {
        var records = request.Selection.SelectMany(key => zone.GetRecords(DnsName.FromWire(key.Owner.Span)).Where(record => record.Type == key.Type))
            .OrderBy(record => Convert.ToHexString(record.Owner.ToWire()), StringComparer.Ordinal).ThenBy(record => record.Type)
            .ThenBy(record => Convert.ToHexString(record.GetCanonicalData()), StringComparer.Ordinal).Take(513).ToArray();
        if (records.Length > 512)
            throw new ArgumentException("Selected RRsets exceed the read record bound.", nameof(request));
        return records.Select(record => new ZoneRecordData(record.GetOwnerWire(), record.Type, record.Ttl, record.GetData())).ToArray();
    }
}
