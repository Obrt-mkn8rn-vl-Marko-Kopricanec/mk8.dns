using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

internal static class DnssecValidationInput
{
    internal static bool TryRrset(IReadOnlyList<DnsRecord> input, DnsName owner, ushort type, int maximum, out DnsRecord[] records)
    {
        records = [];
        if (input.Count is 0 || input.Count > maximum || DnssecData.IsWildcard(owner))
            return false;
        var snapshot = input.ToArray();
        if (snapshot.Length != input.Count || snapshot.Any(record => record is null || record.Type != type || !record.Owner.Equals(owner)))
            return false;
        try
        {
            // Reject duplicates and excess canonical bytes before any provider work.
            _ = DnssecCanonical.GetRrset(snapshot, 0, (byte)owner.LabelCount);
            if (type == 48 && snapshot.Any(record => record.GetData().Length < 4))
                return false;
            records = snapshot;
            return true;
        }
        catch (Exception error) when (error is ArgumentException or FormatException)
        {
            return false;
        }
    }

    internal static bool TrySignatures(IReadOnlyList<DnsRecord> input, out DnsRecord[] signatures)
    {
        signatures = [];
        if (input.Count is 0 or > DnssecChainValidator.MaximumSignatures)
            return false;
        var snapshot = input.ToArray();
        if (snapshot.Length != input.Count || snapshot.Any(record => record is null || record.Type != 46))
            return false;
        if (snapshot.Sum(record => record.GetData().Length + 10L + record.Owner.ToWire().Length) > DnssecCanonical.MaximumRrsetBytes)
            return false;
        signatures = snapshot;
        return true;
    }

    internal static bool IsUsableKey(DnsRecord record)
    {
        try { _ = DnssecKeys.ReadKey(record); return true; }
        catch (FormatException) { return false; }
    }

    internal static bool MatchesDs(DnsRecord ds, DnsRecord key)
    {
        var data = ds.GetData();
        if (!ds.Owner.Equals(key.Owner) || ds.Type != 43 || data.Length != 36 || data[2] != 13 || data[3] != 2 || !IsUsableKey(key))
            return false;
        return CryptographicOperations.FixedTimeEquals(data, DnssecKeys.CreateDs(key, 0).GetData());
    }
}
