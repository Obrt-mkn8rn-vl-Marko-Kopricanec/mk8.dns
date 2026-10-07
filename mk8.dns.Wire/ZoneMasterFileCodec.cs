using System.Globalization;
using System.Text;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public static class ZoneMasterFileCodec
{
    public const int MaximumTextBytes = 1_000_000;

    public static AuthoritativeZone Import(DnsName origin, string text)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(text);
        Require(text.Length is > 0 and <= MaximumTextBytes && text.All(character => character is >= ' ' and <= '~' or '\t' or '\r' or '\n'));
        try
        {
            return ImportCore(origin, text);
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("Invalid master-file zone or record.", exception);
        }
    }

    public static string Export(AuthoritativeZone zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        var output = new StringBuilder();
        output.Append("$ORIGIN ").Append(MasterFileData.FormatName(zone.Origin.ToWire())).Append('\n');
        foreach (var record in zone.GetAllRecords().OrderBy(record => record.Owner.ToString(), StringComparer.Ordinal)
            .ThenBy(record => record.Type).ThenBy(record => Convert.ToHexString(record.GetData()), StringComparer.Ordinal))
        {
            var data = record.GetData();
            output.Append(MasterFileData.FormatName(record.GetOwnerWire())).Append(' ')
                .Append(record.Ttl.ToString(CultureInfo.InvariantCulture)).Append(" IN TYPE")
                .Append(record.Type.ToString(CultureInfo.InvariantCulture)).Append(" \\# ")
                .Append(data.Length.ToString(CultureInfo.InvariantCulture));
            if (data.Length != 0)
                output.Append(' ').Append(Convert.ToHexStringLower(data));
            output.Append('\n');
            if (output.Length > MaximumTextBytes)
                throw new InvalidOperationException("The complete zone exceeds the master-file export bound.");
        }
        return output.ToString();
    }

    private static AuthoritativeZone ImportCore(DnsName origin, string text)
    {
        var currentOrigin = origin.ToWire();
        byte[]? previousOwner = null;
        uint? defaultTtl = null;
        uint? lastTtl = null;
        List<DnsRecord> records = [];
        var bytes = 6;
        foreach (var entry in MasterFileTokens.Read(text))
        {
            var tokens = entry.Tokens;
            if (!tokens[0].Quoted && tokens[0].Text.StartsWith('$'))
            {
                Require(tokens.Count == 2);
                if (string.Equals(tokens[0].Text, "$ORIGIN", StringComparison.OrdinalIgnoreCase))
                {
                    currentOrigin = MasterFileData.Name(tokens[1], currentOrigin);
                    Require(DnsName.FromWire(currentOrigin).IsSubdomainOf(origin));
                }
                else if (string.Equals(tokens[0].Text, "$TTL", StringComparison.OrdinalIgnoreCase))
                    defaultTtl = MasterFileData.Time(tokens[1], int.MaxValue);
                else
                    throw new FormatException("Unsupported master-file directive.");
                continue;
            }
            var position = 0;
            if (!entry.ReuseOwner)
                previousOwner = MasterFileData.Name(tokens[position++], currentOrigin);
            Require(previousOwner is not null);
            var (type, ttl, data) = ReadRecord(tokens, position, currentOrigin, defaultTtl, ref lastTtl);
            bytes = checked(bytes + previousOwner!.Length + data.Length + 10);
            Require(bytes <= ZoneSnapshot.MaximumPayloadBytes && records.Count < 10_000);
            records.Add(new DnsRecord(previousOwner, type, ttl, data));
        }
        return new AuthoritativeZone(origin, records);
    }

    private static (ushort Type, uint Ttl, byte[] Data) ReadRecord(IReadOnlyList<MasterFileToken> tokens, int position, byte[] origin, uint? defaultTtl, ref uint? lastTtl)
    {
        uint? ttl = null;
        var hasClass = false;
        while (position < tokens.Count)
        {
            var field = tokens[position];
            if (!field.Quoted && field.Text.Length != 0 && field.Text[0] is >= '0' and <= '9')
            {
                Require(ttl is null);
                ttl = MasterFileData.Time(field, int.MaxValue);
                lastTtl = ttl;
            }
            else if (!field.Quoted && (string.Equals(field.Text, "IN", StringComparison.OrdinalIgnoreCase) || string.Equals(field.Text, "CLASS1", StringComparison.OrdinalIgnoreCase)))
            {
                Require(!hasClass);
                hasClass = true;
            }
            else
                break;
            position++;
        }
        Require(position < tokens.Count);
        var type = MasterFileData.Type(tokens[position++]);
        var selectedTtl = ttl ?? defaultTtl ?? lastTtl ?? throw new FormatException("A master-file record requires an explicit or default TTL.");
        return (type, selectedTtl, MasterFileData.Record(type, tokens.Skip(position).ToArray(), origin));
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Invalid or excessive master-file data.");
    }
}
