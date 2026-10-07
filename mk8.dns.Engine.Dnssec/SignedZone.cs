using System.Globalization;
using System.Text;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed class SignedZone
{
    public const int MaximumRecords = 40_002;
    public const int MaximumWireBytes = 4_194_304;
    public const int MaximumExportCharacters = 8_000_000;
    private readonly DnsRecord[] records;

    internal SignedZone(AuthoritativeZone source, DnsRecord[] records, DnsRecord dnskey, DnssecSignatureWindow window)
    {
        Source = source;
        this.records = (DnsRecord[])records.Clone();
        Dnskey = dnskey;
        Window = window;
        ParentDs = DnssecKeys.CreateDs(dnskey, dnskey.Ttl);
    }

    public AuthoritativeZone Source { get; }
    public DnsName Origin => Source.Origin;
    public DnsRecord Dnskey { get; }
    public DnsRecord ParentDs { get; }
    public DnssecSignatureWindow Window { get; }
    public IReadOnlyList<DnsRecord> GetAllRecords() => Array.AsReadOnly(records);

    public string ExportMasterFile()
    {
        var text = new StringBuilder();
        foreach (var record in records.OrderBy(record => record.Owner, DnssecNameOrder.Instance).ThenBy(record => record.Type)
            .ThenBy(record => Convert.ToHexString(record.GetData()), StringComparer.Ordinal))
        {
            var data = record.GetData();
            var line = record.Owner.ToString() + " " + record.Ttl.ToString(CultureInfo.InvariantCulture) + " IN TYPE"
                + record.Type.ToString(CultureInfo.InvariantCulture) + " \\# " + data.Length.ToString(CultureInfo.InvariantCulture)
                + (data.Length == 0 ? string.Empty : " " + Convert.ToHexString(data)) + "\n";
            if (line.Length > MaximumExportCharacters - text.Length)
                throw new InvalidOperationException("Complete signed-zone export exceeds its character bound.");
            text.Append(line);
        }
        return text.ToString();
    }
}
