namespace Mk8.Dns.Domain;

public sealed class DnsAnswer
{
    public DnsAnswer(byte responseCode, bool authoritative, IEnumerable<DnsRecord> answers, IEnumerable<DnsRecord> authority, IEnumerable<DnsRecord> additional)
    {
        ArgumentNullException.ThrowIfNull(answers);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(additional);
        ResponseCode = responseCode;
        Authoritative = authoritative;
        Answers = Array.AsReadOnly(answers.ToArray());
        Authority = Array.AsReadOnly(authority.ToArray());
        Additional = Array.AsReadOnly(additional.ToArray());
    }

    public byte ResponseCode { get; }
    public bool Authoritative { get; }
    public IReadOnlyList<DnsRecord> Answers { get; }
    public IReadOnlyList<DnsRecord> Authority { get; }
    public IReadOnlyList<DnsRecord> Additional { get; }
}
