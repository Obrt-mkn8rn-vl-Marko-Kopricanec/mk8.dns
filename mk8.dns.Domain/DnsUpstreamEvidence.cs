namespace Mk8.Dns.Domain;

public sealed class DnsUpstreamEvidence
{
    public const int MaximumRecords = 512;
    public const int MaximumExpandedBytes = 1_048_576;

    public DnsUpstreamEvidence(DnsQuestion question, DnsServerEndpoint server, ushort id, ushort flags, ushort responseCode,
        bool hasEdns, ushort udpPayloadSize, byte ednsVersion, ushort ednsFlags, IEnumerable<DnsRecord> answers,
        IEnumerable<DnsRecord> authority, IEnumerable<DnsRecord> additional)
    {
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(answers);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(additional);
        if (question.Name is null || question.Class != 1 || question.Type is 0 or 41 or (>= 249 and <= 255)
            || (flags & 0xfa40) != 0x8000 || responseCode > 4095 || (responseCode & 15) != (flags & 15)
            || !hasEdns && (responseCode > 15 || udpPayloadSize != 0 || ednsVersion != 0 || ednsFlags != 0))
            throw new ArgumentException("Invalid complete upstream evidence metadata.", nameof(flags));
        var answerRecords = Snapshot(answers);
        var authorityRecords = Snapshot(authority);
        var additionalRecords = Snapshot(additional);
        var count = answerRecords.Length + authorityRecords.Length + additionalRecords.Length;
        if (count > MaximumRecords - (hasEdns ? 1 : 0)
            || answerRecords.Concat(authorityRecords).Concat(additionalRecords)
                .Sum(record => (long)record.GetOwnerWire().Length + 10 + record.GetData().Length) > MaximumExpandedBytes)
            throw new ArgumentException("Upstream evidence exceeds its record or byte bound.", nameof(answers));
        Question = question;
        Server = server;
        Id = id;
        Flags = flags;
        ResponseCode = responseCode;
        HasEdns = hasEdns;
        UdpPayloadSize = udpPayloadSize;
        EdnsVersion = ednsVersion;
        EdnsFlags = ednsFlags;
        Answers = Array.AsReadOnly(answerRecords);
        Authority = Array.AsReadOnly(authorityRecords);
        Additional = Array.AsReadOnly(additionalRecords);
    }

    public DnsQuestion Question { get; }
    public DnsServerEndpoint Server { get; }
    public ushort Id { get; }
    public ushort Flags { get; }
    public ushort ResponseCode { get; }
    public bool Authoritative => (Flags & 0x0400) != 0;
    public bool RecursionAvailable => (Flags & 0x0080) != 0;
    public bool AuthenticatedDataObserved => (Flags & 0x0020) != 0;
    public bool CheckingDisabledObserved => (Flags & 0x0010) != 0;
    public bool HasEdns { get; }
    public ushort UdpPayloadSize { get; }
    public byte EdnsVersion { get; }
    public ushort EdnsFlags { get; }
    public bool DnssecOkObserved => HasEdns && (EdnsFlags & 0x8000) != 0;
    public IReadOnlyList<DnsRecord> Answers { get; }
    public IReadOnlyList<DnsRecord> Authority { get; }
    public IReadOnlyList<DnsRecord> Additional { get; }

    private static DnsRecord[] Snapshot(IEnumerable<DnsRecord> source)
    {
        var records = source.Take(MaximumRecords + 1).ToArray();
        if (records.Length > MaximumRecords || records.Any(record => record is null))
            throw new ArgumentException("Invalid bounded upstream evidence records.", nameof(source));
        return records;
    }
}
