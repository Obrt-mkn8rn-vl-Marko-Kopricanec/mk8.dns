namespace Mk8.Dns.Domain;

public sealed class DnsQuery
{
    private readonly byte[] name;

    public DnsQuery(ushort id, ushort flags, DnsQuestion question, byte[] name, ushort udpPayloadSize, bool hasEdns, byte ednsVersion, bool dnssecOk)
    {
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(name);
        if (!DnsName.FromWire(name).Equals(question.Name) || udpPayloadSize is < 512 or > 1232)
            throw new ArgumentException("Invalid decoded DNS query metadata.", nameof(name));
        Id = id;
        Flags = flags;
        Question = question;
        this.name = (byte[])name.Clone();
        UdpPayloadSize = udpPayloadSize;
        HasEdns = hasEdns;
        EdnsVersion = ednsVersion;
        DnssecOk = dnssecOk;
    }

    public ushort Id { get; }
    public ushort Flags { get; }
    public DnsQuestion Question { get; }
    public ushort UdpPayloadSize { get; }
    public bool HasEdns { get; }
    public byte EdnsVersion { get; }
    public bool DnssecOk { get; }
    public byte[] GetQuestionNameWire() => (byte[])name.Clone();
}
