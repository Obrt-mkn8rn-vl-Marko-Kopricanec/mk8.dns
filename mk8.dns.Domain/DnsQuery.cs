namespace Mk8.Dns.Domain;

public sealed class DnsQuery
{
    private readonly byte[] name;
    private readonly byte[]? cookie;

    public DnsQuery(ushort id, ushort flags, DnsQuestion question, byte[] name, ushort udpPayloadSize, bool hasEdns, byte ednsVersion, bool dnssecOk)
        : this(id, flags, question ?? throw new ArgumentNullException(nameof(question)), name, udpPayloadSize, hasEdns, ednsVersion, dnssecOk, null) { }

    public DnsQuery(ushort id, ushort flags, DnsQuestion? question, byte[] name, ushort udpPayloadSize, bool hasEdns, byte ednsVersion, bool dnssecOk, byte[]? cookie)
    {
        ArgumentNullException.ThrowIfNull(name);
        if ((question is null ? name.Length != 0 || !hasEdns || cookie is null : !DnsName.FromWire(name).Equals(question.Name))
            || udpPayloadSize is < 512 or > 1232 || cookie is not null && (!hasEdns || cookie.Length > ushort.MaxValue))
            throw new ArgumentException("Invalid decoded DNS query metadata.", nameof(name));
        Id = id;
        Flags = flags;
        Question = question;
        this.name = (byte[])name.Clone();
        this.cookie = cookie is null ? null : (byte[])cookie.Clone();
        UdpPayloadSize = udpPayloadSize;
        HasEdns = hasEdns;
        EdnsVersion = ednsVersion;
        DnssecOk = dnssecOk;
    }

    public ushort Id { get; }
    public ushort Flags { get; }
    public DnsQuestion? Question { get; }
    public ushort UdpPayloadSize { get; }
    public bool HasEdns { get; }
    public byte EdnsVersion { get; }
    public bool DnssecOk { get; }
    public byte[] GetQuestionNameWire() => (byte[])name.Clone();
    public byte[]? GetCookieWire() => cookie is null ? null : (byte[])cookie.Clone();
}
