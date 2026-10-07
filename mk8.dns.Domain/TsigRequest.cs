namespace Mk8.Dns.Domain;

public sealed class TsigRequest
{
    private readonly byte[] message;
    private readonly byte[] mac;
    private readonly byte[] other;

    public TsigRequest(byte[] message, DnsName keyName, DnsName algorithm, ulong timeSigned, ushort fudge, byte[] mac, ushort originalId, ushort error, byte[] otherData)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(keyName);
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(mac);
        ArgumentNullException.ThrowIfNull(otherData);
        if (message.Length is < 12 or > ushort.MaxValue || timeSigned > 0xffff_ffff_ffff || mac.Length > ushort.MaxValue || otherData.Length > ushort.MaxValue)
            throw new ArgumentException("Invalid TSIG wire bounds.", nameof(message));
        this.message = (byte[])message.Clone();
        this.mac = (byte[])mac.Clone();
        other = (byte[])otherData.Clone();
        KeyName = keyName;
        Algorithm = algorithm;
        TimeSigned = timeSigned;
        Fudge = fudge;
        OriginalId = originalId;
        Error = error;
    }

    public DnsName KeyName { get; }
    public DnsName Algorithm { get; }
    public ulong TimeSigned { get; }
    public ushort Fudge { get; }
    public ushort OriginalId { get; }
    public ushort Error { get; }
    public byte[] GetMessage() => (byte[])message.Clone();
    public byte[] GetMac() => (byte[])mac.Clone();
    public byte[] GetOtherData() => (byte[])other.Clone();
}
