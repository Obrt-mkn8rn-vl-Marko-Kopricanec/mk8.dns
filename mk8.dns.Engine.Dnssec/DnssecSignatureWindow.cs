namespace Mk8.Dns.Engine.Dnssec;

public sealed class DnssecSignatureWindow
{
    public DnssecSignatureWindow(uint inception, uint expiration)
    {
        var duration = unchecked(expiration - inception);
        if (duration is 0 or >= 0x80000000)
            throw new ArgumentException("A DNSSEC validity interval must advance within the serial half-space.", nameof(expiration));
        Inception = inception;
        Expiration = expiration;
    }

    public uint Inception { get; }
    public uint Expiration { get; }
    public bool Contains(uint now) => unchecked(now - Inception) <= unchecked(Expiration - Inception);
}
