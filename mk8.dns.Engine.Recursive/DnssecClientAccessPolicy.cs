namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecClientAccessPolicy
{
    private readonly DnssecClientNetwork[] networks;

    public DnssecClientAccessPolicy(IEnumerable<DnssecClientNetwork> networks, bool authenticatedDataAllowed = false)
    {
        ArgumentNullException.ThrowIfNull(networks);
        this.networks = [.. networks.Take(65)];
        if (this.networks.Length > 64 || this.networks.Any(network => network is null)
            || this.networks.Select(network => network.Identity).Distinct(StringComparer.Ordinal).Take(this.networks.Length + 1).Count() != this.networks.Length)
        {
            throw new ArgumentException("Supply at most sixty-four distinct explicit client networks.", nameof(networks));
        }
        AuthenticatedDataAllowed = authenticatedDataAllowed;
    }

    public bool AuthenticatedDataAllowed { get; }
    public int NetworkCount => networks.Length;

    public bool Allows(ReadOnlySpan<byte> peer)
    {
        if (peer.Length is not (4 or 16)) return false;
        // Reject mapped identities rather than silently mixing address families.
        // The actual transport must supply its canonical peer family explicitly.
        if (peer.Length == 16 && peer[..10].IndexOfAnyExcept((byte)0) < 0 && peer[10] == 255 && peer[11] == 255)
            return false;
        foreach (var network in networks)
            if (network.Contains(peer)) return true;
        return false;
    }
}
