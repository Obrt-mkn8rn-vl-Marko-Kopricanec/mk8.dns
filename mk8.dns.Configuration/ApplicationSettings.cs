namespace Mk8.Dns.Configuration;

public sealed record ApplicationSettings(string SocketPath, string StateDirectory, string NodeId, string Role)
{
    public IReadOnlyList<Guid> ZoneIds { get; init; } = Array.Empty<Guid>();

    public static ApplicationSettings Parse(string[] args)
    {
        var values = HostArguments.Parse(args, ["--socket", "--state", "--node", "--role", "--zones"]);
        var socket = HostArguments.AbsolutePath(values, "--socket");
        var state = HostArguments.AbsolutePath(values, "--state");
        var node = HostArguments.Required(values, "--node");
        var role = HostArguments.Required(values, "--role");
        if (node.Length > 128 || node.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
            throw new ArgumentException("Node identity must contain at most 128 ASCII letters, digits, hyphens, or underscores.", nameof(args));
        if (!string.Equals(role, "controller", StringComparison.Ordinal) && !string.Equals(role, "authoritative-replica", StringComparison.Ordinal))
            throw new ArgumentException("Select controller or authoritative-replica explicitly. Other roles are not implemented.", nameof(args));
        var zones = new List<Guid>();
        if (values.TryGetValue("--zones", out var zoneText))
        {
            if (!string.Equals(role, "authoritative-replica", StringComparison.Ordinal) || zoneText.Length > 2111)
                throw new ArgumentException("Only an authority replica can load up to 64 configured zones.", nameof(args));
            foreach (var part in zoneText.Split(','))
            {
                if (!Guid.TryParseExact(part, "N", out var id) || id == Guid.Empty || zones.Contains(id) || zones.Count == 64)
                    throw new ArgumentException("Zone identities must be distinct nonempty GUIDs in N format.", nameof(args));
                zones.Add(id);
            }
        }
        return new ApplicationSettings(socket, state, node, role) { ZoneIds = zones.AsReadOnly() };
    }
}
