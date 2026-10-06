namespace Mk8.Dns.Configuration;

public sealed record ApplicationSettings(string SocketPath, string StateDirectory, string NodeId, string Role)
{
    public static ApplicationSettings Parse(string[] args)
    {
        var values = HostArguments.Parse(args, ["--socket", "--state", "--node", "--role"]);
        var socket = HostArguments.AbsolutePath(values, "--socket");
        var state = HostArguments.AbsolutePath(values, "--state");
        var node = HostArguments.Required(values, "--node");
        var role = HostArguments.Required(values, "--role");
        if (node.Length > 128 || node.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
            throw new ArgumentException("Node identity must contain at most 128 ASCII letters, digits, hyphens, or underscores.", nameof(args));
        if (!string.Equals(role, "controller", StringComparison.Ordinal) && !string.Equals(role, "authoritative-replica", StringComparison.Ordinal))
            throw new ArgumentException("Select controller or authoritative-replica explicitly. Other roles are not implemented.", nameof(args));
        return new ApplicationSettings(socket, state, node, role);
    }
}
