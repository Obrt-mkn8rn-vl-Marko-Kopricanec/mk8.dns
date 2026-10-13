namespace Mk8.Dns.Configuration;

public sealed record ApplicationSettings(string SocketPath, string StateDirectory, string NodeId, string Role)
{
    public IReadOnlyList<Guid> ZoneIds { get; init; } = [];
    public string? ControlFile { get; init; }
    public string? PublicationSocket { get; init; }
    public string? CookieSecretFile { get; init; }
    public string? TsigKeyFile { get; init; }
    public string? ControlSecret { get; init; }
    public string? CookieSecret { get; init; }
    public string? TsigSecret { get; init; }
    public UdpResponseBudgetSettings UdpResponseLimits { get; init; } = new();

    public static ApplicationSettings Parse(string[] args) => ParseCore(args, secretReferences: false);

    public static ApplicationSettings FromSecrets(DnsServiceSecrets secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        var settings = ParseCore(secrets.Arguments("Settings"), secretReferences: true);
        if (settings.Role is "controller" && settings.ControlSecret is null) throw new InvalidDataException("SecretControlMissing");
        if (string.Equals(settings.Role, "authoritative-replica", StringComparison.Ordinal))
        {
            if (settings.CookieSecret is null) throw new InvalidDataException("SecretCookieMissing");
            var tsig = secrets.Text("TsigMode", 16);
            if (tsig is not ("enabled" or "disabled") || (string.Equals(tsig, "enabled", StringComparison.Ordinal)) != (settings.TsigSecret is not null))
                throw new InvalidDataException("SecretTsigModeInvalid");
        }
        return settings;
    }

    private static ApplicationSettings ParseCore(string[] args, bool secretReferences)
    {
        var controlOption = secretReferences ? "--control-secret" : "--control";
        var cookieOption = secretReferences ? "--cookie-secret" : "--cookie-secret-file";
        var tsigOption = secretReferences ? "--tsig-secret" : "--tsig-key-file";
        var values = HostArguments.Parse(args, ["--socket", "--state", "--node", "--role", "--zones", controlOption, "--publication-socket", cookieOption, tsigOption, .. UdpResponseBudgetSettings.Arguments]);
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
        var control = Reference(values, controlOption, secretReferences);
        var publication = values.ContainsKey("--publication-socket") ? HostArguments.AbsolutePath(values, "--publication-socket") : null;
        var cookieSecret = Reference(values, cookieOption, secretReferences);
        var tsigKey = Reference(values, tsigOption, secretReferences);
        if (cookieSecret is not null && !string.Equals(role, "authoritative-replica", StringComparison.Ordinal))
            throw new ArgumentException("Only a serving replica can configure cookie secrets.", nameof(args));
        if (tsigKey is not null && !string.Equals(role, "authoritative-replica", StringComparison.Ordinal))
            throw new ArgumentException("Only a serving replica can configure TSIG keys.", nameof(args));
        if ((publication is not null && (control is null || !string.Equals(role, "authoritative-replica", StringComparison.Ordinal)))
            || (control is not null && string.Equals(role, "authoritative-replica", StringComparison.Ordinal) && (publication is null || zones.Count != 0))
            || (publication is not null && string.Equals(publication, socket, StringComparison.Ordinal)))
        {
            throw new ArgumentException("Trusted replica publication requires a separate socket and its configured zone scope.", nameof(args));
        }

        if (secretReferences && string.Equals(role, "authoritative-replica", StringComparison.Ordinal) && UdpResponseBudgetSettings.Arguments.Any(key => !values.ContainsKey(key)))
            throw new InvalidDataException("SecretUdpBudgetMissing");
        return new ApplicationSettings(socket, state, node, role) { ZoneIds = zones.AsReadOnly(), ControlFile = secretReferences ? null : control, ControlSecret = secretReferences ? control : null, PublicationSocket = publication, CookieSecretFile = secretReferences ? null : cookieSecret, CookieSecret = secretReferences ? cookieSecret : null, TsigKeyFile = secretReferences ? null : tsigKey, TsigSecret = secretReferences ? tsigKey : null, UdpResponseLimits = UdpResponseBudgetSettings.Parse(values, role) };
    }

    private static string? Reference(Dictionary<string, string> values, string key, bool secretReferences)
    {
        if (!values.TryGetValue(key, out var name)) return null;
        if (!secretReferences) return HostArguments.AbsolutePath(values, key);
        DnsServiceSecrets.ValidateName(name);
        return name;
    }
}
