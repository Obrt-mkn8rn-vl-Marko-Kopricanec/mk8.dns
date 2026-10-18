using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Supprocom.Secrets;

namespace Mk8.Dns.IntegrationTests;

// Converts only task-owned test inputs to the production installation contract.
// Executables receive no locator, legacy file argument or service value on CLI.
internal sealed class HostInstallationFixture : IDisposable
{
    private readonly string root;
    internal string AssemblyPath { get; }
    internal IReadOnlyDictionary<string, string> AssemblyHashes { get; }

    internal HostInstallationFixture(string host, string[] fixtureArguments, string? dnsPolicy = null)
    {
        root = Path.Combine(Path.GetTempPath(), "m8-install-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var original = RepositoryPaths.HostAssembly(host);
            CopyOutput(Path.GetDirectoryName(original) ?? throw new InvalidDataException("HostOutputMissing"), root);
            AssemblyPath = Path.Combine(root, Path.GetFileName(original));
            AssemblyHashes = Directory.GetFiles(root, "*.dll").ToDictionary(file => Path.GetFileName(file),
                file => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))), StringComparer.Ordinal);
            File.WriteAllText(Path.Combine(root, "appsettings.json"), "not-a-default-config-document");
            var role = host["mk8.dns.".Length..];
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            var arguments = fixtureArguments.ToList();
            if (role is "Application")
            {
                Application(values, arguments);
            }
            else if (role is "Operator")
            {
                Operator(values, arguments);
            }
            else
            {
                if (!arguments.Contains("--role", StringComparer.Ordinal)) arguments.AddRange(["--role", "query"]);
                values.Add("HostPolicy", HostPolicy());
            }
            if (!values.ContainsKey("Recursive")) values.Add("Settings", JsonSerializer.Serialize(arguments));
            if (dnsPolicy is not null)
            {
                if (role is not "Gateway") throw new InvalidOperationException("FixtureDnsPolicyRoleInvalid");
                values.Add("DnsPolicy", dnsPolicy);
            }
            var directory = Path.Combine(root, "Environment");
            Directory.CreateDirectory(directory);
            var text = SupprocomSecretDocument.Serialize(values.Select(pair => new SupprocomSecretSetting(role + ":" + pair.Key, pair.Value)));
            File.WriteAllText(Path.Combine(directory, ".env"), text);
        }
        catch { Directory.Delete(root, recursive: true); throw; }
    }

    private static void CopyOutput(string source, string target)
    {
        foreach (var file in Directory.GetFiles(source)) File.Copy(file, Path.Combine(target, Path.GetFileName(file)));
        foreach (var directory in Directory.GetDirectories(source))
        {
            if (Path.GetFileName(directory) is "Environment") continue;
            var child = Path.Combine(target, Path.GetFileName(directory));
            Directory.CreateDirectory(child); CopyOutput(directory, child);
        }
    }

    private static void Application(Dictionary<string, string> values, List<string> arguments)
    {
        if (arguments.Count == 2 && arguments[0].StartsWith("--recursive-", StringComparison.Ordinal))
        {
            values.Add("Mode", arguments[0][2..^7]);
            var text = File.ReadAllText(arguments[1]);
            using var input = JsonDocument.Parse(text);
            var key = input.RootElement.GetProperty("keyFile").GetString();
            values.Add("AnchorKey", key is not null && File.Exists(key) ? Binary(key) : "AA==");
            // Replace the one fixture field without parsing/reserializing duplicate
            // members: malformed/duplicate production admission controls survive.
            var old = JsonSerializer.Serialize(key);
            values.Add("Recursive", text.Replace("\"keyFile\":" + old, "\"keySecret\":\"AnchorKey\"", StringComparison.Ordinal));
            return;
        }
        values.Add("Mode", "authority"); values.Add("HostPolicy", HostPolicy());
        var control = ReplaceReference(arguments, "--control", "--control-secret", "Control");
        if (control is not null) values.Add("Control", Control(values, control));
        var cookie = ReplaceReference(arguments, "--cookie-secret-file", "--cookie-secret", "Cookie");
        var tsig = ReplaceReference(arguments, "--tsig-key-file", "--tsig-secret", "Tsig");
        if (arguments.Contains("authoritative-replica", StringComparer.Ordinal))
        {
            values.Add("TsigMode", tsig is null ? "disabled" : "enabled");
            if (cookie is null) arguments.AddRange(["--cookie-secret", "Cookie"]);
            values.Add("Cookie", cookie is null ? Cookie() : Binary(cookie));
            if (tsig is not null) values.Add("Tsig", Binary(tsig));
            string[] names = ["response-rate", "response-burst", "byte-rate", "byte-burst", "global-response-rate", "global-response-burst", "global-byte-rate", "global-byte-burst", "prefix-limit"];
            string[] limits = ["100", "200", "51200", "102400", "10000", "20000", "5120000", "10240000", "4096"];
            for (var index = 0; index < names.Length; index++)
                if (!arguments.Contains("--udp-" + names[index], StringComparer.Ordinal)) arguments.AddRange(["--udp-" + names[index], limits[index]]);
        }
    }

    private static string? ReplaceReference(List<string> arguments, string option, string replacement, string name)
    {
        var index = arguments.IndexOf(option);
        if (index < 0) return null;
        var path = arguments[index + 1]; arguments[index] = replacement; arguments[index + 1] = name;
        return path;
    }

    private static string Control(Dictionary<string, string> values, string path)
    {
        var document = JsonNode.Parse(File.ReadAllText(path))?.AsObject() ?? throw new InvalidDataException("FixtureControlMissing");
        MoveText(document, values, "KeyFile", "KeySecret", "PublicationKey");
        MoveText(document, values, "ConnectionStringFile", "ConnectionStringSecret", "Database");
        document.TryAdd("ConnectionStringSecret", value: null); document.TryAdd("PublicationSocket", value: null);
        document.TryAdd("Grants", value: null); document.TryAdd("SigningScanSeconds", 60);
        document.TryAdd("DispatchIntervalMilliseconds", 1000);
        foreach (var zone in document["Zones"]?.AsArray() ?? throw new InvalidDataException("FixtureZonesMissing"))
        {
            var scope = zone?.AsObject() ?? throw new InvalidDataException("FixtureZoneMissing");
            var key = scope["SigningKeyFile"]?.GetValue<string>();
            if (key is not null)
            {
                var name = "ZoneKey" + values.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
                scope.Remove("SigningKeyFile"); scope["SigningKeySecret"] = name;
                values.Add(name, Binary(key));
            }
            scope.TryAdd("SigningKeySecret", value: null); scope.TryAdd("SignatureLifetimeSeconds", 604800);
            scope.TryAdd("DnskeyTtl", 3600); scope.TryAdd("RenewBeforeSeconds", value: null);
        }
        if (document["Grants"] is JsonArray grants)
        {
            foreach (var grant in grants)
            {
                var scope = grant?.AsObject() ?? throw new InvalidDataException("FixtureGrantMissing");
                scope.TryAdd("Profile", "zone"); scope.TryAdd("Actions", new JsonArray("edit", "patch", "read", "status"));
                scope.TryAdd("RecordScopes", new JsonArray());
            }
        }

        return document.ToJsonString();
    }

    private static void MoveText(JsonObject document, Dictionary<string, string> values, string old, string replacement, string name)
    {
        if (document[old]?.GetValue<string>() is not { } path) return;
        document.Remove(old); document[replacement] = name; values.Add(name, File.ReadAllText(path));
    }

    private static void Operator(Dictionary<string, string> values, List<string> arguments)
    {
        var request = ReplaceReference(arguments, "--request", "--request-secret", "Request");
        var credential = ReplaceReference(arguments, "--credential", "--credential-secret", "Credential");
        if (request is not null) values.Add("Request", File.ReadAllText(request));
        if (credential is not null) values.Add("Credential", Binary(credential));
    }

    private static string Binary(string path)
    {
        var bytes = File.ReadAllBytes(path);
        try { return Convert.ToBase64String(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static string HostPolicy() => JsonSerializer.Serialize(new
    {
        ShutdownSeconds = 20,
        HeaderBytes = 4096,
        HeaderCount = 32,
        RequestLineBytes = 2048,
        HeaderTimeoutSeconds = 5,
        Connections = 16,
        ApplicationStreams = 16,
        PublicationStreams = 2,
    });

    private static string Cookie()
    {
        var bytes = new byte[25]; bytes[0] = 1;
        BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(1), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        RandomNumberGenerator.Fill(bytes.AsSpan(9));
        try { return Convert.ToBase64String(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public void Dispose() => Directory.Delete(root, recursive: true);
}
