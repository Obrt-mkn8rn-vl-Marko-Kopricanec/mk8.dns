using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using Supprocom.Secrets;

namespace Mk8.Dns.Configuration;

// A single installation-local Supprocom snapshot, never a reloadable or fallback
// configuration channel. Strings belong to the package snapshot; mutable decoded
// secret buffers belong to callers and must be cleared after their actual use.
public sealed class DnsServiceSecrets
{
    private readonly IReadOnlyDictionary<string, string> values;

    private DnsServiceSecrets(string role, IReadOnlyDictionary<string, string> source)
    {
        if (source.Count is 0 or > 256) throw new InvalidDataException("SecretSchemaBounds");
        Dictionary<string, string> owned = new(StringComparer.OrdinalIgnoreCase);
        long bytes = 0;
        foreach (var (key, value) in source)
        {
            if (!key.StartsWith(role + ":", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("SecretRoleMismatch");
            var name = key[(role.Length + 1)..];
            ValidateName(name);
            bytes += Encoding.UTF8.GetByteCount(value);
            if (bytes > 2_097_152 || !owned.TryAdd(name, value))
                throw new InvalidDataException("SecretSchemaBounds");
        }
        values = new ReadOnlyDictionary<string, string>(owned);
    }

    public static Task<DnsServiceSecrets> LoadAsync(string role, CancellationToken cancellationToken)
        => LoadDirectoryAsync(role, Path.Combine(AppContext.BaseDirectory, "Environment"), cancellationToken);

    internal static async Task<DnsServiceSecrets> LoadDirectoryAsync(string role, string directory, CancellationToken token)
    {
        if (role is not ("Application" or "Gateway" or "Operator")) throw new ArgumentException("SecretRoleInvalid", nameof(role));
        token.ThrowIfCancellationRequested();
        // Refuse missing active input; publishing a placeholder template cannot
        // silently synthesize usable settings or a trust/security-state floor.
        if (!File.Exists(Path.Combine(directory, ".env"))) throw new InvalidDataException("SecretDocumentMissing");
        return await AcquireSnapshotAsync(role, CreateActiveStore(directory), token).ConfigureAwait(false);
    }

    internal static async Task<DnsServiceSecrets> AcquireSnapshotAsync(string role, SupprocomSecretFileStore store, CancellationToken token)
    {
        IReadOnlyDictionary<string, string>? snapshot = null;
        string? refusal = null;
        try { snapshot = await store.LoadAsync(token).ConfigureAwait(false); }
        catch (SupprocomSecretsException error) { refusal = error.Code; }
        // Normalize only the package refusal code. Its diagnostic/inner graph may
        // contain installation values and must not reach unhandled host output.
        if (refusal is not null) throw new InvalidDataException("SecretLoadFailed:" + refusal);
        token.ThrowIfCancellationRequested();
        return new DnsServiceSecrets(role, snapshot ?? throw new InvalidDataException("SecretSnapshotMissing"));
    }

    internal static SupprocomSecretFileStore CreateActiveStore(string directory)
    {
        var options = new SupprocomSecretsOptions
        {
            EnvironmentName = "Production",
            FileOverridesProcessEnvironment = true,
        };
        options.File.Directory = directory;
        // The builtin must never acquire values from a separate template, even
        // when its active-file check sees an empty or lost document.
        options.File.ActiveName = ".env";
        options.File.TemplateName = options.File.ActiveName;
        options.File.Import = SecretFileImport.None;
        options.File.Recovery = SecretFileRecovery.None;
        options.File.Protection = SecretFileProtection.InstallationBoundAesGcm;
        return new SupprocomSecretFileStore(options);
    }

    public string Text(string name, int maximumBytes = 65536)
    {
        ValidateName(name);
        if (!values.TryGetValue(name, out var value) || value.Length == 0 || Encoding.UTF8.GetByteCount(value) > maximumBytes)
            throw new InvalidDataException("SecretValueMissingOrOversized:" + name);
        return value;
    }

    public byte[] Bytes(string name, int maximumBytes)
    {
        var value = Text(name, checked((maximumBytes + 2) / 3 * 4));
        byte[]? bytes = null;
        try { bytes = Convert.FromBase64String(value); }
        catch (FormatException) { /* Public refusal below intentionally omits secret-bearing diagnostics. */ }
        if (bytes is null) throw new InvalidDataException("SecretEncodingInvalid:" + name);
        if (bytes.Length is 0 || bytes.Length > maximumBytes)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException("SecretBytesInvalid:" + name);
        }
        return bytes;
    }

    public string JsonText(string name, int maximumBytes = 65536)
    {
        var text = Text(name, maximumBytes);
        var valid = false;
        try
        {
            using var document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 16 });
            ValidateJson(document.RootElement);
            valid = true;
        }
        catch (JsonException) { /* Json diagnostics are not a permitted secret-output channel. */ }
        if (!valid) throw new InvalidDataException("SecretJsonInvalid:" + name);
        return text;
    }

    private static void ValidateJson(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("SecretJsonDuplicate");
                ValidateJson(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) ValidateJson(item);
        }
        else if (element.ValueKind == JsonValueKind.Number && (!element.TryGetDouble(out var value) || !double.IsFinite(value)))
        {
            throw new InvalidDataException("SecretJsonNumberInvalid");
        }
    }

    public string[] Arguments(string name)
    {
        var text = Text(name);
        string[]? arguments = null;
        try { arguments = JsonSerializer.Deserialize<string[]>(text); }
        catch (JsonException) { /* Missing result below is a value-free schema refusal. */ }
        if (arguments is null || arguments.Length is 0 or > 128 || arguments.Any(string.IsNullOrEmpty))
            throw new InvalidDataException("SecretSettingsInvalid:" + name);
        return arguments;
    }

    public void RequireOnly(IEnumerable<string> names)
    {
        ArgumentNullException.ThrowIfNull(names);
        var allowed = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
        if (values.Keys.Any(name => !allowed.Contains(name))) throw new InvalidDataException("SecretSettingUnknown");
    }

    public static void ValidateName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name.Length is 0 or > 128 || name.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '_' and not '-' and not '.'))
            throw new InvalidDataException("SecretReferenceInvalid");
    }
}
