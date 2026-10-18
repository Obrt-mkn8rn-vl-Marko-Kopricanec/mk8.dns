using Npgsql;

namespace Mk8.Dns.Application.DAL;

// Complete the local profile before acquisition, so Npgsql's optional process
// and password-file sources cannot supply values omitted from the role snapshot.
internal static class LocalPostgresConnection
{
    internal static NpgsqlConnectionStringBuilder Create(string connectionString)
    {
        ArgumentException.ThrowIfNullOrEmpty(connectionString);
        NpgsqlConnectionStringBuilder? settings = null;
        try { settings = new NpgsqlConnectionStringBuilder(connectionString); }
        catch (ArgumentException) { /* Driver diagnostics can contain protected input. */ }
        if (settings is null) throw new ArgumentException("SecretDatabaseInvalid", nameof(connectionString));
        ValidateIdentity(settings);
        ValidateTransport(settings);
        CompleteAuthentication(settings);
        settings.ClientEncoding = Default(settings.ClientEncoding, "UTF8");
        settings.Timezone = Default(settings.Timezone, "UTC");
        settings.ApplicationName = Default(settings.ApplicationName, "mk8.dns");
        // A whitespace no-op survives connection-string serialization as a
        // nonnull value. Null would permit the driver's PGOPTIONS fallback.
        settings.Options = Default(settings.Options, " ");
        settings.TargetSessionAttributes ??= "any";
        return settings;
    }

    private static void ValidateIdentity(NpgsqlConnectionStringBuilder settings)
    {
        if (settings.Host is null || !Path.IsPathFullyQualified(settings.Host) || settings.Host.Contains(',', StringComparison.Ordinal))
            throw new ArgumentException("This controller profile requires one local PostgreSQL Unix socket directory.", nameof(settings));
        if (!settings.ShouldSerialize("Host") || !settings.ShouldSerialize("Database")
            || !settings.ShouldSerialize("Username") || !settings.ShouldSerialize("Port")
            || string.IsNullOrWhiteSpace(settings.Database) || string.IsNullOrWhiteSpace(settings.Username)
            || settings.Port is < 1 or > 65535)
        {
            throw new ArgumentException("SecretDatabaseScopeMissing", nameof(settings));
        }
    }

    private static void ValidateTransport(NpgsqlConnectionStringBuilder settings)
    {
        string[] locators = ["Passfile", "SSL Certificate", "SSL Key", "SSL Password", "Root Certificate"];
        if (locators.Any(settings.ShouldSerialize))
            throw new ArgumentException("SecretDatabaseExternalInputRefused", nameof(settings));
        if ((settings.ShouldSerialize("SSL Mode") && settings.SslMode != SslMode.Disable)
            || (settings.ShouldSerialize("GSS Encryption Mode") && settings.GssEncryptionMode != GssEncryptionMode.Disable)
            || (settings.ShouldSerialize("SSL Negotiation") && settings.SslNegotiation != SslNegotiation.Postgres))
        {
            throw new ArgumentException("SecretDatabaseLocalTransportRequired", nameof(settings));
        }
        settings.SslMode = SslMode.Disable;
        settings.GssEncryptionMode = GssEncryptionMode.Disable;
        settings.SslNegotiation = SslNegotiation.Postgres;
    }

    private static void CompleteAuthentication(NpgsqlConnectionStringBuilder settings)
    {
        var hasPassword = !string.IsNullOrEmpty(settings.Password);
        settings.RequireAuth ??= hasPassword ? "None,Password,MD5,ScramSHA256" : "None";
        foreach (var mode in settings.RequireAuth.Split(','))
        {
            if (mode is not ("None" or "Password" or "MD5" or "ScramSHA256") || (!hasPassword && mode is not "None"))
                throw new ArgumentException("SecretDatabaseAuthenticationRefused", nameof(settings));
        }
        // Without a snapshot password, only AuthenticationOk is allowed. The
        // driver refuses password challenges before consulting any fallback.
    }

    private static string Default(string? value, string fallback) => string.IsNullOrEmpty(value) ? fallback : value;
}
