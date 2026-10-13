using Mk8.Dns.Configuration;
using Supprocom.Secrets;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ServiceSecretsTests
{
    [Fact]
    public async Task StartupSnapshotRemainsIndependentOfLaterProtectedDocumentChanges()
    {
        using var fixture = new SecretsFixture();
        fixture.Write([new("Gateway:Settings", "[\"first\"]")]);
        var first = await DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, CancellationToken.None);
        var store = fixture.Store();
        Assert.Equal(SecretFileProtectionState.Protected, await store.GetStateAsync(CancellationToken.None));
        await store.SetAsync("Gateway:Settings", "[\"second\"]", CancellationToken.None);
        var second = await DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, CancellationToken.None);
        Assert.Equal(["first"], first.Arguments("Settings"));
        Assert.Equal(["second"], second.Arguments("Settings"));
        Assert.True(File.Exists(Path.Combine(fixture.Root, ".installation.key")));
    }

    [Fact]
    public async Task MissingActiveDocumentCannotCreateOrUseTemplateConfiguration()
    {
        using var fixture = new SecretsFixture();
        await File.WriteAllTextAsync(Path.Combine(fixture.Root, ".env.template"), "Gateway__Settings=not-active", CancellationToken.None);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, CancellationToken.None));
        Assert.Equal("SecretDocumentMissing", error.Message);
        Assert.False(File.Exists(Path.Combine(fixture.Root, ".env")));
        Assert.False(File.Exists(Path.Combine(fixture.Root, ".installation.key")));
    }

    [Fact]
    public async Task ProductionIgnoresDevelopmentDocumentsAndPreservesRoleIsolation()
    {
        using var fixture = new SecretsFixture();
        fixture.Write([new("Gateway:Settings", "[\"production\"]")]);
        await File.WriteAllTextAsync(Path.Combine(fixture.Root, ".dev.env"), "Gateway__Settings=not-production", CancellationToken.None);
        var snapshot = await DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, CancellationToken.None);
        Assert.Equal(["production"], snapshot.Arguments("Settings"));
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => DnsServiceSecrets.LoadDirectoryAsync("Application", fixture.Root, CancellationToken.None));
        Assert.Equal("SecretRoleMismatch", error.Message);
    }

    [Fact]
    public async Task BuiltinStoreRefusesExternalPointersWithoutResolvingThem()
    {
        using var fixture = new SecretsFixture();
        await File.WriteAllTextAsync(Path.Combine(fixture.Root, ".env"), "SUPPROCOM_SECRET_SOURCE=unadopted://fixture.invalid/secret\n", CancellationToken.None);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, CancellationToken.None));
        Assert.Equal("SecretLoadFailed:ExternalProviderPointer", error.Message);
        Assert.DoesNotContain("fixture.invalid", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"a\":1,\"A\":2}", "SecretJsonDuplicate")]
    [InlineData("{\"a\":1e999}", "SecretJsonNumberInvalid")]
    [InlineData("{\"a\":", "SecretJsonInvalid:Settings")]
    public async Task StructuredValuesRefuseAmbiguousOrInvalidInputsWithoutValueDiagnostics(string input, string reason)
    {
        using var fixture = new SecretsFixture(); fixture.Write([new("Gateway:Settings", input)]);
        var snapshot = await DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, CancellationToken.None);
        var error = Assert.Throws<InvalidDataException>(() => snapshot.JsonText("Settings"));
        Assert.Equal(reason, error.Message);
    }

    [Fact]
    public async Task RequiredHostPolicyAndDecodedCredentialsRefuseBeforeUse()
    {
        using var fixture = new SecretsFixture();
        fixture.Write([new("Gateway:HostPolicy", "{}"), new("Gateway:Credential", "not-base64")]);
        var snapshot = await DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, CancellationToken.None);
        Assert.Equal("SecretHostPolicyInvalid", Assert.Throws<InvalidDataException>(() => ServiceHostPolicy.FromSecrets(snapshot)).Message);
        Assert.Equal("SecretEncodingInvalid:Credential", Assert.Throws<InvalidDataException>(() => snapshot.Bytes("Credential", 32)).Message);
        Assert.Equal("SecretSettingUnknown", Assert.Throws<InvalidDataException>(() => snapshot.RequireOnly(["HostPolicy"])).Message);
    }

    [Fact]
    public async Task DuplicateDotenvKeysRefuseWithoutLastValuePrecedence()
    {
        using var fixture = new SecretsFixture();
        await File.WriteAllTextAsync(Path.Combine(fixture.Root, ".env"), "Gateway__Settings=first\nGateway__Settings=second\n", CancellationToken.None);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, CancellationToken.None));
        Assert.Equal("SecretLoadFailed:DuplicateDotenvKey", error.Message);
    }

    [Fact]
    public async Task PreCanceledLoadDoesNotReadOrProtectInput()
    {
        using var fixture = new SecretsFixture(); fixture.Write([new("Gateway:Settings", "[\"fixture\"]")]);
        using var stop = new CancellationTokenSource(); await stop.CancelAsync();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DnsServiceSecrets.LoadDirectoryAsync("Gateway", fixture.Root, stop.Token));
        Assert.Equal(stop.Token, error.CancellationToken);
        Assert.False(File.Exists(Path.Combine(fixture.Root, ".installation.key")));
    }

    private sealed class SecretsFixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "m8-secrets-" + Guid.NewGuid().ToString("N"));
        internal SecretsFixture() => Directory.CreateDirectory(Root);
        internal void Write(IEnumerable<SupprocomSecretSetting> settings)
            => File.WriteAllText(Path.Combine(Root, ".env"), SupprocomSecretDocument.Serialize(settings));
        internal SupprocomSecretFileStore Store()
        {
            var options = new SupprocomSecretsOptions { EnvironmentName = "Production", FileOverridesProcessEnvironment = true };
            options.File.Directory = Root; options.File.Import = SecretFileImport.None;
            options.File.Recovery = SecretFileRecovery.None; options.File.Protection = SecretFileProtection.InstallationBoundAesGcm;
            return new SupprocomSecretFileStore(options);
        }
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
