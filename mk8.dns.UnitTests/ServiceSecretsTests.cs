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

    [Theory]
    [InlineData("Application", false)]
    [InlineData("Application", true)]
    [InlineData("Gateway", false)]
    [InlineData("Gateway", true)]
    [InlineData("Operator", false)]
    [InlineData("Operator", true)]
    public async Task MissingOrEmptyActiveCannotAcquireAnIndependentValidTemplate(string role, bool empty)
    {
        using var fixture = new SecretsFixture();
        var active = Path.Combine(fixture.Root, ".env");
        if (empty) await File.WriteAllBytesAsync(active, [], CancellationToken.None);
        var template = SupprocomSecretDocument.Serialize([new(role + ":Settings", "[\"template-sentinel\"]")]);
        Assert.Single(SupprocomSecretDocument.Parse(template).Settings);
        var templatePath = Path.Combine(fixture.Root, ".env.template");
        await File.WriteAllTextAsync(templatePath, template, CancellationToken.None);
        var key = Enumerable.Repeat((byte)42, 32).ToArray(); // NONPRODUCTION installation fixture key.
        var keyPath = Path.Combine(fixture.Root, ".installation.key");
        await File.WriteAllBytesAsync(keyPath, key, CancellationToken.None);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => DnsServiceSecrets.LoadDirectoryAsync(role, fixture.Root, CancellationToken.None));
        Assert.Equal(empty ? "SecretLoadFailed:InvalidTemplate" : "SecretDocumentMissing", error.Message);
        Assert.Equal(empty, File.Exists(active));
        if (empty) Assert.Empty(await File.ReadAllBytesAsync(active, CancellationToken.None));
        Assert.Equal(template, await File.ReadAllTextAsync(templatePath, CancellationToken.None));
        Assert.Equal(key, await File.ReadAllBytesAsync(keyPath, CancellationToken.None));
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData("Application")]
    [InlineData("Gateway")]
    [InlineData("Operator")]
    public async Task ValidActiveValuesRemainAuthoritativeBesideAnIndependentTemplate(string role)
    {
        using var fixture = new SecretsFixture();
        fixture.Write([new(role + ":Settings", "[\"active-sentinel\"]")]);
        var template = SupprocomSecretDocument.Serialize([new(role + ":Settings", "[\"template-sentinel\"]")]);
        var path = Path.Combine(fixture.Root, ".env.template");
        await File.WriteAllTextAsync(path, template, CancellationToken.None);
        var snapshot = await DnsServiceSecrets.LoadDirectoryAsync(role, fixture.Root, CancellationToken.None);
        Assert.Equal(["active-sentinel"], snapshot.Arguments("Settings"));
        Assert.Equal(template, await File.ReadAllTextAsync(path, CancellationToken.None));
        Assert.Equal(SecretFileProtectionState.Protected, await fixture.Store().GetStateAsync(CancellationToken.None));
    }

    [Fact]
    public async Task LostActiveAtBuiltinAcquisitionReturnsNoValuesOrSynthesis()
    {
        using var fixture = new SecretsFixture();
        fixture.Write([new("Gateway:Settings", "[\"active\"]")]);
        var store = DnsServiceSecrets.CreateActiveStore(fixture.Root);
        var template = SupprocomSecretDocument.Serialize([new("Gateway:Settings", "[\"template\"]")]);
        var path = Path.Combine(fixture.Root, ".env.template");
        await File.WriteAllTextAsync(path, template, CancellationToken.None);
        File.Delete(Path.Combine(fixture.Root, ".env"));
        Assert.Empty(await store.LoadAsync(CancellationToken.None));
        Assert.False(File.Exists(Path.Combine(fixture.Root, ".env")));
        Assert.False(File.Exists(Path.Combine(fixture.Root, ".installation.key")));
        Assert.Equal(template, await File.ReadAllTextAsync(path, CancellationToken.None));
    }

    [Fact]
    public async Task LostActiveIsRefusedBeforeTheDnsSnapshotCanBePublished()
    {
        using var fixture = new SecretsFixture();
        fixture.Write([new("Gateway:Settings", "[\"active\"]")]);
        var store = DnsServiceSecrets.CreateActiveStore(fixture.Root);
        var template = SupprocomSecretDocument.Serialize([new("Gateway:Settings", "[\"template\"]")]);
        var path = Path.Combine(fixture.Root, ".env.template");
        await File.WriteAllTextAsync(path, template, CancellationToken.None);
        File.Delete(Path.Combine(fixture.Root, ".env"));
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => DnsServiceSecrets.AcquireSnapshotAsync("Gateway", store, CancellationToken.None));
        Assert.Equal("SecretSchemaBounds", error.Message);
        Assert.Null(error.InnerException);
        Assert.False(File.Exists(Path.Combine(fixture.Root, ".env")));
        Assert.False(File.Exists(Path.Combine(fixture.Root, ".installation.key")));
        Assert.Equal(template, await File.ReadAllTextAsync(path, CancellationToken.None));
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
