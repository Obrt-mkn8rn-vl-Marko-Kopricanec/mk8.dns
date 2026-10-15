using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class OperatorProtectedRequestTests
{
    [Theory]
    [InlineData("unknown")]
    [InlineData("guid")]
    [InlineData("null")]
    public async Task InvalidTypedRequestRefusesWithoutProtectedPropertyOrPathDiagnostics(string shape)
    {
        const string sentinel = "controlled-protected-member-sentinel-17";
        var root = Path.Combine(Path.GetTempPath(), "m8op-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var request = Path.Combine(root, "request.json");
            var credential = Path.Combine(root, "credential.bin");
            await File.WriteAllTextAsync(request, shape switch
            {
                "unknown" => "{\"" + sentinel + "\":1}",
                "guid" => "{\"TenantId\":\"" + sentinel + "\"}",
                _ => "null",
            }).ConfigureAwait(true);
            // Empty credential would fail a later decoder: schema refusal comes first.
            await File.WriteAllBytesAsync(credential, []).ConfigureAwait(true);
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var child = new HostProcess("mk8.dns.Operator", ["--socket", Path.Combine(root, "absent.sock"),
                "--request", request, "--credential", credential], 0);
            await using var childLifetime = child.ConfigureAwait(true);
            await child.WaitForExitAsync(guard.Token).ConfigureAwait(true);
            Assert.NotEqual(0, child.ExitCode);
            var logs = await child.ReadLogsAsync(guard.Token).ConfigureAwait(true);
            Assert.Contains("SecretManagementRequestInvalid", logs, StringComparison.Ordinal);
            Assert.DoesNotContain(sentinel, logs, StringComparison.Ordinal);
            Assert.DoesNotContain("JsonException", logs, StringComparison.Ordinal);
            Assert.DoesNotContain("SecretBytesInvalid", logs, StringComparison.Ordinal);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
