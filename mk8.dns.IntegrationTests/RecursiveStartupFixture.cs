using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.IntegrationTests;

internal sealed class RecursiveStartupFixture : IDisposable
{
    private readonly AnchorStorageDirectory directory = new();
    private readonly byte[] secret = RandomNumberGenerator.GetBytes(32);
    internal Guid Identity { get; } = Guid.NewGuid();
    internal string StorePath => Path.Combine(directory.Path, "anchors");
    internal string ConfigurationPath => Path.Combine(directory.Path, "recursive.json");
    internal JsonObject Configuration { get; }

    internal RecursiveStartupFixture(int port, int upstreamPort, DnsRecord? anchor = null, bool retention = false)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        try
        {
            var keyPath = Path.Combine(directory.Path, "key");
            File.WriteAllBytes(keyPath, secret);
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            using var signing = EcdsaP256DnssecSigningKey.Create();
            var origin = DnsName.Parse("example.");
            var initial = new DnssecTrustAnchorTracker(origin, [anchor ?? DnssecKeys.CreateDnskey(origin, 3600, signing.GetPublicKey())],
                new DnssecSignatureVerifier());
            using var store = retention ? FileAnchorCheckpointStore.CreateWithRetention(StorePath, Identity, initial, secret)
                : FileAnchorCheckpointStore.Create(StorePath, Identity, initial, secret);
            Configuration = new JsonObject
            {
                ["storeDirectory"] = StorePath,
                ["keyFile"] = keyPath,
                ["storeIdentity"] = Identity.ToString("N"),
                ["origin"] = "example.",
                ["minimumRevision"] = 1,
                ["retention"] = retention,
                ["listen"] = Endpoint(port),
                ["roots"] = new JsonArray(Endpoint(upstreamPort)),
                ["refreshServer"] = Endpoint(upstreamPort),
                ["clientNetworks"] = new JsonArray(Network()),
                ["allowAuthenticatedData"] = true,
                ["egressNetworks"] = new JsonArray(Network()),
                ["authorityPort"] = upstreamPort,
                ["maximumRequests"] = 2,
                ["udpWorkers"] = 2,
                ["maximumTcpConnections"] = 2,
                ["maximumTcpMessages"] = 2,
                ["maximumWorkers"] = 2,
                ["maximumWaiters"] = 4,
                ["resolutionTimeoutMilliseconds"] = 3000,
                ["upstreamTimeoutMilliseconds"] = 1000,
            };
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal void Write(string? text = null)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        File.WriteAllText(ConfigurationPath, text ?? Configuration.ToJsonString());
        File.SetUnixFileMode(ConfigurationPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    internal void AssertStoreReopens(bool retention)
    {
        using var opened = retention
            ? FileAnchorCheckpointStore.OpenWithRetention(StorePath, Identity, DnsName.Parse("example."), secret, 1, new DnssecSignatureVerifier())
            : FileAnchorCheckpointStore.Open(StorePath, Identity, DnsName.Parse("example."), secret, 1, new DnssecSignatureVerifier());
        Xunit.Assert.Equal(1, opened.Revision);
    }

    private static JsonObject Endpoint(int port) => new() { ["address"] = "127.0.0.1", ["port"] = port };
    private static JsonObject Network() => new() { ["address"] = "127.0.0.1", ["prefix"] = 32 };

    internal static int VacantPair()
    {
        var (udp, tcp) = DnssecUpstreamFixture.BindPair(ipv6: false);
        using var udpLifetime = udp; using var tcpLifetime = tcp;
        return ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(secret);
        directory.Dispose();
    }
}
