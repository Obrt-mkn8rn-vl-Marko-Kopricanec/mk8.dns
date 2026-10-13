using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mk8.Dns.IntegrationTests;

// An owned Unix backlog observes attempted database contact without running a
// PostgreSQL server, accepting a connection or executing any database command.
internal sealed class ControllerPreflightFixture : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "m8-p-" + Guid.NewGuid().ToString("N"));
    private readonly Socket database = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    private bool settled = true;
    internal string State => Path.Combine(root, "state");
    internal string Runtime => Path.Combine(root, "runtime");
    internal bool DatabaseContacted => database.Poll(0, SelectMode.SelectRead);

    internal ControllerPreflightFixture(string fault)
    {
        try
        {
            Directory.CreateDirectory(root);
            var directory = Path.Combine(root, "database");
            Directory.CreateDirectory(directory);
            database.Bind(new UnixDomainSocketEndPoint(Path.Combine(directory, ".s.PGSQL.5432")));
            database.Listen(1);
            WriteInputs(fault, directory);
        }
        catch
        {
            database.Dispose();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
            throw;
        }
    }

    private void WriteInputs(string fault, string directory)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = Path.Combine(root, "publication.pem");
        File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
        var host = fault switch
        {
            "database-name" => "fixture.invalid",
            "database-relative" => "relative-fixture-database",
            "database-comma" => directory + "," + Path.Combine(root, "other-database"),
            _ => directory,
        };
        File.WriteAllText(Path.Combine(root, "database.txt"), "Host=" + host
            + ";Port=5432;Database=fixture;Username=fixture;Pooling=false;Timeout=1;CommandTimeout=1");
        var publication = fault switch
        {
            "publication-ascii" => Path.Combine(root, new string('x', 101)),
            "publication-utf8" => Path.Combine(root, new string('\u00e9', 40)),
            _ => Path.Combine(Runtime, "publication.sock"),
        };
        if (fault is "publication-utf8" && (publication.Length > 100 || Encoding.UTF8.GetByteCount(publication) <= 100))
            throw new InvalidDataException("The UTF-8 fixture must isolate bytes from character count.");
        var zone = Guid.NewGuid();
        var input = new
        {
            Epoch = Guid.NewGuid(),
            TargetNode = "fixture",
            KeyFile = keyPath,
            ConnectionStringFile = Path.Combine(root, "database.txt"),
            PublicationSocket = publication,
            Zones = new[] { new { ZoneId = zone, Origin = "example." } },
            Grants = new[] { new { TenantId = Guid.NewGuid(), ZoneId = zone, Origin = "example.", Actor = "fixture",
                Expires = DateTimeOffset.UtcNow.AddMinutes(1), CredentialHash = SHA256.HashData("controlled-fixture"u8), }, },
        };
        File.WriteAllText(Path.Combine(root, "control.json"), JsonSerializer.Serialize(input));
    }

    internal HostProcess Start()
    {
        var host = new HostProcess("mk8.dns.Application", ["--socket", Path.Combine(Runtime, "application.sock"),
            "--state", State, "--node", "fixture", "--role", "controller", "--control", Path.Combine(root, "control.json")], 0);
        settled = false;
        return host;
    }

    internal void ObserveSettledChild() => settled = true;

    public void Dispose()
    {
        database.Dispose();
        // A failed child/log join retains its inputs rather than deleting them
        // while an uncertain owner might still use them. The test remains failed.
        if (settled) Directory.Delete(root, recursive: true);
    }
}
