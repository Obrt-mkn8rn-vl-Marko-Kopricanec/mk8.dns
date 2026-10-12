using System.Net;
using System.Text.Json;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Configuration;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.Application;

// No deployment defaults. Parsing and all policy validation precede key/store I/O.
internal sealed partial record RecursiveStartupConfiguration(string StoreDirectory, string KeyFile, Guid StoreIdentity,
    DnsName Origin, long MinimumRevision, bool Retention, IPEndPoint Binding, DnsServerEndpoint[] Roots,
    DnsServerEndpoint RefreshServer, DnssecClientAccessPolicy Access, DnssecClientNetwork[] Egress,
    ushort AuthorityPort, DnssecWorkPolicy Work, int MaximumRequests, int UdpWorkers,
    int MaximumTcpConnections, int MaximumTcpMessages, TimeSpan UpstreamTimeout, DnssecAnchorPollingPolicy? RefreshPolicy)
{
    internal static RecursiveStartupConfiguration Load(string path) => Load(path, authenticatedRefresh: false);

    internal static RecursiveStartupConfiguration Load(string path, bool authenticatedRefresh)
    {
        using var document = JsonDocument.Parse(PrivateFile.Read(path, 65536), new JsonDocumentOptions { MaxDepth = 8 });
        var values = document.RootElement;
        string[] fields = ["storeDirectory", "keyFile", "storeIdentity", "origin", "minimumRevision", "retention",
            "listen", "roots", "refreshServer", "clientNetworks", "allowAuthenticatedData", "egressNetworks", "authorityPort",
            "maximumRequests", "udpWorkers", "maximumTcpConnections", "maximumTcpMessages", "maximumWorkers",
            "maximumWaiters", "resolutionTimeoutMilliseconds", "upstreamTimeoutMilliseconds"];
        RequireFields(values, authenticatedRefresh ? [.. fields, "refreshPolicy"] : fields);
        var refreshPolicy = authenticatedRefresh ? Refresh(values.GetProperty("refreshPolicy")) : null;
        var roots = values.GetProperty("roots").EnumerateArray().Select(Endpoint).Take(17).ToArray();
        if (roots.Length is < 1 or > 16 || roots.Distinct().Take(roots.Length + 1).Count() != roots.Length)
            throw new InvalidDataException("One to sixteen distinct root endpoints are required.");
        var port = (ushort)Number(values, "authorityPort", 1, ushort.MaxValue);
        var egress = Networks(values.GetProperty("egressNetworks"));
        var server = Endpoint(values.GetProperty("refreshServer"));
        if (roots.Append(server).Any(endpoint => !Permits(endpoint, egress, port)))
            throw new InvalidDataException("Roots and refresh endpoint must be covered by the explicit egress policy and authority port.");
        var listen = values.GetProperty("listen");
        RequireFields(listen, ["address", "port"]);
        var address = Address(listen.GetProperty("address").GetString());
        // The native listener requires a specific address, not a wildcard or mapped identity.
        _ = new DnsServerEndpoint(address.GetAddressBytes());
        var identity = Guid.ParseExact(Text(values, "storeIdentity"), "N");
        if (identity == Guid.Empty) throw new InvalidDataException("Store identity must be nonempty.");
        var retention = values.GetProperty("retention").GetBoolean();
        var minimum = Number(values, "minimumRevision", 1, retention ? long.MaxValue : FileAnchorCheckpointStore.MaximumGenerations);
        return new RecursiveStartupConfiguration(AbsolutePath(values, "storeDirectory"), AbsolutePath(values, "keyFile"),
            identity, DnsName.Parse(Text(values, "origin")), minimum,
            retention, new IPEndPoint(address, (int)Number(listen, "port", 1, ushort.MaxValue)),
            roots, server, new DnssecClientAccessPolicy(Networks(values.GetProperty("clientNetworks")),
                values.GetProperty("allowAuthenticatedData").GetBoolean()), egress, port,
            new DnssecWorkPolicy((int)Number(values, "maximumWorkers", 1, 256), (int)Number(values, "maximumWaiters", 1, 65536),
                TimeSpan.FromMilliseconds(Number(values, "resolutionTimeoutMilliseconds", 50, 120000))),
            (int)Number(values, "maximumRequests", 1, 256), (int)Number(values, "udpWorkers", 1, 16),
            (int)Number(values, "maximumTcpConnections", 1, 64), (int)Number(values, "maximumTcpMessages", 1, 256),
            TimeSpan.FromMilliseconds(Number(values, "upstreamTimeoutMilliseconds", 50, 10000)), refreshPolicy);
    }

    internal static bool Permits(DnsServerEndpoint endpoint, DnssecClientNetwork[] networks, ushort port)
        => endpoint.Port == port && networks.Any(network => network.Contains(endpoint.GetAddress()));

    private static DnsServerEndpoint Endpoint(JsonElement value)
    {
        RequireFields(value, ["address", "port"]);
        return new DnsServerEndpoint(Address(Text(value, "address")).GetAddressBytes(), (ushort)Number(value, "port", 1, ushort.MaxValue));
    }

    private static IPAddress Address(string? text)
    {
        if (text?.Contains('%', StringComparison.Ordinal) != false || !IPAddress.TryParse(text, out var address)
            || address.IsIPv4MappedToIPv6)
        {
            throw new InvalidDataException("Supply an unmapped numeric address without an interface scope.");
        }
        return address;
    }

    private static DnssecClientNetwork[] Networks(JsonElement value)
    {
        var entries = value.EnumerateArray().Take(65).ToArray();
        if (entries.Length > 64) throw new InvalidDataException("At most sixty-four explicit networks are allowed.");
        var networks = entries.Select(entry =>
        {
            RequireFields(entry, ["address", "prefix"]);
            var bytes = Address(Text(entry, "address")).GetAddressBytes();
            return new DnssecClientNetwork(bytes, (int)Number(entry, "prefix", 0, bytes.Length * 8));
        }).ToArray();
        _ = new DnssecClientAccessPolicy(networks); // Also reject duplicate canonical grants.
        return networks;
    }

    private static void RequireFields(JsonElement value, string[] names)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!names.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
                throw new InvalidDataException("Unknown or duplicate recursive configuration field.");
        }
        if (seen.Count != names.Length) throw new InvalidDataException("Every recursive configuration field is required.");
    }

    private static string Text(JsonElement value, string name)
        => value.GetProperty(name).GetString() ?? throw new InvalidDataException("Configuration text cannot be null.");

    private static string AbsolutePath(JsonElement value, string name)
    {
        var path = Text(value, name);
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("Configuration paths must be absolute.");
        return Path.GetFullPath(path);
    }

    private static long Number(JsonElement value, string name, long minimum, long maximum)
    {
        var number = value.GetProperty(name).GetInt64();
        if (number < minimum || number > maximum) throw new InvalidDataException("Recursive configuration bound is invalid.");
        return number;
    }
}
