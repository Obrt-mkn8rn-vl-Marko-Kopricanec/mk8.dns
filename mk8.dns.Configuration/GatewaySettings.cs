using System.Globalization;
using System.Net;

namespace Mk8.Dns.Configuration;

public sealed record GatewaySettings(string SocketPath, int HealthPort)
{
    public IPEndPoint? DnsEndpoint { get; init; }
    public GatewayRole Role { get; init; }
    public string? ManagementSocketPath { get; init; }

    public static GatewaySettings Parse(string[] args)
    {
        var values = HostArguments.Parse(args, ["--socket", "--health-port", "--dns-address", "--dns-port", "--role", "--management-socket"]);
        var socket = HostArguments.AbsolutePath(values, "--socket");
        var role = values.GetValueOrDefault("--role", "query");
        if (role is "management")
        {
            var management = HostArguments.AbsolutePath(values, "--management-socket");
            if (string.Equals(socket, management, StringComparison.Ordinal) || values.ContainsKey("--health-port") || values.ContainsKey("--dns-address") || values.ContainsKey("--dns-port"))
                throw new ArgumentException("Management requires a separate private socket and no network listener arguments.", nameof(args));
            return new GatewaySettings(socket, 0) { Role = GatewayRole.Management, ManagementSocketPath = management };
        }
        if (role is not "query" || values.ContainsKey("--management-socket"))
            throw new ArgumentException("Unknown or mixed Gateway role.", nameof(args));
        var portText = HostArguments.Required(values, "--health-port");
        if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1024 or > 65535)
            throw new ArgumentException("The loopback health port must be between 1024 and 65535.", nameof(args));
        IPEndPoint? dns = null;
        var hasAddress = values.TryGetValue("--dns-address", out var addressText);
        var hasPort = values.TryGetValue("--dns-port", out var dnsPortText);
        if (hasAddress != hasPort)
            throw new ArgumentException("DNS address and port must be configured together.", nameof(args));
        if (hasAddress)
        {
            if (!IPAddress.TryParse(addressText, out var address) || !int.TryParse(dnsPortText, NumberStyles.None, CultureInfo.InvariantCulture, out var dnsPort) || dnsPort is < 1 or > 65535)
                throw new ArgumentException("DNS requires an IP literal and a port in 1..65535.", nameof(args));
            if (address.GetAddressBytes().AsSpan().IndexOfAnyExcept((byte)0) < 0 || (address.IsIPv4MappedToIPv6 && address.MapToIPv4().Equals(IPAddress.Any)))
                throw new ArgumentException("DNS requires a specific bind address to preserve UDP reply source identity.", nameof(args));
            if (dnsPort == port && address.Equals(IPAddress.Loopback))
                throw new ArgumentException("DNS TCP and loopback health require distinct bind endpoints.", nameof(args));
            dns = new IPEndPoint(address, dnsPort);
        }
        return new GatewaySettings(socket, port) { DnsEndpoint = dns };
    }
}
