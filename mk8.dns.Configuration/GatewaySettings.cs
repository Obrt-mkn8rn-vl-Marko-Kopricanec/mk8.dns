using System.Globalization;
using System.Net;

namespace Mk8.Dns.Configuration;

public sealed record GatewaySettings(string SocketPath, int HealthPort)
{
    public IPEndPoint? DnsEndpoint { get; init; }

    public static GatewaySettings Parse(string[] args)
    {
        var values = HostArguments.Parse(args, ["--socket", "--health-port", "--dns-address", "--dns-port"]);
        var socket = HostArguments.AbsolutePath(values, "--socket");
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
            dns = new IPEndPoint(address, dnsPort);
        }
        return new GatewaySettings(socket, port) { DnsEndpoint = dns };
    }
}
