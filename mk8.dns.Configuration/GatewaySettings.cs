using System.Globalization;

namespace Mk8.Dns.Configuration;

public sealed record GatewaySettings(string SocketPath, int HealthPort)
{
    public static GatewaySettings Parse(string[] args)
    {
        var values = HostArguments.Parse(args, ["--socket", "--health-port"]);
        var socket = HostArguments.AbsolutePath(values, "--socket");
        var portText = HostArguments.Required(values, "--health-port");
        if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1024 or > 65535)
            throw new ArgumentException("The loopback health port must be between 1024 and 65535.", nameof(args));
        return new GatewaySettings(socket, port);
    }
}
