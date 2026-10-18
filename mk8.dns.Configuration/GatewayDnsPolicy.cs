using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mk8.Dns.Configuration;

// Optional tightening of the existing listener ceilings, from the same snapshot.
public sealed class GatewayDnsPolicy
{
    public int TcpConnections { get; }
    public int MessagesPerConnection { get; }
    public int FrameTimeoutMilliseconds { get; }

    private GatewayDnsPolicy(int connections, int messages, int timeout)
    {
        TcpConnections = connections;
        MessagesPerConnection = messages;
        FrameTimeoutMilliseconds = timeout;
    }

    public static GatewayDnsPolicy FromSecrets(DnsServiceSecrets secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        if (!secrets.Contains("DnsPolicy")) return new GatewayDnsPolicy(16, 100, 2000);
        Input? input = null;
        try { input = JsonSerializer.Deserialize<Input>(secrets.JsonText("DnsPolicy")); }
        catch (JsonException) { /* No protected property names or values in diagnostics. */ }
        if (input is null) throw new InvalidDataException("SecretDnsPolicyInvalid");
        if (input.TcpConnections is < 1 or > 16 || input.MessagesPerConnection is < 1 or > 100
            || input.FrameTimeoutMilliseconds is < 1 or > 2000)
        {
            throw new InvalidDataException("SecretDnsPolicyBounds");
        }
        return new GatewayDnsPolicy(input.TcpConnections, input.MessagesPerConnection, input.FrameTimeoutMilliseconds);
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record Input(
        [property: JsonRequired] int TcpConnections,
        [property: JsonRequired] int MessagesPerConnection,
        [property: JsonRequired] int FrameTimeoutMilliseconds);
}
