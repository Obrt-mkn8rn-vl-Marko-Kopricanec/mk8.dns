using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

public sealed class UnixManagementHttpClient : IZoneManagement, IDisposable
{
    private readonly HttpClient client;
    private readonly SocketsHttpHandler handler;

    public UnixManagementHttpClient(string socketPath)
    {
        PrivateUnixSocket.ValidatePath(socketPath);
        var endpoint = new UnixDomainSocketEndPoint(socketPath);
        handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
            ConnectTimeout = TimeSpan.FromSeconds(2),
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            MaxConnectionsPerServer = 4,
            MaxResponseHeadersLength = 8,
        };
        try
        {
            client = new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri("http://localhost"), Timeout = Timeout.InfiniteTimeSpan };
        }
        catch
        {
            handler.Dispose();
            throw;
        }
    }

    public async ValueTask<ManagementReply> ExecuteAsync(ManagementRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var body = new ManagementApiRequest(request.Origin)
        {
            ExpectedRevision = request.Action is "edit" or "patch" or "import" ? request.ExpectedRevision : null,
            Records = request.Action is "status" ? Array.Empty<ZoneRecordData>() : request.Records,
            Changes = request.Action is "status" ? Array.Empty<RrsetChange>() : request.Changes,
            Selection = request.Action is "status" ? Array.Empty<RrsetKey>() : request.Selection,
            ZoneFile = request.Action is "status" ? null : request.ZoneFile,
        };
        _ = ManagementHttpProtocol.BindRequest(body, request.Action, request.TenantId, request.ZoneId, request.OperationId, request.Credential);
        var prefix = "/v2/tenants/" + request.TenantId.ToString("D") + "/zones/" + request.ZoneId.ToString("D");
        var method = request.Action switch { "edit" => HttpMethod.Put, "patch" => HttpMethod.Patch, "read" or "import" or "export" => HttpMethod.Post, "status" => HttpMethod.Get, _ => throw new ArgumentException("Unknown management action.", nameof(request)) };
        var path = request.Action switch { "edit" => prefix, "patch" => prefix + "/rrsets", "read" => prefix + "/rrsets/read", "import" => prefix + "/zonefile/import", "export" => prefix + "/zonefile/export", _ => ManagementHttpProtocol.OperationPath(request.TenantId, request.ZoneId, request.OperationId, request.Origin) };
        using var message = new HttpRequestMessage(method, new Uri(path, UriKind.Relative)) { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
        message.Headers.Add("Authorization", ManagementHttpProtocol.EncodeCredential(request.Credential));
        if (request.Action is "edit" or "patch" or "import")
            message.Headers.Add("Idempotency-Key", request.OperationId.ToString("D"));
        if (request.Action is "read" or "export")
            message.Headers.Add("X-Mk8-Request-Id", request.OperationId.ToString("D"));
        if (request.Action is not "status")
        {
            message.Content = new ByteArrayContent(ManagementHttpProtocol.WriteRequest(body));
            message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        if (!response.Headers.TryGetValues(ManagementHttpProtocol.VersionHeader, out var versions) || !versions.SequenceEqual([ManagementHttpProtocol.Version], StringComparer.Ordinal))
            throw new HttpRequestException("Unsupported management API version.");
        if (response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Accepted))
            throw new HttpRequestException("Management Gateway rejected the request.", inner: null, response.StatusCode);
        if (response.Content.Headers.ContentLength > ManagementHttpProtocol.MaximumReplyBytes || !string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new HttpRequestException("Invalid management reply envelope.");
        var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            using var data = new MemoryStream();
            var buffer = new byte[8192];
            int count;
            while ((count = await stream.ReadAsync(buffer.AsMemory(), deadline.Token).ConfigureAwait(false)) != 0)
            {
                if (data.Length + count > ManagementHttpProtocol.MaximumReplyBytes)
                    throw new HttpRequestException("Management reply exceeds its bound.");
                await data.WriteAsync(buffer.AsMemory(0, count), deadline.Token).ConfigureAwait(false);
            }
            var reply = ManagementHttpProtocol.ReadReply(data.ToArray());
            ManagementHttpProtocol.VerifyReply(reply, request.Action, request.OperationId);
            var expectedStatus = request.Action is "edit" or "patch" or "import" && reply.State is "accepted" ? HttpStatusCode.Accepted : HttpStatusCode.OK;
            if (response.StatusCode != expectedStatus)
                throw new HttpRequestException("Invalid management reply status.");
            return reply;
        }
    }

    public void Dispose()
    {
        client.Dispose();
        handler.Dispose();
    }
}
