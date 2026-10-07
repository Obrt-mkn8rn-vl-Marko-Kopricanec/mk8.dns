using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Grpc.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;

namespace Mk8.Dns.Presentation;

public sealed class ManagementHttpApi(IZoneManagement source) : IAsyncDisposable
{
    private const int MaximumInflight = 4;
    private readonly Lock sync = new();
    private readonly CancellationTokenSource closing = new();
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? closeTask;
    private bool closed;
    private bool mapped;
    private int active;

    public void Map(IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(source);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(closed, this);
            if (mapped)
                throw new InvalidOperationException("Management routes are already mapped.");
            mapped = true;
        }
        const string zone = "/v2/tenants/{tenantId:guid}/zones/{zoneId:guid}";
        endpoints.MapPut(zone, (HttpContext context) => HandleAsync(context, "edit"));
        endpoints.MapPatch(zone + "/rrsets", (HttpContext context) => HandleAsync(context, "patch"));
        endpoints.MapPost(zone + "/rrsets/read", (HttpContext context) => HandleAsync(context, "read"));
        endpoints.MapPost(zone + "/zonefile/import", (HttpContext context) => HandleAsync(context, "import"));
        endpoints.MapPost(zone + "/zonefile/export", (HttpContext context) => HandleAsync(context, "export"));
        endpoints.MapGet(zone + "/operations/{operationId:guid}", (HttpContext context) => HandleAsync(context, "status"));
    }

    public ValueTask DisposeAsync()
    {
        lock (sync)
        {
            if (closeTask is not null)
                return new ValueTask(closeTask);
            closed = true;
            if (active == 0)
                drained.TrySetResult();
            closeTask = FinishCloseAsync();
            return new ValueTask(closeTask);
        }
    }

    private async Task FinishCloseAsync()
    {
        try
        {
            await closing.CancelAsync().ConfigureAwait(false);
        }
        finally
        {
            await drained.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            closing.Dispose();
        }
    }

    private async Task HandleAsync(HttpContext context, string action)
    {
        context.Response.Headers[ManagementHttpProtocol.VersionHeader] = ManagementHttpProtocol.Version;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        CancellationToken closeToken;
        int rejection;
        lock (sync)
        {
            rejection = closed ? StatusCodes.Status503ServiceUnavailable : active == MaximumInflight ? StatusCodes.Status429TooManyRequests : 0;
            closeToken = rejection == 0 ? closing.Token : CancellationToken.None;
            if (rejection == 0)
                active++;
        }
        if (rejection != 0)
        {
            await FailAsync(context, rejection, rejection == 429 ? "busy" : "closing").ConfigureAwait(false);
            return;
        }
        byte[]? credential = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, closeToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            credential = await AuthenticateAsync(context).ConfigureAwait(false);
            if (credential is not null)
                await DispatchAsync(context, action, credential, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or JsonException)
        {
            await FailAsync(context, 400, "invalid_request").ConfigureAwait(false);
        }
        catch (BadHttpRequestException exception)
        {
            await FailAsync(context, exception.StatusCode == 413 ? 413 : 400, exception.StatusCode == 413 ? "body_too_large" : "invalid_request").ConfigureAwait(false);
        }
        catch (RpcException exception)
        {
            var status = RpcStatus(exception.StatusCode, closeToken.IsCancellationRequested);
            await FailAsync(context, status, status is 400 or 403 or 404 or 409 ? "controller_rejected" : "controller_unavailable").ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            await FailAsync(context, closeToken.IsCancellationRequested ? 503 : 504, "request_cancelled").ConfigureAwait(false);
        }
        catch (InvalidDataException)
        {
            await FailAsync(context, 502, "invalid_controller_reply").ConfigureAwait(false);
        }
        finally
        {
            if (credential is not null)
                CryptographicOperations.ZeroMemory(credential);
            lock (sync)
            {
                active--;
                if (closed && active == 0)
                    drained.TrySetResult();
            }
        }
    }

    private static async Task<byte[]?> AuthenticateAsync(HttpContext context)
    {
        if (context.Request.Headers.ContainsKey("Origin") || context.Request.Headers.ContainsKey("Cookie"))
        {
            await FailAsync(context, 403, "browser_credentials_forbidden").ConfigureAwait(false);
            return null;
        }
        var authorization = context.Request.Headers.Authorization;
        if (authorization.Count != 1)
        {
            await FailAsync(context, 401, "credential_required").ConfigureAwait(false);
            return null;
        }
        try
        {
            return ManagementHttpProtocol.DecodeCredential(authorization[0]!);
        }
        catch (FormatException)
        {
            await FailAsync(context, 401, "invalid_credential").ConfigureAwait(false);
            return null;
        }
    }

    private async Task DispatchAsync(HttpContext context, string action, byte[] credential, CancellationToken token)
    {
        var tenant = RouteId(context, "tenantId");
        var zone = RouteId(context, "zoneId");
        var operation = action is "status" ? RouteId(context, "operationId") : RequestId(context, action);
        var body = await ReadRequestAsync(context, action, token).ConfigureAwait(false);
        if (body is null)
            return;
        var request = ManagementHttpProtocol.BindRequest(body, action, tenant, zone, operation, credential);
        token.ThrowIfCancellationRequested();
        ManagementReply reply;
        byte[] response;
        try
        {
            reply = await source.ExecuteAsync(request, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            ManagementHttpProtocol.VerifyReply(reply, action, operation);
            response = ManagementHttpProtocol.WriteReply(reply);
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or FormatException)
        {
            throw new InvalidDataException("Invalid controller reply.", exception);
        }
        context.Response.StatusCode = action is "edit" or "patch" or "import" && reply.State is "accepted" ? 202 : 200;
        context.Response.ContentType = "application/json; charset=utf-8";
        if (action is "edit" or "patch" or "import")
            context.Response.Headers.Location = ManagementHttpProtocol.OperationPath(tenant, zone, operation, body.Origin);
        await context.Response.Body.WriteAsync(response, token).ConfigureAwait(false);
    }

    private static async Task<ManagementApiRequest?> ReadRequestAsync(HttpContext context, string action, CancellationToken token)
    {
        if (action is "status")
        {
            if (context.Request.Query.Count != 1 || !context.Request.Query.TryGetValue("origin", out var origins) || origins.Count != 1
                || context.Request.ContentLength is not (null or 0) || context.Request.Headers.ContainsKey("Transfer-Encoding")
                || context.Request.Headers.ContainsKey("Idempotency-Key") || context.Request.Headers.ContainsKey("X-Mk8-Request-Id"))
                throw new ArgumentException("Invalid operation query.", nameof(context));
            return new ManagementApiRequest(ManagementHttpProtocol.DecodeOrigin(origins[0]!));
        }
        if (context.Request.Query.Count != 0)
            throw new ArgumentException("Unknown query parameter.", nameof(context));
        if (!IsJson(context.Request))
        {
            await FailAsync(context, 415, "json_required").ConfigureAwait(false);
            return null;
        }
        var bytes = await ReadBodyAsync(context, token).ConfigureAwait(false);
        if (bytes is null)
        {
            await FailAsync(context, 413, "body_too_large").ConfigureAwait(false);
            return null;
        }
        return ManagementHttpProtocol.ReadRequest(bytes);
    }

    private static int RpcStatus(StatusCode code, bool closed) => code switch
    {
        StatusCode.PermissionDenied => 403,
        StatusCode.Unauthenticated => 401,
        StatusCode.InvalidArgument => 400,
        StatusCode.NotFound => 404,
        StatusCode.FailedPrecondition => 409,
        StatusCode.ResourceExhausted => 429,
        StatusCode.Unavailable or StatusCode.Unimplemented => 503,
        StatusCode.DeadlineExceeded => 504,
        StatusCode.Cancelled => closed ? 503 : 504,
        _ => 502,
    };

    private static Guid RouteId(HttpContext context, string name)
    {
        if (!Guid.TryParse(Convert.ToString(context.Request.RouteValues[name], CultureInfo.InvariantCulture), out var value) || value == Guid.Empty)
            throw new ArgumentException("Invalid resource identity.", nameof(context));
        return value;
    }

    private static Guid RequestId(HttpContext context, string action)
    {
        var mutation = action is "edit" or "patch" or "import";
        var key = mutation ? "Idempotency-Key" : "X-Mk8-Request-Id";
        if (context.Request.Headers.ContainsKey(mutation ? "X-Mk8-Request-Id" : "Idempotency-Key"))
            throw new ArgumentException("Unexpected request identity header.", nameof(context));
        if (!context.Request.Headers.TryGetValue(key, out var values) && !mutation)
            return Guid.NewGuid();
        if (values.Count != 1 || !Guid.TryParseExact(values[0], "D", out var value) || value == Guid.Empty)
            throw new ArgumentException("Invalid request identity header.", nameof(context));
        return value;
    }

    private static bool IsJson(HttpRequest request)
    {
        if (request.Headers.ContainsKey("Content-Encoding"))
            return false;
        return request.Headers.ContentType.Count == 1 && MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
            && string.Equals(contentType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)
            && (contentType.CharSet is null || string.Equals(contentType.CharSet.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<byte[]?> ReadBodyAsync(HttpContext context, CancellationToken token)
    {
        if (context.Request.ContentLength > ManagementHttpProtocol.MaximumRequestBytes)
            return null;
        using var data = new MemoryStream();
        var buffer = new byte[8192];
        int count;
        while ((count = await context.Request.Body.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false)) != 0)
        {
            if (data.Length + count > ManagementHttpProtocol.MaximumRequestBytes)
                return null;
            await data.WriteAsync(buffer.AsMemory(0, count), token).ConfigureAwait(false);
        }
        return data.ToArray();
    }

    private static async Task FailAsync(HttpContext context, int status, string code)
    {
        if (context.RequestAborted.IsCancellationRequested || context.Response.HasStarted)
        {
            context.Abort();
            return;
        }
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        if (status == 401)
            context.Response.Headers.WWWAuthenticate = "Bearer";
        if (status is 429 or 503)
            context.Response.Headers.RetryAfter = "1";
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            await context.Response.Body.WriteAsync(ManagementHttpProtocol.WriteError(code), deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            context.Abort();
        }
    }
}
