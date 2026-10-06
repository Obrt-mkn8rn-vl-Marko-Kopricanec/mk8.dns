using System.Net;
using System.Text;
using Grpc.Core;
using Microsoft.AspNetCore.Http;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ManagementHttpTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Zone = Guid.NewGuid();
    private static readonly byte[] Credential = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
    private static readonly byte[] Origin = [7, 101, 120, 97, 109, 112, 108, 101, 0];

    [Fact]
    public async Task ClientUsesResourceRoutesHeaderCredentialsAndExplicitOperationIdentity()
    {
        List<ManagementRequest> admitted = [];
        var source = new HttpManagementStub((request, _) =>
        {
            Assert.Equal(Credential, request.Credential.ToArray());
            admitted.Add(request);
            return ValueTask.FromResult(Reply(request));
        });
        var fixture = new ManagementHttpFixture(source);
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.StartAsync().ConfigureAwait(true);
        using var client = new UnixManagementHttpClient(fixture.SocketPath);
        foreach (var action in new[] { "edit", "patch", "read", "status" })
        {
            var request = action is "status" ? Request("edit") with { Action = "status" } : Request(action);
            var reply = await client.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(request.OperationId, reply.OperationId);
            Assert.Equal(action is "read" ? "current" : "accepted", reply.State);
            Assert.Equal(action, admitted[^1].Action);
            Assert.Equal(Tenant, admitted[^1].TenantId);
            Assert.Equal(Zone, admitted[^1].ZoneId);
            Assert.Equal(request.ExpectedRevision, admitted[^1].ExpectedRevision);
            Assert.Equal(Origin, admitted[^1].Origin.ToArray());
        }
        Assert.Equal(4, source.Calls);
        await fixture.Api.DisposeAsync().ConfigureAwait(true);
        // The ingress-owned credential is wiped after each admitted exchange.
        Assert.All(admitted, request => Assert.All(request.Credential.ToArray(), value => Assert.Equal(0, value)));
    }

    [Theory]
    [InlineData("Credential", "\"AA==\"")]
    [InlineData("TenantId", "\"00000000-0000-0000-0000-000000000000\"")]
    [InlineData("Action", "\"status\"")]
    [InlineData("Origin", "\"AA==\"")]
    [InlineData("Records", "[null]")]
    public async Task UnknownDuplicateAndNullMembersCannotReachController(string name, string value)
    {
        var source = new HttpManagementStub((request, _) => ValueTask.FromResult(Reply(request)));
        var fixture = new ManagementHttpFixture(source);
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.StartAsync().ConfigureAwait(true);
        using var message = Mutation();
        var body = Body(Request("edit"));
        var json = Encoding.UTF8.GetString(ManagementHttpProtocol.WriteRequest(name is "Records" ? body with { Records = [null!] } : body));
        message.Content = new StringContent(name is "Records" ? json : json[..^1] + ",\"" + name + "\":" + value + "}", Encoding.UTF8, "application/json");
        using var response = await fixture.Client.SendAsync(message).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, source.Calls);
    }

    [Theory]
    [InlineData("missing", 401)]
    [InlineData("duplicate", 401)]
    [InlineData("noncanonical", 401)]
    [InlineData("origin", 403)]
    [InlineData("cookie", 403)]
    [InlineData("no-key", 400)]
    [InlineData("bad-key", 400)]
    [InlineData("extra-query", 400)]
    [InlineData("wrong-type", 415)]
    [InlineData("compressed", 415)]
    public async Task InvalidAuthenticationAndRequestEnvelopesNeverDispatch(string mode, int status)
    {
        var source = new HttpManagementStub((request, _) => ValueTask.FromResult(Reply(request)));
        var fixture = new ManagementHttpFixture(source);
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.StartAsync().ConfigureAwait(true);
        using var message = Mutation();
        switch (mode)
        {
            case "missing": message.Headers.Remove("Authorization"); break;
            case "duplicate": Assert.True(message.Headers.TryAddWithoutValidation("Authorization", ManagementHttpProtocol.EncodeCredential(Credential))); break;
            case "noncanonical": message.Headers.Remove("Authorization"); message.Headers.Add("Authorization", "Bearer " + new string('A', 42) + "B"); break;
            case "origin": message.Headers.Add("Origin", "http://localhost"); break;
            case "cookie": message.Headers.Add("Cookie", "credential=ignored"); break;
            case "no-key": message.Headers.Remove("Idempotency-Key"); break;
            case "bad-key": message.Headers.Remove("Idempotency-Key"); message.Headers.Add("Idempotency-Key", Guid.Empty.ToString("D")); break;
            case "extra-query": message.RequestUri = new Uri(message.RequestUri!.OriginalString + "?Credential=forbidden", UriKind.Relative); break;
            case "wrong-type": message.Content!.Headers.ContentType = new("text/plain"); break;
            case "compressed": message.Content!.Headers.ContentEncoding.Add("gzip"); break;
        }
        using var response = await fixture.Client.SendAsync(message).ConfigureAwait(true);
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        Assert.Equal(0, source.Calls);
    }

    [Fact]
    public async Task MissingExpectedRevisionAndOversizedChunkedBodyCannotDispatch()
    {
        var source = new HttpManagementStub((request, _) => ValueTask.FromResult(Reply(request)));
        var fixture = new ManagementHttpFixture(source);
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.StartAsync().ConfigureAwait(true);
        using var missing = Mutation();
        missing.Content = new ByteArrayContent(ManagementHttpProtocol.WriteRequest(Body(Request("edit")) with { ExpectedRevision = null }));
        missing.Content.Headers.ContentType = new("application/json");
        using var rejected = await fixture.Client.SendAsync(missing).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        using var oversized = Mutation();
        oversized.Content = new StreamContent(new MemoryStream(new byte[ManagementHttpProtocol.MaximumRequestBytes + 1], writable: false));
        oversized.Content.Headers.ContentType = new("application/json");
        oversized.Headers.TransferEncodingChunked = true;
        using var large = await fixture.Client.SendAsync(oversized).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, large.StatusCode);
        Assert.Equal(0, source.Calls);
    }

    [Theory]
    [InlineData(StatusCode.PermissionDenied, 403)]
    [InlineData(StatusCode.Unauthenticated, 401)]
    [InlineData(StatusCode.InvalidArgument, 400)]
    [InlineData(StatusCode.NotFound, 404)]
    [InlineData(StatusCode.FailedPrecondition, 409)]
    [InlineData(StatusCode.ResourceExhausted, 429)]
    [InlineData(StatusCode.Unavailable, 503)]
    [InlineData(StatusCode.DeadlineExceeded, 504)]
    [InlineData(StatusCode.Internal, 502)]
    public async Task ControllerFailuresHaveExplicitStatusWithoutInternalDetails(StatusCode code, int status)
    {
        var source = new HttpManagementStub((_, _) => throw new RpcException(new Status(code, "private database and credential details")));
        var fixture = new ManagementHttpFixture(source);
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.StartAsync().ConfigureAwait(true);
        using var message = Mutation();
        using var response = await fixture.Client.SendAsync(message).ConfigureAwait(true);
        Assert.Equal(status, (int)response.StatusCode);
        Assert.DoesNotContain("private", await response.Content.ReadAsStringAsync().ConfigureAwait(true), StringComparison.Ordinal);
        Assert.Equal(1, source.Calls);
    }

    [Theory]
    [InlineData("identity")]
    [InlineData("hash")]
    [InlineData("state")]
    [InlineData("null")]
    public async Task InvalidControllerReceiptsAreGatewayErrors(string mode)
    {
        var source = new HttpManagementStub((request, _) => ValueTask.FromResult(mode switch
        {
            "identity" => Reply(request) with { OperationId = Guid.NewGuid() },
            "hash" => Reply(request) with { ContentHash = "wrong" },
            "state" => Reply(request) with { State = "current" },
            _ => null!,
        }));
        var fixture = new ManagementHttpFixture(source);
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.StartAsync().ConfigureAwait(true);
        using var message = Mutation();
        using var response = await fixture.Client.SendAsync(message).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
    }

    [Fact]
    public async Task ClosingStopsAdmissionAndRetainsLeaseUntilIgnoredCancellationDrains()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var count = 0;
        var source = new HttpManagementStub(async (request, _) =>
        {
            if (Interlocked.Increment(ref count) == 4)
                entered.TrySetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(15), CancellationToken.None).ConfigureAwait(true);
            return Reply(request);
        });
        var fixture = new ManagementHttpFixture(source);
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.StartAsync().ConfigureAwait(true);
        using var first = Mutation();
        using var second = Mutation();
        using var third = Mutation();
        using var fourth = Mutation();
        var requests = new[] { first, second, third, fourth }.Select(message => fixture.Client.SendAsync(message)).ToArray();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
        try
        {
            using var busy = Mutation();
            using var rejected = await fixture.Client.SendAsync(busy).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
            var close = fixture.Api.DisposeAsync().AsTask();
            Assert.Same(close, fixture.Api.DisposeAsync().AsTask());
            Assert.False(close.IsCompleted);
            Assert.Throws<IOException>(() =>
            {
                using var competitor = new PrivateUnixSocket(fixture.SocketPath);
            });
            using var late = Mutation();
            using var closing = await fixture.Client.SendAsync(late).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, closing.StatusCode);
            Assert.Equal(4, source.Calls);
            release.TrySetResult();
            foreach (var pending in requests)
            {
                using var response = await pending.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
                Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            }
            await close.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
        }
        finally
        {
            release.TrySetResult();
        }
    }

    [Theory]
    [InlineData("redirect")]
    [InlineData("version")]
    [InlineData("mime")]
    [InlineData("size")]
    [InlineData("chunked-size")]
    public async Task ClientRejectsUntrustedResponseEnvelopes(string mode)
    {
        var source = new HttpManagementStub((request, _) => ValueTask.FromResult(Reply(request)));
        var fixture = new ManagementHttpFixture(source, async context =>
        {
            context.Response.Headers[ManagementHttpProtocol.VersionHeader] = mode is "version" ? "2" : "1";
            context.Response.ContentType = mode is "mime" ? "text/html" : "application/json";
            if (mode is "redirect")
            {
                context.Response.StatusCode = 302;
                context.Response.Headers.Location = "http://other-host/credential-leak";
                return;
            }
            var length = ManagementHttpProtocol.MaximumReplyBytes + 1;
            if (mode is "size")
                context.Response.ContentLength = length;
            await context.Response.Body.WriteAsync(new byte[length], context.RequestAborted).ConfigureAwait(true);
        });
        await using var lifetime = fixture.ConfigureAwait(true);
        await fixture.StartAsync().ConfigureAwait(true);
        using var client = new UnixManagementHttpClient(fixture.SocketPath);
        _ = await Assert.ThrowsAsync<HttpRequestException>(() => client.ExecuteAsync(Request("edit"), CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, source.Calls);
    }

    private static ManagementRequest Request(string action) => new(action, Tenant, Zone, Guid.NewGuid(), 0, Origin,
        action is "edit" ? [new(Origin, 1, 300, new byte[] { 192, 0, 2, 1 })] : Array.Empty<ZoneRecordData>(), Credential)
    {
        Changes = action is "patch" ? [new(Origin, 16, 300, [new byte[] { 1, 65 }], [], false)] : Array.Empty<RrsetChange>(),
        Selection = action is "read" ? [new(Origin, 1)] : Array.Empty<RrsetKey>(),
    };

    private static ManagementApiRequest Body(ManagementRequest request) => new(request.Origin) { ExpectedRevision = request.ExpectedRevision, Records = request.Records };
    private static ManagementReply Reply(ManagementRequest request) => new(request.OperationId, 1, 1, new string('a', 64), request.Action is "read" ? "current" : "accepted");
    private static HttpRequestMessage Mutation()
    {
        var request = Request("edit");
        var message = new HttpRequestMessage(HttpMethod.Put, new Uri($"/v1/tenants/{Tenant:D}/zones/{Zone:D}", UriKind.Relative))
        {
            Content = new ByteArrayContent(ManagementHttpProtocol.WriteRequest(Body(request))),
        };
        message.Content.Headers.ContentType = new("application/json");
        message.Headers.Add("Authorization", ManagementHttpProtocol.EncodeCredential(Credential));
        message.Headers.Add("Idempotency-Key", request.OperationId.ToString("D"));
        return message;
    }
}
