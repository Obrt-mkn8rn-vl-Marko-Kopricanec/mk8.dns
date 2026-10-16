using System.Net;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ManagementHttpCleanupTests
{
    [Fact]
    public async Task CallbackFailureStillDrainsTheApiAndRetiresEveryHttpFixtureOwner()
    {
        var source = new FaultingController();
        await using var sourceLifetime = source.ConfigureAwait(true);
        var fixture = new ManagementHttpFixture(source);
        var path = fixture.SocketPath;
        Task? closing = null;
        Task<HttpResponseMessage>? request = null;
        using var message = Request();
        var body = await Record.ExceptionAsync(async () =>
        {
            await fixture.StartAsync().ConfigureAwait(true);
            request = fixture.Client.SendAsync(message, CancellationToken.None);
            await source.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            closing = fixture.DisposeAsync().AsTask();
            await source.CallbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(10), TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.False(closing.IsCompleted);
            Assert.Throws<IOException>(() => { using var competitor = new PrivateUnixSocket(path); });
            source.Release.TrySetResult();
            var error = await Assert.ThrowsAsync<AggregateException>(() => closing.WaitAsync(TimeSpan.FromSeconds(10), TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.Same(source.Failure, Assert.Single(error.Flatten().InnerExceptions));
            Assert.False(Directory.Exists(Path.GetDirectoryName(path)));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => fixture.Client.GetAsync(new Uri("http://localhost"), CancellationToken.None)).ConfigureAwait(true);
        }).ConfigureAwait(true);
        source.Release.TrySetResult();
        var actualClose = fixture.DisposeAsync().AsTask();
        await TestTaskSettlement.RunAsync(() =>
        {
            if (body is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(body).Throw();
            return Task.CompletedTask;
        }, () => TestTaskSettlement.AllAsync(
            () => TestTaskSettlement.ObserveAsync(actualClose.WaitAsync(CancellationToken.None), error => error is AggregateException aggregate
                && aggregate.Flatten().InnerExceptions.All(leaf => ReferenceEquals(leaf, source.Failure))),
            async () => { if (request is not null) await SettleReplyAsync(request.WaitAsync(CancellationToken.None)).ConfigureAwait(true); })).ConfigureAwait(true);
    }

    private static async Task SettleReplyAsync(Task<HttpResponseMessage> request)
    {
        try { using var response = await request.WaitAsync(CancellationToken.None).ConfigureAwait(true); Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode); }
        catch (HttpRequestException) { /* Owned host closure may abort the response. */ }
        catch (OperationCanceledException) { /* HttpClient is also retired by the fixture. */ }
    }

    private static HttpRequestMessage Request()
    {
        var message = new HttpRequestMessage(HttpMethod.Put, new Uri($"/v2/tenants/{Guid.NewGuid():D}/zones/{Guid.NewGuid():D}", UriKind.Relative));
        message.Headers.Add("Authorization", ManagementHttpProtocol.EncodeCredential(new byte[32]));
        message.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString("D"));
        message.Content = new ByteArrayContent(ManagementHttpProtocol.WriteRequest(new ManagementApiRequest(new byte[] { 0 }) { ExpectedRevision = 0, Records = [new ZoneRecordData(new byte[] { 0 }, 1, 300, new byte[] { 192, 0, 2, 1 })] }));
        message.Content.Headers.ContentType = new("application/json"); return message;
    }

    private sealed class FaultingController : IZoneManagement, IAsyncDisposable
    {
        private CancellationTokenRegistration registration;
        internal IOException Failure { get; } = new("Controlled controller cancellation callback failure.");
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource CallbackEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<ManagementReply> ExecuteAsync(ManagementRequest request, CancellationToken token)
        {
            registration = token.Register(() => { CallbackEntered.TrySetResult(); throw Failure; });
            Entered.TrySetResult();
            await Release.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            return new ManagementReply(request.OperationId, 1, 1, new string('a', 64), "accepted");
        }
        public ValueTask DisposeAsync() => registration.DisposeAsync();
    }
}
