using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.DependencyInjection;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class RpcAdmissionLifetimeTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task DisposalCannotReplaceHeldSourceSuccessOrFault(bool probe, bool sourceFailure)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var source = new HeldSource(sourceFailure);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApplicationProbe(source);
        services.AddAuthoritativeQuery(source);
        var provider = services.BuildServiceProvider();
        await using var providerLifetime = provider.ConfigureAwait(true);
        var status = provider.GetRequiredService<ApplicationProbeService>();
        var query = provider.GetRequiredService<AuthoritativeQueryService>();
        var context = new CallContext(guard.Token);
        var calls = Enumerable.Range(0, 16).Select(_ => CallAsync(status, query, context, probe)).ToArray();
        await TestTaskSettlement.RunAsync(async () =>
        {
            await source.Entered.Task.WaitAsync(guard.Token).ConfigureAwait(true);
            Assert.All(calls, call => Assert.False(call.IsCompleted));
            var rejected = await Assert.ThrowsAsync<RpcException>(() => CallAsync(status, query, context, probe)).ConfigureAwait(true);
            Assert.Equal(StatusCode.ResourceExhausted, rejected.StatusCode);
            Assert.Equal(16, source.Calls);
            await provider.DisposeAsync().ConfigureAwait(true);
            await provider.DisposeAsync().ConfigureAwait(true);
            Assert.All(calls, call => Assert.False(call.IsCompleted));
            Assert.False(guard.IsCancellationRequested);
            source.Resume.SetResult();
            await CheckResultsAsync(calls, source, sourceFailure, guard.Token).ConfigureAwait(true);
            Assert.Equal(16, source.Returned);
            // Each completion returned its charge, even after container disposal.
            var later = await Record.ExceptionAsync(() => CallAsync(status, query, context, probe)).ConfigureAwait(true);
            if (sourceFailure) Assert.Same(source.Failure, later);
            else Assert.Null(later);
            Assert.Equal(17, source.Calls);
        }, async () =>
        {
            source.Resume.TrySetResult();
            await TestTaskSettlement.RunAsync(async () =>
            {
                _ = await Record.ExceptionAsync(() => Task.WhenAll(calls).WaitAsync(CancellationToken.None)).ConfigureAwait(true);
                foreach (var call in calls)
                {
                    var error = await Record.ExceptionAsync(() => call.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
                    if (!ReferenceEquals(error, source.Failure)) Assert.Null(error);
                }
            }, async () => await provider.DisposeAsync().ConfigureAwait(true)).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }

    private static async Task CheckResultsAsync(Task[] calls, HeldSource source, bool sourceFailure, CancellationToken token)
    {
        foreach (var call in calls)
        {
            var error = await Record.ExceptionAsync(() => call.WaitAsync(token)).ConfigureAwait(true);
            if (sourceFailure) Assert.Same(source.Failure, error);
            else Assert.Null(error);
        }
    }

    private static async Task CallAsync(ApplicationProbeService status, AuthoritativeQueryService query, ServerCallContext context, bool probe)
    {
        if (probe)
        {
            var reply = await status.GetStatus(new StatusRequest { ProtocolVersion = ProtocolVersion.Current }, context).ConfigureAwait(true);
            Assert.Equal("held-node", reply.NodeId);
            Assert.Equal(7u, reply.ActiveSnapshots);
            Assert.True(reply.DnsReady);
        }
        else
        {
            var reply = await query.Exchange(new DnsRequest
            {
                ProtocolVersion = ProtocolVersion.Current,
                Message = ByteString.CopyFrom([1]),
                PeerAddress = ByteString.CopyFrom([127, 0, 0, 1]),
            }, context).ConfigureAwait(true);
            Assert.Equal("*"u8.ToArray(), reply.Message.ToByteArray());
        }
    }

    private sealed class HeldSource(bool fail) : IApplicationStatusSource, IDnsExchange
    {
        private int calls;
        private int returned;
        internal int Calls => Volatile.Read(ref calls);
        internal int Returned => Volatile.Read(ref returned);
        internal InvalidOperationException Failure { get; } = new("Controlled admitted source failure.");
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<ApplicationStatus> GetStatusAsync(CancellationToken cancellationToken)
        {
            await WaitAsync().ConfigureAwait(true);
            return new ApplicationStatus(ProtocolVersion.Current, "held-node", "authority", DnsReady: true, 7);
        }

        public async ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken)
        {
            await WaitAsync().ConfigureAwait(true);
            return [42];
        }

        private async Task WaitAsync()
        {
            if (Interlocked.Increment(ref calls) == 16) Entered.SetResult();
            await Resume.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            _ = Interlocked.Increment(ref returned);
            if (fail) throw Failure;
        }
    }

    private sealed class CallContext(CancellationToken token) : ServerCallContext
    {
        protected override CancellationToken CancellationTokenCore => token;
        protected override string MethodCore => throw new NotSupportedException();
        protected override string HostCore => throw new NotSupportedException();
        protected override string PeerCore => throw new NotSupportedException();
        protected override DateTime DeadlineCore => throw new NotSupportedException();
        protected override Metadata RequestHeadersCore => throw new NotSupportedException();
        protected override Metadata ResponseTrailersCore => throw new NotSupportedException();
        protected override Status StatusCore { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        protected override WriteOptions? WriteOptionsCore { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        protected override AuthContext AuthContextCore => throw new NotSupportedException();
        protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) => throw new NotSupportedException();
        protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => throw new NotSupportedException();
    }
}
