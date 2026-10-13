using System.Runtime.InteropServices;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ManagementCredentialOwnershipTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OwnedCredentialSurvivesTransactionDrainThenClearsWithoutMutatingIngress(bool found)
    {
        byte[] ingress = [.. Enumerable.Repeat((byte)123, 32)];
        var authorizer = new Authorizer();
        var transaction = new Transaction();
        await using var transactionLifetime = transaction.ConfigureAwait(true);
        var request = new ManagementRequest("status", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 0,
            DnsName.Parse("example.").ToWire(), [], ingress);
        var snapshot = ZoneBundleCodec.Compile(request.ZoneId, 1, AuthorityFixture.Zone());
        if (found) transaction.Operation = new ZoneOperation(request.TenantId, request.OperationId, "unused", "actor", "node", snapshot, Activated: false);
        var application = new ZoneManagementApplication(new Store(transaction), authorizer, new ZoneBundleAdapter(), "node");
        var operation = application.ExecuteAsync(request, CancellationToken.None).AsTask();
        await TestTaskSettlement.RunAsync(async () =>
        {
            await transaction.Disposing.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true);
            Assert.False(operation.IsCompleted);
            Assert.True(MemoryMarshal.TryGetArray(authorizer.Credential, out var owned));
            Assert.NotSame(ingress, owned.Array);
            Assert.Equal(ingress, authorizer.Credential.ToArray());
            transaction.Release.TrySetResult();
            if (found) Assert.Equal("accepted", (await operation.WaitAsync(CancellationToken.None).ConfigureAwait(true)).State);
            else await Assert.ThrowsAsync<KeyNotFoundException>(() => operation.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
            Assert.All(authorizer.Credential.ToArray(), value => Assert.Equal(0, value));
            Assert.All(ingress, value => Assert.Equal(123, value));
        }, async () =>
        {
            transaction.Release.TrySetResult();
            try { await operation.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true); }
            catch (KeyNotFoundException) when (!found && operation.IsFaulted) { }
        }).ConfigureAwait(true);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthorizationAndAdmissionFaultsClearOnlyTheOwnedCopy(bool failAuthorization)
    {
        byte[] ingress = [.. Enumerable.Repeat((byte)123, 32)];
        var fault = new InvalidOperationException("Owned management admission fault.");
        var authorizer = new Authorizer { Failure = failAuthorization ? fault : null };
        var transaction = new Transaction();
        transaction.Release.SetResult();
        await using var lifetime = transaction.ConfigureAwait(true);
        var store = new Store(transaction) { Failure = failAuthorization ? null : fault };
        var application = new ZoneManagementApplication(store, authorizer, new ZoneBundleAdapter(), "node");
        var request = new ManagementRequest("status", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 0,
            DnsName.Parse("example.").ToWire(), [], ingress);
        var observed = await Assert.ThrowsAsync<InvalidOperationException>(() => application.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Same(fault, observed);
        Assert.All(authorizer.Credential.ToArray(), value => Assert.Equal(0, value));
        Assert.All(ingress, value => Assert.Equal(123, value));
        Assert.False(transaction.Disposing.Task.IsCompleted);
    }

    private sealed class Authorizer : IManagementAuthorizer
    {
        internal ReadOnlyMemory<byte> Credential { get; private set; }
        internal Exception? Failure { get; set; }
        public string Authorize(ManagementRequest request)
        {
            Credential = request.Credential;
            if (Failure is not null) throw Failure;
            return "actor";
        }
        public void AuthorizeOperation(ManagementRequest request, string operationActor) { }
        public void AuthorizeZone(ManagementRequest request, AuthoritativeZone zone) { }
    }
    private sealed class Store(Transaction transaction) : IControlPlaneStore
    {
        internal Exception? Failure { get; set; }
        public ValueTask<IControlTransaction> BeginAsync(CancellationToken cancellationToken)
            => Failure is null ? ValueTask.FromResult<IControlTransaction>(transaction) : ValueTask.FromException<IControlTransaction>(Failure);
        public ValueTask<ZoneOperation?> ReadPendingAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public ValueTask MarkActivatedAsync(ZoneOperation operation, PublicationReply receipt, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
    private sealed class Transaction : IControlTransaction
    {
        internal ZoneOperation? Operation { get; set; }
        internal TaskCompletionSource Disposing { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ValueTask<ZoneOperation?> ReadOperationAsync(Guid tenantId, Guid operationId, CancellationToken cancellationToken) => ValueTask.FromResult(Operation);
        public ValueTask<ZoneSnapshot?> ReadZoneAsync(Guid tenantId, Guid zoneId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public ValueTask<IReadOnlyList<ZoneOwnership>> ReadOwnershipAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public ValueTask AppendAsync(ZoneOperation operation, CancellationToken cancellationToken) => throw new NotSupportedException();
        public ValueTask CommitAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public async ValueTask DisposeAsync()
        {
            Disposing.TrySetResult();
            await Release.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true);
        }
    }
}
