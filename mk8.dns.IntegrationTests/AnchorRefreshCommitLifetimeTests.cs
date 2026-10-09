using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class AnchorRefreshCommitLifetimeTests
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(3, true)]
    public async Task EveryHeldDurableBoundaryRetainsOldSnapshotLeaseAndJoinedSessionClosing(int boundary, bool fail)
    {
        using var f = new AnchorRefreshWireFixture(); using var directory = new AnchorStorageDirectory();
        var root = Path.Combine(directory.Path, "anchors"); var id = Guid.NewGuid();
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        using var held = new HeldWrite(boundary, fail);
        using var store = FileAnchorCheckpointStore.CreateCore(root, id,
            new DnssecTrustAnchorTracker(f.Origin, [f.Initial], f.Verifier, f.Clock), secret, held.OnWrite);
        var endpoint = new DnsServerEndpoint([127, 0, 0, 1], 5300);
        var session = new DnssecAnchorRefresher(f.Origin, store, f, f.Verifier, endpoint, f.Clock);
        var old = session.Current; held.Armed = true;
        var refresh = session.RefreshAsync(CancellationToken.None).AsTask();
        try
        {
            await held.Reached.Task.WaitAsync(AnchorRefreshWireFixture.Timeout, f.Clock).ConfigureAwait(true);
            Assert.Same(old, session.Current); Assert.Single(old.Anchors);
            var closing = session.DisposeAsync().AsTask();
            Assert.False(refresh.IsCompleted); Assert.False(closing.IsCompleted);
            Assert.Throws<IOException>(() => { using var ignored = FileAnchorCheckpointStore.Open(root, id, f.Origin, secret, 1, f.Verifier, f.Clock); });
            held.Resume.Set();
            if (fail) await Assert.ThrowsAsync<IOException>(() => refresh.WaitAsync(AnchorRefreshWireFixture.Timeout, f.Clock)).ConfigureAwait(true);
            else Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await refresh.WaitAsync(AnchorRefreshWireFixture.Timeout, f.Clock).ConfigureAwait(true));
            await closing.WaitAsync(AnchorRefreshWireFixture.Timeout, f.Clock).ConfigureAwait(true);
            // Session closure never disposes the caller's actual store/lease.
            Assert.Throws<IOException>(() => { using var ignored = FileAnchorCheckpointStore.Open(root, id, f.Origin, secret, 1, f.Verifier, f.Clock); });
            store.Dispose();
            AssertRecovery(f, root, id, secret, boundary, fail);
            Assert.Single(old.Anchors);
        }
        finally
        {
            held.Resume.Set(); _ = await Record.ExceptionAsync(() => refresh.WaitAsync(AnchorRefreshWireFixture.Timeout, f.Clock)).ConfigureAwait(true);
            await session.DisposeAsync().ConfigureAwait(true);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static void AssertRecovery(AnchorRefreshWireFixture fixture, string root, Guid id, byte[] secret, int boundary, bool fail)
    {
        if (fail && boundary is 1 or 2)
        {
            Assert.Throws<InvalidDataException>(() => { using var ignored = FileAnchorCheckpointStore.Open(root, id, fixture.Origin, secret, 1, fixture.Verifier, fixture.Clock); });
        }
        else
        {
            using var recovered = FileAnchorCheckpointStore.Open(root, id, fixture.Origin, secret, 1, fixture.Verifier, fixture.Clock);
            Assert.Equal(fail && boundary == 0 ? 1 : 2, recovered.Revision);
            Assert.Equal(fail && boundary == 0 ? 1 : 0, recovered.Tracker.GetTrustAnchors().Count);
        }
    }

    private sealed class HeldWrite(int boundary, bool fail) : IDisposable
    {
        internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ManualResetEventSlim Resume { get; } = new();
        internal bool Armed { get; set; }
        internal void OnWrite(AnchorStoreWriteStage stage)
        {
            if (!Armed || (int)stage != boundary) return;
            Reached.SetResult();
            if (!Resume.Wait(AnchorRefreshWireFixture.Timeout)) throw new TimeoutException();
            if (fail) throw new IOException("Controlled exception after actual durable boundary.");
        }
        public void Dispose() => Resume.Dispose();
    }
}
