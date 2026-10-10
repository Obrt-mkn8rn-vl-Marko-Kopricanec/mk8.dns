using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class AnchorRetentionLifetimeTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [Theory]
    [InlineData(4, false)]
    [InlineData(5, false)]
    [InlineData(6, false)]
    [InlineData(7, false)]
    [InlineData(4, true)]
    [InlineData(5, true)]
    [InlineData(6, true)]
    [InlineData(7, true)]
    public async Task RetentionOwnsActualWriteCleanupKeyAndLeaseThroughConcurrentClosure(int boundary, bool fail)
    {
        using var directory = new AnchorStorageDirectory(); using var key = EcdsaP256DnssecSigningKey.Create();
        var origin = DnsName.Parse("example."); var id = Guid.NewGuid(); var secret = RandomNumberGenerator.GetBytes(32);
        try { await RunOwnedAsync(directory, key, origin, id, secret, boundary, fail).ConfigureAwait(true); }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static async Task RunOwnedAsync(AnchorStorageDirectory directory, EcdsaP256DnssecSigningKey key,
        DnsName origin, Guid id, byte[] secret, int boundary, bool fail)
    {
        var initial = new DnssecTrustAnchorTracker(origin, [DnssecKeys.CreateDnskey(origin, 3600, key.GetPublicKey())], new EcdsaP256DnssecVerifier());
        var root = Path.Combine(directory.Path, "anchors"); var armed = false;
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var resume = new ManualResetEventSlim();
        using var store = FileAnchorCheckpointStore.CreateRetentionCore(root, id, initial, secret, stage =>
        {
            if (!armed || (int)stage != boundary) return;
            reached.TrySetResult();
            if (!resume.Wait(Timeout, CancellationToken.None)) throw new TimeoutException("Owned retention boundary was not released.");
            if (fail) throw new IOException("Controlled failure AFTER actual retention boundary.");
        });
        for (long revision = 1; revision < 4; revision++) Assert.Equal(revision + 1, store.Save(revision));
        armed = true;
        try { await ExerciseAsync(store, root, id, origin, secret, reached, resume, boundary, fail).ConfigureAwait(true); }
        finally { resume.Set(); }
    }

    private static async Task ExerciseAsync(FileAnchorCheckpointStore store, string root, Guid id, DnsName origin,
        byte[] secret, TaskCompletionSource reached, ManualResetEventSlim resume, int boundary, bool fail)
    {
        var retaining = Task.Run(() => store.Retain(4, 4, 2), CancellationToken.None); Task? disposing = null;
        try
        {
            await reached.Task.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            disposing = Task.Run(() => { started.TrySetResult(); store.Dispose(); }, CancellationToken.None);
            await started.Task.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.False(retaining.IsCompleted); Assert.False(disposing.IsCompleted);
            Assert.Throws<IOException>(() => { using var ignored = Open(root, id, origin, secret); });
            resume.Set();
            if (fail) await Assert.ThrowsAsync<IOException>(() => retaining.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            else Assert.Equal(3, await retaining.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true));
            await disposing.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Throws<ObjectDisposedException>(() => store.Retain(4, 4, 2));
            AssertSuccessor(root, id, origin, secret, boundary, fail);
        }
        finally
        {
            resume.Set();
            _ = await Record.ExceptionAsync(() => retaining.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            if (disposing is not null) await disposing.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        }
    }

    private static FileAnchorCheckpointStore Open(string root, Guid id, DnsName origin, byte[] secret)
        => FileAnchorCheckpointStore.OpenWithRetention(root, id, origin, secret, 4, new EcdsaP256DnssecVerifier());

    private static void AssertSuccessor(string root, Guid id, DnsName origin, byte[] secret, int boundary, bool fail)
    {
        using var successor = Open(root, id, origin, secret);
        Assert.Equal(4, successor.Revision);
        Assert.Equal(fail && boundary == 4 ? 1 : 3, successor.FirstRetainedRevision);
        if (fail && boundary is 5 or 6)
        {
            Assert.Throws<IOException>(() => successor.Save(4));
            Assert.Equal(3, successor.Retain(4, 4, 2));
        }
        Assert.Equal(5, successor.Save(4));
    }

    [Fact]
    public void CancellationAfterBoundaryPublicationDoesNotUndoAcknowledgedCleanup()
    {
        using var directory = new AnchorStorageDirectory(); using var key = EcdsaP256DnssecSigningKey.Create();
        var origin = DnsName.Parse("example."); var secret = RandomNumberGenerator.GetBytes(32); var armed = false;
        using var cancellation = new CancellationTokenSource();
        var initial = new DnssecTrustAnchorTracker(origin, [DnssecKeys.CreateDnskey(origin, 3600, key.GetPublicKey())], new EcdsaP256DnssecVerifier());
        try
        {
            using var store = FileAnchorCheckpointStore.CreateRetentionCore(Path.Combine(directory.Path, "anchors"), Guid.NewGuid(), initial, secret, stage =>
            {
                if (armed && stage == AnchorStoreWriteStage.RetentionDirectory) cancellation.Cancel();
            });
            for (long revision = 1; revision < 4; revision++) Assert.Equal(revision + 1, store.Save(revision, CancellationToken.None));
            armed = true;
            Assert.Equal(3, store.Retain(4, 4, 2, cancellation.Token)); Assert.True(cancellation.IsCancellationRequested);
            Assert.Equal(3, store.FirstRetainedRevision); Assert.Equal(5, store.Save(4, CancellationToken.None));
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }
}
