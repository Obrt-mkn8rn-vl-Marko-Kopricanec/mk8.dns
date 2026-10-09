using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class AnchorStorageLifetimeTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(3, true)]
    public async Task ClosingRetainsActualWriteAndLeaseAcrossEveryDurableBoundary(int boundary, bool fail)
    {
        using var directory = new AnchorStorageDirectory();
        using var key = EcdsaP256DnssecSigningKey.Create();
        var origin = DnsName.Parse("example."); var id = Guid.NewGuid();
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var initial = new DnssecTrustAnchorTracker(origin, [DnssecKeys.CreateDnskey(origin, 3600, key.GetPublicKey())], new EcdsaP256DnssecVerifier());
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var disposalStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var resume = new ManualResetEventSlim(); var armed = false;
        var root = Path.Combine(directory.Path, "anchors");
        using var store = FileAnchorCheckpointStore.CreateCore(root, id, initial, secret, stage =>
        {
            if (!armed || (int)stage != boundary) return;
            reached.SetResult();
            if (!resume.Wait(Timeout)) throw new TimeoutException("Owned storage gate did not release.");
            if (fail) throw new IOException("Injected failure after an actual durable write.");
        });
        armed = true;
        var saving = Task.Run(() => store.Save(1), CancellationToken.None);
        Task? disposing = null;
        try
        {
            await reached.Task.WaitAsync(Timeout).ConfigureAwait(true);
            disposing = Task.Run(() => { disposalStarted.SetResult(); store.Dispose(); }, CancellationToken.None);
            await disposalStarted.Task.WaitAsync(Timeout).ConfigureAwait(true);
            AssertHeldWriter(root, id, origin, secret, saving, disposing);
            resume.Set();
            await CheckSaveAsync(saving, fail).ConfigureAwait(true);
            await disposing.WaitAsync(Timeout).ConfigureAwait(true);
            Assert.Throws<ObjectDisposedException>(() => store.Save(1));
            AssertRecovery(root, id, origin, secret, boundary, fail);
        }
        finally
        {
            resume.Set();
            _ = await Record.ExceptionAsync(() => saving.WaitAsync(Timeout)).ConfigureAwait(true);
            if (disposing is not null) await disposing.WaitAsync(Timeout).ConfigureAwait(true);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static FileAnchorCheckpointStore Open(string root, Guid id, DnsName origin, byte[] secret)
        => FileAnchorCheckpointStore.Open(root, id, origin, secret, 1, new EcdsaP256DnssecVerifier());

    private static void AssertHeldWriter(string root, Guid id, DnsName origin, byte[] secret, Task saving, Task disposing)
    {
        Assert.False(saving.IsCompleted); Assert.False(disposing.IsCompleted);
        Assert.Throws<IOException>(() => { using var ignored = Open(root, id, origin, secret); });
    }

    private static async Task CheckSaveAsync(Task<long> saving, bool fail)
    {
        if (fail) await Assert.ThrowsAsync<IOException>(() => saving.WaitAsync(Timeout)).ConfigureAwait(true);
        else Assert.Equal(2, await saving.WaitAsync(Timeout).ConfigureAwait(true));
    }

    private static void AssertRecovery(string root, Guid id, DnsName origin, byte[] secret, int boundary, bool fail)
    {
        if (fail && boundary is 1 or 2)
        {
            Assert.Throws<InvalidDataException>(() => { using var ignored = Open(root, id, origin, secret); });
            return;
        }
        using var successor = Open(root, id, origin, secret);
        Assert.Equal(fail && boundary == 0 ? 1 : 2, successor.Revision);
        Assert.Equal(successor.Revision + 1, successor.Save(successor.Revision));
    }
}
