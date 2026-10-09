using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Application.DAL;

public sealed partial class FileAnchorCheckpointStore : IDisposable
{
    public const int MaximumGenerations = 256;
    private readonly string root;
    private readonly Guid identity;
    private readonly DnsName origin;
    private readonly byte[] authenticationKey;
    private readonly FileStream lease;
    private readonly Lock sync = new();
    private readonly Action<AnchorStoreWriteStage>? afterDurableWrite;
    private DnssecTrustAnchorTracker? tracker;
    private long revision;
    private byte[] digest = new byte[32];
    private bool disposed;
    private bool faulted;
    private int closing;

    private FileAnchorCheckpointStore(string directory, Guid storageId, DnsName expectedOrigin,
        ReadOnlySpan<byte> key, bool create, Action<AnchorStoreWriteStage>? hook = null, Func<SafeFileHandle, int, int>? nativeLock = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        ArgumentNullException.ThrowIfNull(expectedOrigin);
        if (!OperatingSystem.IsLinux() || !Path.IsPathFullyQualified(directory) || storageId == Guid.Empty || key.Length != 32)
            throw new ArgumentException("An absolute Linux path, nonempty store identity and 32-byte authentication key are required.", nameof(directory));
        root = Path.GetFullPath(directory); identity = storageId; origin = expectedOrigin;
        authenticationKey = key.ToArray(); afterDurableWrite = hook;
        try { lease = AcquireLease(create, nativeLock); }
        catch { CryptographicOperations.ZeroMemory(authenticationKey); throw; }
    }

    public static FileAnchorCheckpointStore Create(string directory, Guid storageId, DnssecTrustAnchorTracker initial,
        ReadOnlySpan<byte> authenticationKey)
        => CreateCore(directory, storageId, initial, authenticationKey, null);

    internal static FileAnchorCheckpointStore CreateCore(string directory, Guid storageId, DnssecTrustAnchorTracker initial,
        ReadOnlySpan<byte> key, Action<AnchorStoreWriteStage>? hook, Func<SafeFileHandle, int, int>? nativeLock = null)
    {
        ArgumentNullException.ThrowIfNull(initial);
        var store = new FileAnchorCheckpointStore(directory, storageId, initial.Origin, key, create: true, hook, nativeLock);
        try
        {
            store.Initialize(initial);
            return store;
        }
        catch { store.Dispose(); throw; }
    }

    public static FileAnchorCheckpointStore Open(string directory, Guid storageId, DnsName expectedOrigin,
        ReadOnlySpan<byte> authenticationKey, long minimumRevision, IDnssecSignatureVerifier verifier, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        if (minimumRevision is < 1 or > MaximumGenerations)
            throw new ArgumentOutOfRangeException(nameof(minimumRevision));
        var store = new FileAnchorCheckpointStore(directory, storageId, expectedOrigin, authenticationKey, create: false);
        try
        {
            var state = store.ReadState(allowInitial: false);
            if (state.Revision < minimumRevision)
                throw new InvalidDataException("Anchor storage is older than its trusted revision floor.");
            store.tracker = DnssecTrustAnchorTracker.RestoreCheckpoint(expectedOrigin, state.Checkpoint, verifier, time);
            store.revision = state.Revision; store.digest = state.Digest;
            return store;
        }
        catch { store.Dispose(); throw; }
    }

    public DnssecTrustAnchorTracker Tracker
    {
        get { lock (sync) { RequireHealthy(); return tracker!; } }
    }

    public long Revision
    {
        get { lock (sync) { RequireHealthy(); return revision; } }
    }

    public long Save(long expectedRevision, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            RequireHealthy(); cancellationToken.ThrowIfCancellationRequested();
            if (expectedRevision != revision)
                throw new InvalidOperationException("Anchor revision changed.");
            if (revision >= MaximumGenerations)
                throw new IOException("Anchor retention capacity requires explicit maintenance.");
            VerifyCurrentState();
            var checkpoint = tracker!.CreateCheckpoint();
            cancellationToken.ThrowIfCancellationRequested();
            Commit(checkpoint);
            return revision;
        }
    }

    public void Dispose()
    {
        _ = Interlocked.Exchange(ref closing, 1);
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            try { lease.Dispose(); }
            finally { CryptographicOperations.ZeroMemory(authenticationKey); }
        }
    }

    private void RequireHealthy()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref closing) != 0, this);
        if (faulted)
            throw new IOException("Anchor storage ownership is faulted; explicit recovery is required.");
    }
}
