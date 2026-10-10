using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;

namespace Mk8.Dns.UnitTests;

internal sealed class AnchorRetentionFixture : IDisposable
{
    internal AnchorStorageFixture Storage { get; } = new();
    internal FileAnchorCheckpointStore Create(Action<AnchorStoreWriteStage>? hook = null)
        => FileAnchorCheckpointStore.CreateRetentionCore(Storage.Root, Storage.Identity,
            Storage.Keys.Tracker(Storage.Keys.A), Storage.Secret, hook);
    internal FileAnchorCheckpointStore Open(long floor)
        => FileAnchorCheckpointStore.OpenWithRetention(Storage.Root, Storage.Identity, Storage.Keys.Origin,
            Storage.Secret, floor, DnssecFixture.Verifier, Storage.Keys.Clock);
    internal static void Advance(FileAnchorCheckpointStore store, long revision)
    {
        while (store.Revision < revision) AssertRevision(store);
    }
    private static void AssertRevision(FileAnchorCheckpointStore store)
    {
        var expected = store.Revision;
        if (store.Save(expected) != expected + 1) throw new InvalidOperationException("Controlled save was not acknowledged.");
    }
    internal byte[] Pointer(long revision, long first, byte[] previous, byte[] digest)
        => Frame("M8P2", writer => { writer.Write(revision); writer.Write(first); writer.Write(previous); writer.Write(digest); });
    internal byte[] Generation(long revision, byte[] previous, byte[] payload)
        => Frame("M8S2", writer => { writer.Write(revision); writer.Write(previous); writer.Write(payload.Length); writer.Write(payload); });
    private byte[] Frame(string purpose, Action<BinaryWriter> body)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(System.Text.Encoding.ASCII.GetBytes(purpose)); writer.Write(Storage.Identity.ToByteArray());
            var name = Storage.Keys.Origin.ToWire(); writer.Write((ushort)name.Length); writer.Write(name); body(writer);
        }
        return Storage.Seal(stream.ToArray());
    }
    internal static byte[] Digest(string file) => SHA256.HashData(File.ReadAllBytes(file));
    public void Dispose() => Storage.Dispose();
}
