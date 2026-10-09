using System.Security.Cryptography;

namespace Mk8.Dns.Application.DAL;

public sealed partial class FileAnchorCheckpointStore
{
    private sealed record Entries(bool Pointer, SortedSet<long> Generations);
    private sealed record State(long Revision, byte[] Digest, byte[] Checkpoint);

    private Entries InspectEntries()
    {
        NativeStoragePath.RequireDirectory(root);
        var generations = new SortedSet<long>(); var pointer = false;
        foreach (var path in Directory.EnumerateFileSystemEntries(root))
        {
            RequirePrivateFile(path);
            var name = Path.GetFileName(path);
            if (string.Equals(name, ".writer.lock", StringComparison.Ordinal)) continue;
            if (string.Equals(name, "active.bin", StringComparison.Ordinal)) { pointer = true; continue; }
            if (name.EndsWith(".tmp", StringComparison.Ordinal) && Guid.TryParseExact(name.AsSpan(0, name.Length - 4), "N", out var temporary)
                && temporary != Guid.Empty && string.Equals(name, temporary.ToString("N") + ".tmp", StringComparison.Ordinal)) continue;
            if (name.Length != 23 || !name.EndsWith(".anchor", StringComparison.Ordinal)
                || !long.TryParse(name.AsSpan(0, 16), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var number)
                || number is < 1 or > MaximumGenerations || !string.Equals(path, GenerationPath(number), StringComparison.Ordinal))
                throw new InvalidDataException("Unknown anchor storage entry.");
            generations.Add(number);
        }
        NativeStoragePath.RequireDirectory(root);
        return new Entries(pointer, generations);
    }

    private State ReadState(bool allowInitial)
    {
        var entries = InspectEntries();
        if (lease.Length is < 55 or > 309)
            throw new InvalidDataException("Anchor initialization marker is missing or malformed.");
        var marker = new byte[(int)lease.Length]; lease.Position = 0; lease.ReadExactly(marker);
        AnchorStoreEnvelope.VerifyMarker(marker, identity, origin, authenticationKey);
        if (!entries.Pointer)
        {
            if (allowInitial && entries.Generations.Count == 0) return new State(0, new byte[32], []);
            throw new InvalidDataException("Acknowledged anchor metadata is missing.");
        }
        try { return ReadChain(entries); }
        catch (EndOfStreamException error) { throw new InvalidDataException("Truncated anchor storage metadata.", error); }
    }

    private State ReadChain(Entries entries)
    {
        var pointer = AnchorStoreEnvelope.DecodePointer(ReadBounded(Path.Combine(root, "active.bin")), identity, origin, authenticationKey);
        if (entries.Generations.Count != pointer.Revision || entries.Generations.Max != pointer.Revision)
            throw new InvalidDataException("Anchor generation evidence conflicts with the active pointer.");
        byte[] previous = new byte[32]; byte[] checkpoint = [];
        for (long number = 1; number <= pointer.Revision; number++)
        {
            if (!entries.Generations.Contains(number)) throw new InvalidDataException("Anchor generation history is incomplete.");
            var raw = ReadBounded(GenerationPath(number));
            var value = AnchorStoreEnvelope.DecodeGeneration(raw, identity, origin, authenticationKey);
            if (value.Revision != number || !CryptographicOperations.FixedTimeEquals(value.Previous, previous))
                throw new InvalidDataException("Anchor generation chain mismatch.");
            previous = SHA256.HashData(raw); checkpoint = value.Checkpoint;
        }
        if (!CryptographicOperations.FixedTimeEquals(pointer.Digest, previous))
            throw new InvalidDataException("Anchor pointer digest mismatch.");
        return new State(pointer.Revision, previous, checkpoint);
    }

    private void VerifyCurrentState()
    {
        try
        {
            var state = ReadState(allowInitial: false);
            if (state.Revision != revision || !CryptographicOperations.FixedTimeEquals(state.Digest, digest))
                throw new InvalidDataException("Anchor acknowledgement disagrees with storage.");
        }
        catch { faulted = true; throw; }
    }
}
