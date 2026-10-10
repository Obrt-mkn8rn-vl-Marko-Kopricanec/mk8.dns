using System.Security.Cryptography;

namespace Mk8.Dns.Application.DAL;

public sealed partial class FileAnchorCheckpointStore
{
    private Entries InspectRetentionEntries()
    {
        NativeStoragePath.RequireDirectory(root);
        var generations = new SortedSet<long>(); var pointer = false; var temporaryCount = 0; var count = 0;
        foreach (var path in Directory.EnumerateFileSystemEntries(root))
        {
            // Bounded admission, not a guarantee about filesystem enumeration latency.
            if (++count > (MaximumGenerations * 2) + 10)
                throw new InvalidDataException("Too much retained anchor storage evidence.");
            RequirePrivateFile(path);
            var name = Path.GetFileName(path);
            if (string.Equals(name, ".writer.lock", StringComparison.Ordinal)) continue;
            if (string.Equals(name, "active.bin", StringComparison.Ordinal)) { pointer = true; continue; }
            if (name.EndsWith(".tmp", StringComparison.Ordinal) && Guid.TryParseExact(name.AsSpan(0, name.Length - 4), "N", out var temporary)
                && temporary != Guid.Empty && string.Equals(name, temporary.ToString("N") + ".tmp", StringComparison.Ordinal))
            {
                if (++temporaryCount > 8) throw new InvalidDataException("Too many anchor temporary files.");
                continue;
            }
            if (name.Length != 23 || !name.EndsWith(".anchor", StringComparison.Ordinal)
                || !long.TryParse(name.AsSpan(0, 16), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var number)
                || number < 1 || !string.Equals(path, GenerationPath(number), StringComparison.Ordinal))
            {
                throw new InvalidDataException("Unknown retained anchor storage entry.");
            }
            generations.Add(number);
            if (generations.Count > MaximumGenerations * 2)
                throw new InvalidDataException("Too many retained anchor generations.");
        }
        NativeStoragePath.RequireDirectory(root);
        return new Entries(pointer, generations);
    }

    private State ReadRetainedState(bool allowInitial)
    {
        var entries = InspectRetentionEntries();
        if (lease.Length is < 55 or > 309)
            throw new InvalidDataException("Retained anchor initialization marker is missing or malformed.");
        var marker = new byte[(int)lease.Length]; lease.Position = 0; lease.ReadExactly(marker);
        AnchorRetentionEnvelope.VerifyMarker(marker, identity, origin, authenticationKey);
        if (!entries.Pointer)
        {
            if (allowInitial && entries.Generations.Count == 0) return new State(0, new byte[32], []);
            throw new InvalidDataException("Acknowledged retained anchor metadata is missing.");
        }
        try { return ReadRetainedChain(entries); }
        catch (EndOfStreamException error) { throw new InvalidDataException("Truncated retained anchor metadata.", error); }
    }

    private State ReadRetainedChain(Entries entries)
    {
        var pointer = AnchorRetentionEnvelope.DecodePointer(ReadBounded(Path.Combine(root, "active.bin")), identity, origin, authenticationKey);
        if (pointer.First > trustedFloor || pointer.Revision < trustedFloor)
            throw new InvalidDataException("The trusted floor does not cover the retained anchor history.");
        if (entries.Generations.Count == 0 || entries.Generations.Max != pointer.Revision)
            throw new InvalidDataException("Retained anchor evidence conflicts with its active pointer.");
        byte[] previous = pointer.Previous; byte[] checkpoint = []; var retired = 0;
        foreach (var number in entries.Generations)
        {
            var raw = ReadBounded(GenerationPath(number));
            var value = AnchorRetentionEnvelope.DecodeGeneration(raw, identity, origin, authenticationKey);
            if (value.Revision != number) throw new InvalidDataException("Retained anchor generation identity changed.");
            if (number < pointer.First) { retired++; continue; } // Authenticated leftovers, never authority.
            if (!CryptographicOperations.FixedTimeEquals(value.Previous, previous))
                throw new InvalidDataException("Retained anchor generation chain mismatch.");
            previous = SHA256.HashData(raw); checkpoint = value.Checkpoint;
        }
        var live = entries.Generations.Count - retired;
        if (live != pointer.Revision - pointer.First + 1 || !entries.Generations.Contains(pointer.First)
            || !CryptographicOperations.FixedTimeEquals(pointer.Digest, previous))
        {
            throw new InvalidDataException("Retained anchor history is incomplete or its digest changed.");
        }
        return new State(pointer.Revision, previous, checkpoint, pointer.First, pointer.Previous, retired);
    }
}
