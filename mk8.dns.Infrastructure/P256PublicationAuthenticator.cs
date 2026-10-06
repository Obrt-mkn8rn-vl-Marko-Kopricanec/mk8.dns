using System.Security.Cryptography;
using System.Text;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure;

public sealed class P256PublicationAuthenticator : IPublicationAuthenticator, IDisposable
{
    private readonly ECDsa key;
    private readonly Guid epoch;
    private readonly string node;
    private readonly Dictionary<Guid, DnsName> zones;
    private readonly bool canSign;
    private readonly Lock sync = new();

    public P256PublicationAuthenticator(Guid epoch, string node, IReadOnlyDictionary<Guid, DnsName> zones, string pem, bool canSign)
    {
        ArgumentNullException.ThrowIfNull(zones);
        ArgumentException.ThrowIfNullOrEmpty(node);
        ArgumentException.ThrowIfNullOrEmpty(pem);
        if (!canSign && !pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal))
            throw new ArgumentException("A serving replica requires a public publisher key.", nameof(pem));
        if (epoch == Guid.Empty || node.Length > 128 || node.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')
            || zones.Count is 0 or > 64 || zones.Any(pair => pair.Key == Guid.Empty || pair.Value is null))
            throw new ArgumentException("Invalid publisher trust scope.", nameof(zones));
        this.epoch = epoch;
        this.node = node;
        this.zones = new Dictionary<Guid, DnsName>(zones);
        this.canSign = canSign;
        key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            if (!string.Equals(key.ExportParameters(false).Curve.Oid.Value, "1.2.840.10045.3.1.7", StringComparison.Ordinal))
                throw new ArgumentException("Publisher keys must use NIST P-256.", nameof(pem));
            if (canSign)
                _ = key.ExportParameters(true);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    public byte[] CreateBody(ZoneSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        RequireScope(snapshot.ZoneId, snapshot.Origin);
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        writer.Write("M8P1"u8);
        writer.Write(epoch.ToByteArray());
        writer.Write(node);
        writer.Write(snapshot.ZoneId.ToByteArray());
        var origin = snapshot.Origin.ToWire();
        writer.Write((ushort)origin.Length);
        writer.Write(origin);
        writer.Write(snapshot.Revision);
        writer.Write(snapshot.Serial);
        writer.Write(Convert.FromHexString(snapshot.ContentHash));
        var payload = snapshot.GetPayload();
        writer.Write(payload.Length);
        writer.Write(payload);
        writer.Flush();
        return output.ToArray();
    }

    public byte[] Sign(ReadOnlySpan<byte> body)
    {
        if (!canSign)
            throw new InvalidOperationException("This node has no publisher signing authority.");
        lock (sync)
            return key.SignData(body, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public ZoneSnapshot Verify(ReadOnlySpan<byte> body, ReadOnlySpan<byte> signature)
    {
        if (body.Length is < 80 or > ZoneSnapshot.MaximumPayloadBytes + 512 || signature.Length != 64)
            throw new UnauthorizedAccessException("Invalid publication authentication bounds.");
        lock (sync)
            if (!key.VerifyData(body, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new UnauthorizedAccessException("Publication signature is invalid.");
        using var input = new MemoryStream(body.ToArray(), writable: false);
        using var reader = new BinaryReader(input, Encoding.UTF8, leaveOpen: true);
        try
        {
            if (!reader.ReadBytes(4).AsSpan().SequenceEqual("M8P1"u8) || new Guid(reader.ReadBytes(16)) != epoch || !string.Equals(reader.ReadString(), node, StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Publication publisher epoch or target does not match configured trust.");
            var id = new Guid(reader.ReadBytes(16));
            var length = reader.ReadUInt16();
            if (length is 0 or > 255)
                throw new FormatException("Invalid publication origin.");
            var origin = DnsName.FromWire(reader.ReadBytes(length));
            RequireScope(id, origin);
            var revision = reader.ReadInt64();
            var serial = reader.ReadUInt32();
            var digest = reader.ReadBytes(32);
            var payloadLength = reader.ReadInt32();
            if (payloadLength is < 1 or > ZoneSnapshot.MaximumPayloadBytes || input.Length - input.Position != payloadLength)
                throw new FormatException("Invalid publication payload bounds.");
            var snapshot = new ZoneSnapshot(id, origin, revision, serial, reader.ReadBytes(payloadLength));
            if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(snapshot.ContentHash)) || !body.SequenceEqual(CreateBody(snapshot)))
                throw new FormatException("Publication metadata is not canonical or the payload digest differs.");
            return snapshot;
        }
        catch (EndOfStreamException exception)
        {
            throw new FormatException("Incomplete signed publication.", exception);
        }
    }

    public void Dispose()
    {
        lock (sync)
            key.Dispose();
    }

    public byte[] SignActivation(string publicationId) => Sign(ActivationBody(publicationId));

    public void VerifyActivation(string publicationId, ReadOnlySpan<byte> signature)
    {
        var body = ActivationBody(publicationId);
        lock (sync)
            if (signature.Length != 64 || !key.VerifyData(body, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new UnauthorizedAccessException("Activation signature is invalid.");
    }

    private static byte[] ActivationBody(string publicationId)
    {
        if (publicationId is not { Length: 64 } || publicationId.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException("A canonical publication identity is required.", nameof(publicationId));
        return [.. "M8A1"u8, .. Convert.FromHexString(publicationId)];
    }

    private void RequireScope(Guid id, DnsName origin)
    {
        if (!zones.TryGetValue(id, out var expected) || !expected.Equals(origin))
            throw new UnauthorizedAccessException("Publication zone is outside this node's configured scope.");
    }
}
