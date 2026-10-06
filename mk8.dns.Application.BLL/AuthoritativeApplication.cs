using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Engine.Authoritative;

namespace Mk8.Dns.Application.BLL;

public sealed class AuthoritativeApplication : IDnsExchange, IApplicationStatusSource
{
    private AuthoritativeCatalog? catalog;
    private readonly IDnsMessageCodec codec;
    private readonly string nodeId;

    public AuthoritativeApplication(AuthoritativeCatalog catalog, IDnsMessageCodec codec, string nodeId)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentException.ThrowIfNullOrEmpty(nodeId);
        if (catalog.ZoneCount == 0)
            throw new ArgumentException("A serving Application requires a nonempty catalog.", nameof(catalog));
        this.catalog = catalog;
        this.codec = codec;
        this.nodeId = nodeId;
    }

    public AuthoritativeApplication(IDnsMessageCodec codec, string nodeId)
    {
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentException.ThrowIfNullOrEmpty(nodeId);
        this.codec = codec;
        this.nodeId = nodeId;
        catalog = new AuthoritativeCatalog([]);
    }

    internal void ReplaceCatalog(AuthoritativeCatalog replacement) => Volatile.Write(ref catalog, replacement);
    internal void Suspend() => Volatile.Write(ref catalog, null);

    public ValueTask<ApplicationStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var generation = Volatile.Read(ref catalog);
        if (generation is null)
            throw new InvalidOperationException("Authoritative storage requires verified reconciliation.");
        return ValueTask.FromResult(new ApplicationStatus(ProtocolVersion.Current, nodeId, "authoritative-replica", generation.ZoneCount != 0, generation.ZoneCount));
    }

    public ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (message.Length > ushort.MaxValue || peerAddress.Length is not (4 or 16))
            throw new ArgumentException("Invalid DNS exchange bounds.", nameof(message));
        try
        {
            var generation = Volatile.Read(ref catalog);
            if (generation is null)
                return ValueTask.FromResult(codec.EncodeError(message.Span, 2));
            var query = codec.Decode(message.Span);
            return ValueTask.FromResult(codec.Encode(query, generation.Resolve(query.Question), tcp));
        }
        catch (FormatException)
        {
            return ValueTask.FromResult(codec.EncodeError(message.Span, 1));
        }
        catch (NotSupportedException)
        {
            return ValueTask.FromResult(codec.EncodeError(message.Span, 4));
        }
    }
}
