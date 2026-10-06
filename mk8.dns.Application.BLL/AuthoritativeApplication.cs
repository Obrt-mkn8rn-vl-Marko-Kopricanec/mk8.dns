using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Engine.Authoritative;

namespace Mk8.Dns.Application.BLL;

public sealed class AuthoritativeApplication : IDnsExchange, IApplicationStatusSource
{
    private readonly AuthoritativeCatalog catalog;
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

    public ValueTask<ApplicationStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(new ApplicationStatus(ProtocolVersion.Current, nodeId, "authoritative-replica", true, catalog.ZoneCount));
    }

    public ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (message.Length > ushort.MaxValue || peerAddress.Length is not (4 or 16))
            throw new ArgumentException("Invalid DNS exchange bounds.", nameof(message));
        try
        {
            var query = codec.Decode(message.Span);
            return ValueTask.FromResult(codec.Encode(query, catalog.Resolve(query.Question), tcp));
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
