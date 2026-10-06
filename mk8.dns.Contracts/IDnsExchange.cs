namespace Mk8.Dns.Contracts;

public interface IDnsExchange
{
    ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken);
}
