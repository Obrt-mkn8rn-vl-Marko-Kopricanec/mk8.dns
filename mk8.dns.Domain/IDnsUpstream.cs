namespace Mk8.Dns.Domain;

public interface IDnsUpstream
{
    // Implementations own endpoint/transaction/question matching and bounded UDP/TCP I/O.
    // A returned answer must be complete (never TC); I/O failures are IOException/TimeoutException.
    ValueTask<DnsAnswer> ExchangeAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken);
}
