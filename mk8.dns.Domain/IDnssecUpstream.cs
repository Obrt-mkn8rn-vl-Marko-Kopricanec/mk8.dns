namespace Mk8.Dns.Domain;

public interface IDnssecUpstream
{
    // Fixed local-validation acquisition: RD/AD clear, CD/DO set. Implementations
    // own endpoint/ID/question matching and return only complete non-TC evidence.
    // Header/EDNS observations and records are not authenticated DNSSEC status.
    ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken);
}
