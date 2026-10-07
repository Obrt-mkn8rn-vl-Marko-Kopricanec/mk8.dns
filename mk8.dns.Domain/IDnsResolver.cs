namespace Mk8.Dns.Domain;

public interface IDnsResolver
{
    // The owner supplies a complete selected recursive answer, with AA clear and no additional data.
    // No validation status is represented here; instances must stay in one fixed non-validating profile.
    ValueTask<DnsAnswer> ResolveAsync(DnsQuestion question, CancellationToken cancellationToken);
}
