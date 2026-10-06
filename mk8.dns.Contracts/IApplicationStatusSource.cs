namespace Mk8.Dns.Contracts;

public interface IApplicationStatusSource
{
    ValueTask<ApplicationStatus> GetStatusAsync(CancellationToken cancellationToken);
}
