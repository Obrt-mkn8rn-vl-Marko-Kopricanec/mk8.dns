namespace Mk8.Dns.Application.Abstractions;

public interface IZoneResigningStore
{
    ValueTask<IZoneResigningTransaction> BeginAsync(CancellationToken cancellationToken);
}
