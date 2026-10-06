namespace Mk8.Dns.Contracts;

public interface IZoneManagement
{
    ValueTask<ManagementReply> ExecuteAsync(ManagementRequest request, CancellationToken cancellationToken);
}
