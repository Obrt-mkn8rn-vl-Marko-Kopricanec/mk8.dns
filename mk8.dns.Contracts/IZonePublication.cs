namespace Mk8.Dns.Contracts;

public interface IZonePublication
{
    ValueTask<PublicationReply> ExecuteAsync(PublicationRequest request, CancellationToken cancellationToken);
}
