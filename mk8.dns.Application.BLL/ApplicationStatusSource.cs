using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Application.BLL;

public sealed class ApplicationStatusSource : IApplicationStatusSource
{
    private readonly IZoneSnapshotStore snapshots;
    private readonly string nodeId;
    private readonly string role;

    public ApplicationStatusSource(IZoneSnapshotStore snapshots, string nodeId, string role)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        ArgumentException.ThrowIfNullOrEmpty(nodeId);
        ArgumentException.ThrowIfNullOrEmpty(role);
        this.snapshots = snapshots;
        this.nodeId = nodeId;
        this.role = role;
    }

    public async ValueTask<ApplicationStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        var count = await snapshots.CountActiveAsync(cancellationToken).ConfigureAwait(false);
        return new ApplicationStatus(ProtocolVersion.Current, nodeId, role, false, count);
    }
}
