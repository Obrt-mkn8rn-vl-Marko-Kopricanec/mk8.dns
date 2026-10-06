using Mk8.Dns.Contracts;

namespace Mk8.Dns.UnitTests;

internal sealed class HttpManagementStub(Func<ManagementRequest, CancellationToken, ValueTask<ManagementReply>> execute) : IZoneManagement
{
    internal int Calls => Volatile.Read(ref calls);
    private int calls;

    public ValueTask<ManagementReply> ExecuteAsync(ManagementRequest request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref calls);
        return execute(request, cancellationToken);
    }
}
