namespace Mk8.Dns.Engine.Recursive;

// Shared by one epoch facade. A charge survives waiter cancellation and revision
// retirement until the actual source, timer and cancellation callbacks settle.
internal sealed class DnssecSharedWorkBudget(int maximum)
{
    private readonly Lock gate = new();
    private int active;

    internal int Active { get { lock (gate) return active; } }

    internal bool TryAcquire()
    {
        lock (gate)
        {
            if (active == maximum) return false;
            active++;
            return true;
        }
    }

    internal void Release()
    {
        lock (gate)
        {
            if (active == 0) throw new InvalidOperationException("An authenticated worker charge was released twice.");
            active--;
        }
    }
}
