using System.Runtime.InteropServices;

namespace Mk8.Dns.Application;

internal sealed class RecursiveShutdown : IDisposable
{
    private readonly Lock gate = new();
    private readonly CancellationTokenSource source = new();
    private readonly PosixSignalRegistration terminate;
    private readonly PosixSignalRegistration interrupt;
    private Task? cancellation;
    private bool closing;

    internal RecursiveShutdown()
    {
        try
        {
            terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Stop);
            try { interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, Stop); }
            catch { terminate.Dispose(); throw; }
        }
        catch
        {
            lock (gate) { closing = true; source.Dispose(); }
            throw;
        }
    }

    internal CancellationToken Token => source.Token;

    private void Stop(PosixSignalContext context)
    {
        context.Cancel = true;
        lock (gate)
        {
            if (!closing) cancellation ??= source.CancelAsync();
        }
    }

    internal Task JoinAsync()
    {
        terminate.Dispose(); interrupt.Dispose();
        lock (gate)
        {
            closing = true;
            return cancellation ?? Task.CompletedTask;
        }
    }

    public void Dispose()
    {
        terminate.Dispose(); interrupt.Dispose();
        lock (gate)
        {
            closing = true;
            source.Dispose();
        }
    }
}
