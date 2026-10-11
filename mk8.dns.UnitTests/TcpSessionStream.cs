namespace Mk8.Dns.UnitTests;

internal sealed class TcpSessionStream(byte[] input) : Stream
{
    private readonly byte[] input = (byte[])input.Clone();
    private readonly MemoryStream output = new();
    private readonly Lock gate = new();
    private int offset;
    internal int ReadCalls { get; private set; }
    internal int WriteCalls { get; private set; }
    internal int FlushCalls { get; private set; }
    internal int DisposeCalls { get; private set; }
    internal int BytesRead => offset;
    internal int ReadChunk { get; set; } = 1;
    internal Func<CancellationToken, Task>? BeforeRead { get; set; }
    internal Func<CancellationToken, Task>? BeforeWrite { get; set; }
    internal Func<CancellationToken, Task>? BeforeFlush { get; set; }
    internal byte[] Output { get { lock (gate) return output.ToArray(); } }
    public override bool CanRead => DisposeCalls == 0;
    public override bool CanWrite => DisposeCalls == 0;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ReadCalls++;
        if (BeforeRead is { } before) await before(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var count = Math.Min(Math.Min(ReadChunk, buffer.Length), input.Length - offset);
        input.AsMemory(offset, count).CopyTo(buffer); offset += count;
        return count;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        WriteCalls++;
        if (BeforeWrite is { } before) await before(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate) output.Write(buffer.Span);
    }

    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        FlushCalls++;
        if (BeforeFlush is { } before) await before(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { DisposeCalls++; output.Dispose(); }
        base.Dispose(disposing);
    }
}
