using System.Net.Sockets;

namespace Mk8.Dns.Engine.Recursive;

// Owns the NetworkStream, not the socket. Only actual native-stream failures
// and input framing are tagged; source/provider exceptions must still fault.
internal sealed class DnssecNativePeerStream : Stream
{
    private readonly NetworkStream stream;
    private IOException? peerFailure;
    internal DnssecNativePeerStream(Socket socket) => stream = new NetworkStream(socket, ownsSocket: false);
    internal bool IsPeerFailure(IOException error) => ReferenceEquals(peerFailure, error);
    private IOException Failure(string message, Exception? inner = null)
    {
        var error = new IOException(message, inner); peerFailure = error; return error;
    }
    private int prefixBytes;
    private int length;
    private int remaining;
    public override bool CanRead => stream.CanRead;
    public override bool CanWrite => stream.CanWrite;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int read;
        try { read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false); }
        catch (Exception error) when (error is IOException or SocketException) { throw Failure("Native peer read failed.", error); }
        if (read == 0 && (prefixBytes != 0 || remaining != 0)) throw Failure("Incomplete native peer frame.");
        Track(buffer.Span[..read]);
        return read;
    }

    private void Track(ReadOnlySpan<byte> bytes)
    {
        foreach (ref readonly var value in bytes)
        {
            if (remaining != 0)
            {
                if (--remaining == 0) { prefixBytes = 0; length = 0; }
            }
            else
            {
                length = (length << 8) | value;
                if (++prefixBytes == 2)
                {
                    if (length < 12) throw Failure("Native peer frame has no complete DNS header.");
                    remaining = length;
                }
            }
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        try { await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false); }
        catch (Exception error) when (error is IOException or SocketException) { throw Failure("Native peer write failed.", error); }
    }

    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        try { await stream.FlushAsync(cancellationToken).ConfigureAwait(false); }
        catch (Exception error) when (error is IOException or SocketException) { throw Failure("Native peer flush failed.", error); }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) stream.Dispose();
        base.Dispose(disposing);
    }

}
