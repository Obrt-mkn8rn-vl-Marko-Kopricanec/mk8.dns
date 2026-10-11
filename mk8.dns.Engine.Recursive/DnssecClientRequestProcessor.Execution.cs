using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientRequestProcessor
{
    private async ValueTask<DnssecClientReply> ExecuteAsync(byte[] request, bool tcp, CancellationToken token)
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        try
        {
            token.ThrowIfCancellationRequested();
            lock (gate) if (closing) return new DnssecClientReply(DnssecClientReplyOutcome.Closed, []);
            DnsQuery query;
            try { query = DnsMessageCodec.DecodeQuery(request); }
            catch (FormatException) { return Deliver(new DnssecClientReply(DnssecClientReplyOutcome.Malformed, DnsMessageCodec.EncodeError(request, 1))); }
            catch (NotSupportedException) { return Deliver(new DnssecClientReply(DnssecClientReplyOutcome.Unsupported, DnsMessageCodec.EncodeError(request, 4))); }
            if ((query.Flags & ~0x0130) != 0)
                return Deliver(Error(query, tcp, DnssecClientReplyOutcome.Malformed, 1));
            if (query.Question is not { Class: 1 } question || query.EdnsVersion != 0 || query.GetCookieWire() is not null
                || (query.Flags & 0x0010) != 0 || question.Type is 0 or 41 or 46 or >= 249 and <= 255
                || question.Name.ToWire() is [1, 42, ..])
            {
                return Deliver(Error(query, tcp, DnssecClientReplyOutcome.Unsupported, 4));
            }
            if ((query.Flags & 0x0100) == 0 || !source.TryBeginClientQuery(question, out var revision))
                return Deliver(Error(query, tcp, DnssecClientReplyOutcome.Refused, 5));
            var result = await source.ResolveDnssecAsync(question, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (!source.TryEncodeClientReply(query, result, revision, tcp, policy.AuthenticatedDataAllowed, out var encoded)
                || (requireCompleteTcp && tcp && !DnssecClientTcpMessageCodec.IsComplete(encoded)))
            {
                return Deliver(Error(query, tcp, DnssecClientReplyOutcome.Failure, 2));
            }
            token.ThrowIfCancellationRequested();
            return Deliver(new DnssecClientReply(DnssecClientReplyOutcome.Encoded, encoded, revision));
        }
        finally { Release(); }
    }

    private static DnssecClientReply Error(DnsQuery query, bool tcp, DnssecClientReplyOutcome outcome, byte code)
    {
        var encoded = DnsMessageCodec.EncodeResponse(query, new DnsAnswer(code, authoritative: false, [], [], []), tcp);
        // Availability is explicit for this admitted validating-only profile.
        // No failed, unsupported, unsigned-marker or refused result receives AD.
        var flags = BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(2));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(2), (ushort)((flags | 0x0080) & ~0x0020));
        return new DnssecClientReply(outcome, encoded);
    }
}
