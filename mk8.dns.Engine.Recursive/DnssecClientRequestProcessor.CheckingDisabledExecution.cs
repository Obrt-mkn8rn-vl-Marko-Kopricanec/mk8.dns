using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientRequestProcessor
{
    private async ValueTask<DnssecClientReply> ExecuteCheckingDisabledAsync(DnsQuery query, DnsQuestion question, bool tcp,
        NonValidatingIterativeResolver resolver, DnssecResolutionClock clock, CancellationToken token)
    {
        // Include actual acquisition/provider time; returned records are unvalidated.
        var received = (Timestamp: clock.GetTimestamp(), Wall: clock.GetUtcNow());
        var answer = await resolver.ResolveAsync(question, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if (answer.ResponseCode is not (0 or 3 or 6))
            return Deliver(Error(query, tcp, DnssecClientReplyOutcome.Failure, 2));
        var records = answer.Answers.Concat(answer.Authority).Concat(answer.Additional).ToArray();
        if (records.Length > DnsUpstreamEvidence.MaximumRecords
            || records.Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length) > DnsUpstreamEvidence.MaximumExpandedBytes)
        {
            return Deliver(Error(query, tcp, DnssecClientReplyOutcome.Failure, 2));
        }
        var elapsed = Elapsed(clock, received);
        var selected = new DnsAnswer(answer.ResponseCode, authoritative: false,
            AgeUnchecked(answer.Answers, elapsed), AgeUnchecked(answer.Authority, elapsed), AgeUnchecked(answer.Additional, elapsed));
        var message = DnsMessageCodec.EncodeResponse(query, selected, tcp);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(2));
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), (ushort)((flags | 0x0080) & ~0x0020));
        token.ThrowIfCancellationRequested();
        if (Elapsed(clock, received) > elapsed || (requireCompleteTcp && tcp && !DnssecClientTcpMessageCodec.IsComplete(message)))
            return Deliver(Error(query, tcp, DnssecClientReplyOutcome.Failure, 2));
        return Deliver(new DnssecClientReply(DnssecClientReplyOutcome.CheckingDisabled, message));
    }

    private static double Elapsed(DnssecResolutionClock clock, (long Timestamp, DateTimeOffset Wall) received)
        => Math.Ceiling(Math.Max(Math.Max(0, clock.GetElapsedTime(received.Timestamp, clock.GetTimestamp()).TotalSeconds),
            Math.Max(0, (clock.GetUtcNow() - received.Wall).TotalSeconds)));

    private static DnsRecord[] AgeUnchecked(IReadOnlyList<DnsRecord> records, double elapsed)
        => [.. records.Select(record => record.WithTtl(elapsed >= record.Ttl ? 0 : record.Ttl - (uint)elapsed))];
}
