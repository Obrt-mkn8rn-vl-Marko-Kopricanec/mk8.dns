using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal static class CompleteTcpFixture
{
    internal static DnsQuestion Question => ClientProofFixture.Question(type: 16);

    internal static void Install(ClientProofEpochFixture fixture, int count)
    {
        var records = Records(count);
        var signature = DnssecRrsetSigner.Sign(records, fixture.Anchors.Keys.Key(fixture.Anchors.Keys.A),
            fixture.Anchors.Keys.A, DnssecFixture.Verifier, new DnssecSignatureWindow(99, 10000));
        fixture.Override = (question, server, _) => ValueTask.FromResult(question.Type == 48
            ? fixture.Anchors.Reply(question, server) : fixture.Anchors.Reply(question, server, answers: [.. records, signature]));
    }

    internal static DnsRecord[] Records(int count)
    {
        // Distinct finite TXT vectors exercise wire limits, not service configuration.
        return [.. Enumerable.Range(0, count).Select(index =>
        {
            var text = new byte[240]; text[0] = 239;
            BinaryPrimitives.WriteUInt16BigEndian(text.AsSpan(1), checked((ushort)index));
            return new DnsRecord(Question.Name, 16, 300, text);
        })];
    }

    internal static DnssecClientRequestProcessor Processor(ClientProofEpochFixture fixture, int requests = 64)
        => DnssecClientRequestProcessor.CreateWithCompleteTcpAnswers(fixture.Resolver,
            new DnssecClientAccessPolicy([new DnssecClientNetwork([192, 0, 2, 0], 24)], authenticatedDataAllowed: true), requests);
}
