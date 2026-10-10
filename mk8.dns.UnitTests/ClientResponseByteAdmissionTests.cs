using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientResponseByteAdmissionTests
{
    [Fact]
    public async Task ProofBytesAndAliasDataShareTheCompleteExpandedOutputBound()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Clear();
        // Finite reserved-name/material vectors; no network or deployment assignments.
        var suffix = string.Join('.', new string('b', 63), new string('c', 63), new string('d', 48), "example");
        var alias = DnsName.Parse(new string('a', 63) + "." + suffix + ".");
        var target = DnsName.Parse(new string('z', 63) + "." + suffix + ".");
        Assert.Equal(250, target.ToWire().Length);
        fixture.RootRecords.Add(new DnsRecord(alias, 5, 300, target.ToWire()));
        for (var record = 0; record < 16; record++)
        {
            var data = new byte[65_231];
            for (var offset = 0; offset < data.Length;)
            {
                var size = Math.Min(255, data.Length - offset - 1);
                data[offset] = (byte)size; offset += size + 1;
            }
            data[^1] = (byte)record;
            fixture.RootRecords.Add(new DnsRecord(target, 16, 300, data));
        }
        var question = new DnsQuestion(alias, 16, 1);
        var ordinary = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, ordinary.Outcome);
        var dataBytes = ordinary.Answers.Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length);
        Assert.InRange(dataBytes, 1_048_000L, DnsUpstreamEvidence.MaximumExpandedBytes);
        var complete = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, complete.Outcome);
        Assert.Null(complete.ClientProof);
        Assert.Empty(complete.Answers);
        Assert.False(DnssecClientResponseProjection.TryPrepare(complete, question, dnssecOk: true, out var snapshot));
        Assert.Null(snapshot);
    }
}
