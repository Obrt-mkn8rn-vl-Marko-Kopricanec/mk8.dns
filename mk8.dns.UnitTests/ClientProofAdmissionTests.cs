using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofAdmissionTests
{
    [Theory]
    [InlineData(509, DnssecResolutionOutcome.Authenticated)]
    [InlineData(510, DnssecResolutionOutcome.Failure)]
    public async Task CompleteAliasDataPlusSignaturesShareTheOutputRecordBound(int count, DnssecResolutionOutcome expected)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Clear();
        var question = ClientProofFixture.Question("alias.example.");
        fixture.RootRecords.Add(new DnsRecord(question.Name, 5, 300, DnsName.Parse("www.example.").ToWire()));
        // Distinct finite RFC5737 vectors; none is a deployment address or network target.
        for (var index = 0; index < count; index++)
        {
            byte[] address = index < 256 ? [192, 0, 2, (byte)index] : [198, 51, 100, (byte)(index - 256)];
            fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("www.example."), 1, 300, address));
        }
        var ordinary = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, ordinary.Outcome);
        Assert.Equal(count + 1, ordinary.Answers.Count);
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(expected, result.Outcome);
        if (expected == DnssecResolutionOutcome.Failure)
        {
            Assert.Null(result.ClientProof); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        }
        else
        {
            var proof = ClientProofFixture.Proof(result);
            Assert.Equal(512, result.Answers.Count + proof.AnswerSignatures.Count);
        }
    }

    [Fact]
    public async Task CancellationAfterAnAliasProofKeepsActualIgnoringTargetWorkOwned()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question("alias.example.");
        fixture.RootRecords.Add(new DnsRecord(question.Name, 5, 300, DnsName.Parse("www.example.").ToWire()));
        using var cancellation = new CancellationTokenSource();
        var completion = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (actual, server, _) =>
        {
            if (actual.Equals(ClientProofFixture.Question()))
            {
                entered.TrySetResult(); return new ValueTask<DnsUpstreamEvidence>(completion.Task);
            }
            return ValueTask.FromResult(fixture.Default(actual, server));
        };
        var operation = ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, cancellation.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None);
            await cancellation.CancelAsync();
            Assert.False(operation.IsCompleted);
        }
        finally
        {
            completion.TrySetResult(fixture.Default(ClientProofFixture.Question(), OnlineDnssecFixture.RootServer));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None));
        }
    }
}
