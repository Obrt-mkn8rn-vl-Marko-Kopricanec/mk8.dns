using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OperationCutDependencyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AFailureCannotForgetAuthenticatedProviderCutForAaaaFallback(bool failKeys)
    {
        using var fixture = new OperationCutDependencyFixture { FailProviderKeys = failKeys };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutDependencyFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OperationCutDependencyFixture.Child));
    }

    [Fact]
    public async Task AuthenticatedUnsignedProviderCutSurvivesSeparateAddressFamilySearch()
    {
        using var fixture = new OperationCutDependencyFixture { UnsignedProvider = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutDependencyFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority); Assert.Null(result.UnsignedDelegation);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OperationCutDependencyFixture.Child));
    }

    [Fact]
    public async Task SameProviderCutAllowsActualChildAuthenticatedAaaaFallback()
    {
        using var fixture = new OperationCutDependencyFixture { ParentAddress = false };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutDependencyFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(7U, result.AuthenticatedTtl); Assert.Equal(OperationCutDependencyFixture.Question.Name, Assert.Single(result.Answers).Owner);
        Assert.Contains(fixture.Calls, call => call.Server.Equals(OperationCutDependencyFixture.Provider) && call.Question.Type == 28);
    }

    [Fact]
    public async Task UnauthenticatedProviderDsCannotEstablishAnAddressCut()
    {
        using var fixture = new OperationCutDependencyFixture { CorruptProviderDs = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutDependencyFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Contains(fixture.Calls, call => call.Server.Equals(OperationCutDependencyFixture.Child));
    }
}
