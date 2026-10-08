using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineNsec3ProvenanceTests
{
    [Theory]
    [InlineData("mixed")]
    [InlineData("signature")]
    [InlineData("labels")]
    [InlineData("iterations")]
    [InlineData("hash")]
    [InlineData("salt")]
    [InlineData("foreign-owner")]
    [InlineData("foreign-soa")]
    [InlineData("missing-soa")]
    [InlineData("missing-denial")]
    public async Task InvalidOrMixedCorrelatedEvidenceCannotBecomeAuthenticatedDenial(string mode)
    {
        ArgumentNullException.ThrowIfNull(mode);
        using var fixture = new OnlineNsec3Fixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type == 48) return reply;
            var material = reply.Authority.ToList();
            var proof = material.First(record => record.Type == 50);
            if (mode is "mixed")
            {
                var nsec = OnlineDnssecFixture.Nsec(DnsName.Parse("example."), DnsName.Parse("z.example."), 2, 6, 48);
                material.Add(nsec); material.Add(fixture.Sign(nsec));
            }
            else if (mode is "signature" or "labels")
            {
                var index = material.FindIndex(record => record.Type == 46 && record.Owner.Equals(proof.Owner));
                var bytes = material[index].GetData();
                if (mode is "labels") bytes[3]--;
                else bytes[^1] ^= 1;
                material[index] = new DnsRecord(material[index].Owner, 46, 300, bytes);
            }
            else if (mode is "missing-soa" or "missing-denial")
                material.RemoveAll(record => record.Type == (mode is "missing-soa" ? 6 : 50));
            else if (mode is "foreign-soa")
            {
                var index = material.FindIndex(record => record.Type == 6);
                material[index] = material[index].WithOwner(DnsName.Parse("other.example."));
            }
            else
            {
                var index = material.IndexOf(proof); var bytes = proof.GetData();
                if (mode is "iterations") bytes[3] = 1;
                else if (mode is "hash") bytes[0] = 2;
                else if (mode is "salt") bytes = [1, 0, 0, 0, 1, 99, .. bytes.AsSpan(5).ToArray()];
                var damaged = mode is "foreign-owner" ? proof.WithOwner(DnsName.Parse("foreign.example.")) : new DnsRecord(proof.Owner, 50, 300, bytes);
                material[index] = damaged;
                material.RemoveAll(record => record.Type == 46 && record.Owner.Equals(proof.Owner));
                material.Add(fixture.Sign(damaged)); // Valid MAC cannot legitimize wrong NSEC3 parameters/ownership.
            }
            return OnlineDnssecFixture.Copy(reply, authority: material.ToArray());
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question("missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ForgedParentAbsenceDoesNotFetchUnsignedChild(bool optOut)
    {
        using var fixture = new OnlineNsec3Fixture { Unsigned = true, OptOut = optOut };
        fixture.Transform = reply => reply.Question.Type == 43 ? OnlineDnssecFixture.Copy(reply, authority: reply.Authority.Select(record =>
        {
            if (record.Type != 46 || BinaryPrimitives.ReadUInt16BigEndian(record.GetData()) != 50) return record;
            var bytes = record.GetData(); bytes[^1] ^= 1;
            return new DnsRecord(record.Owner, 46, record.Ttl, bytes);
        }).ToArray()) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question("www.child.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }

    [Fact]
    public async Task Nsec3DataInAdditionalDoesNotAcquireDenialAuthority()
    {
        using var fixture = new OnlineNsec3Fixture();
        fixture.Transform = reply => reply.Question.Type == 48 ? reply : OnlineDnssecFixture.Copy(reply,
            authority: reply.Authority.Where(record => record.Type == 6 || record.Owner.Equals(DnsName.Parse("example."))).ToArray(),
            additional: reply.Authority.Where(record => record.Type != 6 && !record.Owner.Equals(DnsName.Parse("example."))).ToArray());
        var result = await fixture.Resolver().ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question("missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
    }

    [Fact]
    public async Task SignedChildNegativeCannotBeSubstitutedByParentHashProofs()
    {
        using var fixture = new OnlineNsec3Fixture();
        fixture.Transform = reply =>
        {
            if (!reply.Server.Equals(OnlineDnssecFixture.ChildServer) || reply.Question.Type == 48) return reply;
            var root = fixture.Ring();
            return OnlineDnssecFixture.Copy(reply, authority: [.. reply.Authority.Where(record => record.Type == 6 || record.Owner.Equals(DnsName.Parse("child.example."))),
                .. root, .. root.Select(record => fixture.Sign(record))]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(OnlineNsec3ResolutionTests.Question("missing.child.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
    }
}
