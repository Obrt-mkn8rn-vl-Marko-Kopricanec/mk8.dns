using System.Buffers.Binary;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class RrsetReadBoundTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{

    [Fact]
    public async Task OversizedReadFailsExplicitlyInsteadOfReturningAPartialRrset()
    {
        var fixture = new RecordManagementFixture(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var lifetime = fixture.ConfigureAwait(true);
        var owner = DnsName.Parse("bulk.example.").ToWire();
        var records = Enumerable.Range(0, 513).Select(index => new ZoneRecordData(owner, 65280, 300, Data(index))).ToArray();
        await fixture.InitializeAsync(records).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<ArgumentException>(() => fixture.Application.ExecuteAsync(fixture.Read("bulk.example.", 65280), CancellationToken.None).AsTask()).ConfigureAwait(true);
        var snapshot = await fixture.SnapshotAsync().ConfigureAwait(true);
        Assert.Equal(1L, snapshot.Revision);
    }

    private static byte[] Data(int index)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, checked((ushort)index));
        return result;
    }
}
