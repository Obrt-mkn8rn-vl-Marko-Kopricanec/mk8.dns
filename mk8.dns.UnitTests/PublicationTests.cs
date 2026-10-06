using System.Security.Cryptography;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class PublicationTests
{
    [Fact]
    public async Task PrepareDoesNotActivateAndDuplicateActivationIsIdempotent()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var request = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        var reply = await publisher.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal("prepared", reply.State);
        Assert.Null(await fixture.Store.ReadActiveAsync(PublicationFixture.ZoneId, CancellationToken.None).ConfigureAwait(true));
        Assert.False((await fixture.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        var activation = fixture.Activate(request.PublicationId);
        var first = await publisher.ExecuteAsync(activation, CancellationToken.None).ConfigureAwait(true);
        var second = await publisher.ExecuteAsync(activation, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(first, second);
        Assert.Equal("activated", first.State);
        Assert.True((await fixture.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        var wire = await fixture.Authority.ExchangeAsync(AuthorityFixture.Query(), false, new byte[] { 127, 0, 0, 1 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(new byte[] { 192, 0, 2, 1 }, wire[^4..]);
        Assert.False(File.Exists(Path.Combine(fixture.Root, "state", PublicationFixture.ZoneId.ToString("N"), "previous.json")));
    }

    [Theory]
    [InlineData("body")]
    [InlineData("signature")]
    [InlineData("identity")]
    public async Task ForgedPrepareCannotChangeStorage(string changed)
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var request = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        var body = request.Body.ToArray();
        var signature = request.Signature.ToArray();
        if (string.Equals(changed, "body", StringComparison.Ordinal))
            body[^1] ^= 1;
        if (string.Equals(changed, "signature", StringComparison.Ordinal))
            signature[0] ^= 1;
        request = request with { Body = body, Signature = signature, PublicationId = string.Equals(changed, "identity", StringComparison.Ordinal) ? new string('0', 64) : request.PublicationId };
        if (string.Equals(changed, "identity", StringComparison.Ordinal))
            _ = await Assert.ThrowsAsync<ArgumentException>(() => publisher.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        else
            _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => publisher.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0u, await fixture.Store.CountActiveAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Single(Directory.GetFileSystemEntries(Path.Combine(fixture.Root, "proofs")));
    }

    [Fact]
    public async Task ActivationRequiresItsOwnSignatureAndPreparedContents()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        var wrongPurpose = fixture.Activate(prepared.PublicationId) with { Signature = prepared.Signature };
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => publisher.ExecuteAsync(wrongPurpose, CancellationToken.None).AsTask()).ConfigureAwait(true);
        var missing = fixture.Activate(new string('1', 64));
        _ = await Assert.ThrowsAsync<IOException>(() => publisher.ExecuteAsync(missing, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Null(await fixture.Store.ReadActiveAsync(PublicationFixture.ZoneId, CancellationToken.None).ConfigureAwait(true));
    }

    [Theory]
    [InlineData("epoch")]
    [InlineData("node")]
    [InlineData("zone")]
    [InlineData("origin")]
    [InlineData("key")]
    public async Task ConfiguredTrustRejectsOtherPublisherScopes(string changed)
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var id = string.Equals(changed, "zone", StringComparison.Ordinal) ? Guid.NewGuid() : PublicationFixture.ZoneId;
        var origin = DnsName.Parse(string.Equals(changed, "origin", StringComparison.Ordinal) ? "other." : "example.");
        using var verifier = new P256PublicationAuthenticator(string.Equals(changed, "epoch", StringComparison.Ordinal) ? Guid.NewGuid() : PublicationFixture.Epoch,
            string.Equals(changed, "node", StringComparison.Ordinal) ? "other-node" : PublicationFixture.Node,
            new Dictionary<Guid, DnsName> { [id] = origin }, string.Equals(changed, "key", StringComparison.Ordinal) ? otherKey.ExportSubjectPublicKeyInfoPem() : fixture.PublicKey, canSign: false);
        var request = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(request.Body.Span, request.Signature.Span));
    }

    [Fact]
    public async Task ReplicaCannotImportPrivatePublisherKeyOrSign()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var scope = new Dictionary<Guid, DnsName> { [PublicationFixture.ZoneId] = DnsName.Parse("example.") };
        _ = Assert.Throws<ArgumentException>(() => new P256PublicationAuthenticator(PublicationFixture.Epoch, PublicationFixture.Node, scope, key.ExportPkcs8PrivateKeyPem(), canSign: false));
        _ = Assert.Throws<InvalidOperationException>(() => fixture.Verifier.Sign("body"u8));
    }

    [Theory]
    [InlineData("incomplete-marker")]
    [InlineData("mixed-key-blocks")]
    public async Task PublicKeyProfileRejectsPrivateKeyWithMisleadingPublicMarker(string layout)
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = key.ExportPkcs8PrivateKeyPem();
        var pem = string.Equals(layout, "incomplete-marker", StringComparison.Ordinal)
            ? privateKey + "\n-----BEGIN PUBLIC KEY-----"
            : fixture.PublicKey + "\n" + privateKey;
        var scope = new Dictionary<Guid, DnsName> { [PublicationFixture.ZoneId] = DnsName.Parse("example.") };
        _ = Assert.Throws<ArgumentException>(() => new P256PublicationAuthenticator(PublicationFixture.Epoch, PublicationFixture.Node, scope, pem, canSign: false));
    }

    [Fact]
    public async Task SignedPayloadStillRequiresAuthoritativeAdmission()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var valid = PublicationFixture.Snapshot(1, 1);
        var malformed = new ZoneSnapshot(valid.ZoneId, valid.Origin, valid.Revision, valid.Serial, "bad bundle"u8);
        var request = fixture.Prepare(malformed);
        _ = await Assert.ThrowsAsync<FormatException>(() => publisher.ExecuteAsync(request, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0u, await fixture.Store.CountActiveAsync(CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task OlderGenerationCannotReplaceAnActivatedGeneration()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var old = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        var newer = fixture.Prepare(PublicationFixture.Snapshot(2, 2, 2));
        _ = await publisher.ExecuteAsync(old, CancellationToken.None).ConfigureAwait(true);
        _ = await publisher.ExecuteAsync(newer, CancellationToken.None).ConfigureAwait(true);
        _ = await publisher.ExecuteAsync(fixture.Activate(newer.PublicationId), CancellationToken.None).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => publisher.ExecuteAsync(old, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => publisher.ExecuteAsync(fixture.Activate(old.PublicationId), CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(2L, (await fixture.Store.ReadActiveAsync(PublicationFixture.ZoneId, CancellationToken.None).ConfigureAwait(true))!.Revision);
    }

    [Fact]
    public async Task QueriesPinOneCatalogDuringReplacement()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var old = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await publisher.ExecuteAsync(old, CancellationToken.None).ConfigureAwait(true);
        _ = await publisher.ExecuteAsync(fixture.Activate(old.PublicationId), CancellationToken.None).ConfigureAwait(true);
        var query = AuthorityFixture.Query();
        var peer = new byte[] { 127, 0, 0, 1 };
        var before = await fixture.Authority.ExchangeAsync(query, false, peer, CancellationToken.None).ConfigureAwait(true);
        var newer = fixture.Prepare(PublicationFixture.Snapshot(2, 2, 2));
        _ = await publisher.ExecuteAsync(newer, CancellationToken.None).ConfigureAwait(true);
        var update = publisher.ExecuteAsync(fixture.Activate(newer.PublicationId), CancellationToken.None).AsTask();
        var results = new List<byte[]>();
        for (var index = 0; index < 1000; index++)
            results.Add(await fixture.Authority.ExchangeAsync(query, false, peer, CancellationToken.None).ConfigureAwait(true));
        _ = await update.ConfigureAwait(true);
        var after = await fixture.Authority.ExchangeAsync(query, false, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.NotEqual(before, after);
        Assert.All(results, result => Assert.True(result.AsSpan().SequenceEqual(before) || result.AsSpan().SequenceEqual(after)));
    }

    [Fact]
    public async Task RestartRequiresMatchingPublisherProof()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        _ = await publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).ConfigureAwait(true);
        await publisher.DisposeAsync().ConfigureAwait(true);
        var reopened = await fixture.OpenAsync().ConfigureAwait(true);
        await reopened.DisposeAsync().ConfigureAwait(true);
        Assert.True((await fixture.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        var proof = Path.Combine(fixture.Root, "proofs", prepared.PublicationId + ".pub");
        var bytes = await File.ReadAllBytesAsync(proof).ConfigureAwait(true);
        bytes[^1] ^= 1;
        await File.WriteAllBytesAsync(proof, bytes).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => fixture.OpenAsync().AsTask()).ConfigureAwait(true);
        File.Delete(proof);
        _ = await Assert.ThrowsAsync<IOException>(() => fixture.OpenAsync().AsTask()).ConfigureAwait(true);
        Assert.Equal(1L, (await fixture.Store.ReadActiveAsync(PublicationFixture.ZoneId, CancellationToken.None).ConfigureAwait(true))!.Revision);
    }

    [Fact]
    public async Task PreparedSignatureAloneCannotAuthorizeServingAfterRestart()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        var snapshot = PublicationFixture.Snapshot(1, 1);
        _ = await publisher.ExecuteAsync(fixture.Prepare(snapshot), CancellationToken.None).ConfigureAwait(true);
        await publisher.DisposeAsync().ConfigureAwait(true);
        // Model an interrupted/externally written active pointer without its separate activation authorization.
        await fixture.Store.ActivateAsync(snapshot, CancellationToken.None).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<IOException>(() => fixture.OpenAsync().AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Authority.GetStatusAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
    }

    [Fact]
    public async Task DisposalDrainsAdmittedPublicationAndClosesQueuedWork()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fixture = new PublicationFixture(async _ =>
        {
            entered.SetResult();
            await resume.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
        });
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        var activation = publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
        var queued = publisher.ExecuteAsync(prepared, CancellationToken.None).AsTask();
        var disposal = publisher.DisposeAsync().AsTask();
        Assert.False(disposal.IsCompleted);
        _ = await Assert.ThrowsAsync<ObjectDisposedException>(() => publisher.ExecuteAsync(prepared, CancellationToken.None).AsTask()).ConfigureAwait(true);
        resume.SetResult();
        Assert.Equal("activated", (await activation.ConfigureAwait(true)).State);
        _ = await Assert.ThrowsAsync<ObjectDisposedException>(() => queued.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        await disposal.ConfigureAwait(true);
    }

    [Fact]
    public async Task StorageFailureSuspendsServingUntilVerifiedRestart()
    {
        var fixture = new PublicationFixture(_ => throw new IOException("injected durability failure"));
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<IOException>(() => publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Authority.GetStatusAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        var reply = await fixture.Authority.ExchangeAsync(AuthorityFixture.Query(), false, new byte[] { 127, 0, 0, 1 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, reply[3] & 15);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).AsTask()).ConfigureAwait(true);
    }

    [Fact]
    public async Task SurvivingActivationReceiptRejectsCompleteSnapshotRootLossOnRestart()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(2, 2));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        _ = await publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).ConfigureAwait(true);
        await publisher.DisposeAsync().ConfigureAwait(true);
        await fixture.Store.DisposeAsync().ConfigureAwait(true);
        var path = Path.Combine(fixture.Root, "state");
        Directory.Delete(path, recursive: true);
        var empty = new FileZoneSnapshotStore(path);
        await using var emptyLifetime = empty.ConfigureAwait(true);
        var authority = new AuthoritativeApplication(new DnsMessageCodecAdapter(), PublicationFixture.Node);
        _ = await Assert.ThrowsAsync<InvalidDataException>(() => ZonePublicationApplication.OpenAsync(empty, fixture.Journal, fixture.Verifier, new ZoneBundleAdapter(), authority, PublicationFixture.Node, [PublicationFixture.ZoneId], CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => authority.GetStatusAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0u, await empty.CountActiveAsync(CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task RunningReplicaCannotForgetItsGenerationWhenZoneDirectoryDisappears()
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(2, 2));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        _ = await publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).ConfigureAwait(true);
        Directory.Delete(Path.Combine(fixture.Root, "state", PublicationFixture.ZoneId.ToString("N")), recursive: true);
        var older = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await Assert.ThrowsAsync<InvalidDataException>(() => publisher.ExecuteAsync(older, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Authority.GetStatusAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.False(Directory.Exists(Path.Combine(fixture.Root, "state", PublicationFixture.ZoneId.ToString("N"))));
    }

    [Theory]
    [InlineData("pub")]
    [InlineData("act")]
    public async Task TamperedRetainedPublisherProofOrAcknowledgementSuspendsServing(string extension)
    {
        var fixture = new PublicationFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        await using var lifetime = publisher.ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        _ = await publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).ConfigureAwait(true);
        var path = Path.Combine(fixture.Root, "proofs", prepared.PublicationId + "." + extension);
        var contents = await File.ReadAllBytesAsync(path).ConfigureAwait(true);
        contents[^1] ^= 1;
        await File.WriteAllBytesAsync(path, contents).ConfigureAwait(true);
        if (string.Equals(extension, "pub", StringComparison.Ordinal))
            _ = await Assert.ThrowsAsync<InvalidDataException>(() => publisher.ExecuteAsync(prepared, CancellationToken.None).AsTask()).ConfigureAwait(true);
        else
            _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Authority.GetStatusAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(1L, (await fixture.Store.ReadActiveAsync(PublicationFixture.ZoneId, CancellationToken.None).ConfigureAwait(true))!.Revision);
    }
}
