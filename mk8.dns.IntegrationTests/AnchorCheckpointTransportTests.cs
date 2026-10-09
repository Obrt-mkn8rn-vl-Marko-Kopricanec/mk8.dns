using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class AnchorCheckpointTransportTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    public async Task RecoveredExpiredPendingKeyRequiresFreshCorrelatedAuthentication(bool ipv6, bool tcpFallback, bool corrupt)
    {
        using var key = EcdsaP256DnssecSigningKey.Create();
        using var next = EcdsaP256DnssecSigningKey.Create();
        var origin = DnsName.Parse("example.");
        var verifier = new EcdsaP256DnssecVerifier();
        DnsRecord[] records = [DnssecKeys.CreateDnskey(origin, 3600, key.GetPublicKey()), DnssecKeys.CreateDnskey(origin, 3600, next.GetPublicKey())];
        var clock = new RecoveryClock();
        var tracker = Recover(origin, records, key, verifier, clock);
        var signature = DnssecRrsetSigner.Sign(records, records[0], key, verifier,
            new DnssecSignatureWindow((uint)clock.Seconds - 1, (uint)clock.Seconds + 10_000));
        signature = Corrupt(signature, corrupt);
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var pair = DnssecUpstreamFixture.BindPair(ipv6); using var udp = pair.Udp; using var tcp = pair.Tcp;
        var endpoint = DnssecUpstreamFixture.Endpoint(udp);
        var question = new DnsQuestion(origin, 48, 1);
        var worker = Task.Run(async () =>
        {
            var datagram = await udp.ReceiveAsync(closure.Token).ConfigureAwait(true);
            var request = DnsMessageCodec.DecodeQuery(datagram.Buffer);
            Assert.Equal(question, request.Question); Assert.True(request.DnssecOk);
            if (!tcpFallback)
                await udp.SendAsync(Reply(datagram.Buffer, [.. records, signature]), datagram.RemoteEndPoint, closure.Token).ConfigureAwait(true);
            else
            {
                var truncated = Reply(datagram.Buffer, []); truncated[2] |= 2;
                await udp.SendAsync(truncated, datagram.RemoteEndPoint, closure.Token).ConfigureAwait(true);
                using var peer = await tcp.AcceptTcpClientAsync(closure.Token).ConfigureAwait(true); using var stream = peer.GetStream();
                var frame = await DnssecUpstreamFixture.ReadFrameAsync(stream, closure.Token).ConfigureAwait(true);
                Assert.Equal(datagram.Buffer, frame);
                await DnssecUpstreamFixture.SendFrameAsync(stream, Reply(frame, [.. records, signature]), closure.Token).ConfigureAwait(true);
            }
        }, closure.Token);
        try
        {
            var client = new DnssecUpstreamClient(peer => peer.Equals(endpoint), TimeSpan.FromSeconds(3));
            var response = await client.ExchangeDnssecAsync(question, endpoint, closure.Token).ConfigureAwait(true);
            Assert.True(response.AuthenticatedDataObserved);
            Assert.True(tracker.TryCapture(response.Answers.Where(record => record.Type == 48).ToArray(),
                response.Answers.Where(record => record.Type == 46).ToArray(), out var observation));
            Assert.Equal(!corrupt, tracker.TryApply(observation));
            AssertRecoveredState(tracker, records[1], corrupt);
        }
        finally
        {
            await closure.CancelAsync().ConfigureAwait(true);
            try { await worker.ConfigureAwait(true); }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
    }

    private static void AssertRecoveredState(DnssecTrustAnchorTracker tracker, DnsRecord pending, bool corrupt)
    {
        Assert.Equal(corrupt ? 1 : 2, tracker.GetTrustAnchors().Count);
        Assert.Equal(corrupt ? DnssecAnchorState.AddPending : DnssecAnchorState.Valid,
            Assert.Single(tracker.GetStatus(), state => state.Key.GetData().SequenceEqual(pending.GetData())).State);
    }

    private static DnssecTrustAnchorTracker Recover(DnsName origin, DnsRecord[] records,
        EcdsaP256DnssecSigningKey key, EcdsaP256DnssecVerifier verifier, RecoveryClock clock)
    {
        var tracker = new DnssecTrustAnchorTracker(origin, [records[0]], verifier, clock);
        var initial = DnssecRrsetSigner.Sign(records, records[0], key, verifier, new DnssecSignatureWindow(99, 10_000));
        Assert.True(tracker.TryCapture(records, [initial], out var first));
        Assert.True(tracker.TryApply(first));
        clock.Seconds += 2_592_000;
        tracker = DnssecTrustAnchorTracker.RestoreCheckpoint(origin, tracker.CreateCheckpoint(), verifier, clock);
        Assert.Single(tracker.GetTrustAnchors());
        Assert.Equal(TimeSpan.Zero, Assert.Single(tracker.GetStatus(), state => state.State == DnssecAnchorState.AddPending).AddHoldDownRemaining);
        return tracker;
    }

    private static DnsRecord Corrupt(DnsRecord signature, bool corrupt)
    {
        if (!corrupt) return signature;
        var data = signature.GetData(); data[^1] ^= 1;
        return new DnsRecord(signature.Owner, 46, signature.Ttl, data);
    }

    private static byte[] Reply(byte[] request, DnsRecord[] records)
    {
        var end = 12;
        while (request[end] != 0) end += request[end] + 1;
        end += 5;
        using var output = new MemoryStream();
        var header = request.AsSpan(0, end).ToArray();
        DnssecUpstreamFixture.Write16(header, 2, 0x8430);
        DnssecUpstreamFixture.Write16(header, 6, (ushort)records.Length);
        DnssecUpstreamFixture.Write16(header, 8, 0); DnssecUpstreamFixture.Write16(header, 10, 0);
        output.Write(header);
        foreach (var record in records)
        {
            output.Write(record.Owner.ToWire());
            var fields = new byte[10]; var data = record.GetData();
            BinaryPrimitives.WriteUInt16BigEndian(fields, record.Type); BinaryPrimitives.WriteUInt16BigEndian(fields.AsSpan(2), 1);
            BinaryPrimitives.WriteUInt32BigEndian(fields.AsSpan(4), record.Ttl); BinaryPrimitives.WriteUInt16BigEndian(fields.AsSpan(8), (ushort)data.Length);
            output.Write(fields); output.Write(data);
        }
        return output.ToArray();
    }

    private sealed class RecoveryClock : TimeProvider
    {
        internal long Seconds { get; set; } = 100;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => (Seconds - 100) * TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Seconds);
    }
}
