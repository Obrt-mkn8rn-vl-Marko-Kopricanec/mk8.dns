using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;

namespace Mk8.Dns.IntegrationTests;

internal sealed class RsaDnssecWireFixture : IDisposable
{
    private readonly RSA rsa = RSA.Create(1024);
    private readonly EcdsaP256DnssecSigningKey ecdsa = EcdsaP256DnssecSigningKey.Create();
    internal RsaDnssecWireFixture()
    {
        var material = rsa.ExportParameters(false);
        Key = new DnsRecord(DnsName.Parse("example."), 48, 300, [1, 1, 3, 8, checked((byte)material.Exponent!.Length), .. material.Exponent, .. material.Modulus!]);
        ChildKey = DnssecKeys.CreateDnskey(DnsName.Parse("child.example."), 300, ecdsa.GetPublicKey());
    }

    internal DnsRecord Key { get; }
    internal DnsRecord ChildKey { get; }
    internal static DnssecSignatureVerifier Verifier { get; } = new();
    internal TimeProvider Clock { get; } = new FixedClock();
    private static DnssecSignatureWindow Window { get; } = new(99, 1000);

    internal byte[] Reply(byte[] query, DnsServerEndpoint child, bool childRole, bool corrupt)
    {
        var question = DnsMessageCodec.DecodeQuery(query).Question ?? throw new FormatException("Fixture requires one ordinary question.");
        var end = 12 + question.Name.ToWire().Length + 4;
        DnsRecord[] answers; DnsRecord[] authority = []; DnsRecord[] additional = []; var aa = true;
        var key = childRole ? ChildKey : Key;
        if (question.Type == 48)
            answers = [key, childRole ? DnssecRrsetSigner.Sign([key], ChildKey, ecdsa, Verifier, Window) : Sign([key])];
        else if (question.Type == 43)
        {
            var ds = DnssecKeys.CreateDs(ChildKey, 300); answers = [ds, Sign([ds])];
        }
        else if (!childRole)
        {
            answers = []; aa = false;
            var ns = DnsName.Parse("ns.child.example."); authority = [new DnsRecord(ChildKey.Owner, 2, 300, ns.ToWire())];
            var address = child.GetAddress(); additional = [new DnsRecord(ns, address.Length == 4 ? (ushort)1 : (ushort)28, 300, address)];
        }
        else
        {
            var record = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 43]);
            answers = [record, DnssecRrsetSigner.Sign([record], ChildKey, ecdsa, Verifier, Window)];
        }
        var packets = answers.Concat(authority).Concat(additional).Select(record => Encode(record, corrupt && (childRole || question.Type == 43))).ToArray();
        var result = new byte[end + packets.Sum(row => row.Length) + 11]; query.AsSpan(0, end).CopyTo(result);
        DnssecUpstreamFixture.Write16(result, 2, (ushort)(aa ? 0x8430 : 0x8030));
        DnssecUpstreamFixture.Write16(result, 6, (ushort)answers.Length); DnssecUpstreamFixture.Write16(result, 8, (ushort)authority.Length);
        DnssecUpstreamFixture.Write16(result, 10, (ushort)(additional.Length + 1));
        foreach (var row in packets) { row.CopyTo(result, end); end += row.Length; }
        DnssecUpstreamFixture.Write16(result, end + 1, 41); DnssecUpstreamFixture.Write16(result, end + 3, 1232);
        DnssecUpstreamFixture.Write16(result, end + 7, 0x8000); return result;
    }

    private DnsRecord Sign(DnsRecord[] records)
    {
        var first = records[0]; var header = new byte[18]; BinaryPrimitives.WriteUInt16BigEndian(header, first.Type);
        header[2] = 8; header[3] = (byte)first.Owner.LabelCount;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), 300); BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), Window.Expiration);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), Window.Inception); BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(16), DnssecKeys.KeyTag(Key));
        byte[] prefix = [.. header, .. Key.GetOwnerWire()]; byte[] data = [.. prefix, .. DnssecCanonical.GetRrset(records, 300, header[3])];
        return new DnsRecord(first.Owner, 46, 300, [.. prefix, .. rsa.SignHash(SHA256.HashData(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)]);
    }
    private static byte[] Encode(DnsRecord record, bool corrupt)
    {
        var name = record.GetOwnerWire(); var data = record.GetData(); if (corrupt && record.Type == 46) data[^1] ^= 1;
        var result = new byte[name.Length + 10 + data.Length]; name.CopyTo(result, 0);
        DnssecUpstreamFixture.Write16(result, name.Length, record.Type); DnssecUpstreamFixture.Write16(result, name.Length + 2, 1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(name.Length + 4), record.Ttl);
        DnssecUpstreamFixture.Write16(result, name.Length + 8, (ushort)data.Length); data.CopyTo(result, name.Length + 10); return result;
    }
    public void Dispose() { rsa.Dispose(); ecdsa.Dispose(); }

    internal sealed class Node : IAsyncDisposable
    {
        private readonly UdpClient udp;
        private readonly TcpListener tcp;
        private readonly CancellationTokenSource closure;
        private readonly bool forceTcp;
        private Task[] workers = [];
        internal Node(bool ipv6, bool forceTcp, CancellationToken token)
        {
            (udp, tcp) = DnssecUpstreamFixture.BindPair(ipv6); Server = DnssecUpstreamFixture.Endpoint(udp);
            closure = CancellationTokenSource.CreateLinkedTokenSource(token); this.forceTcp = forceTcp;
        }
        internal DnsServerEndpoint Server { get; }
        internal ConcurrentQueue<DnsQuestion> Requests { get; } = new();
        internal void Start(Func<byte[], byte[]> reply) => workers = [UdpAsync(reply), TcpAsync(reply)];
        private async Task UdpAsync(Func<byte[], byte[]> reply)
        {
            try
            {
                while (true)
                {
                    var request = await udp.ReceiveAsync(closure.Token).ConfigureAwait(false);
                    Requests.Enqueue(DnsMessageCodec.DecodeQuery(request.Buffer).Question!); var response = reply(request.Buffer);
                    if (forceTcp)
                    {
                        response = request.Buffer.ToArray(); DnssecUpstreamFixture.Write16(response, 2, 0x8630);
                        DnssecUpstreamFixture.Write16(response, 6, 0); DnssecUpstreamFixture.Write16(response, 8, 0);
                    }
                    await udp.SendAsync(response, request.RemoteEndPoint, closure.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
        private async Task TcpAsync(Func<byte[], byte[]> reply)
        {
            try
            {
                while (true)
                {
                    using var peer = await tcp.AcceptTcpClientAsync(closure.Token).ConfigureAwait(false); using var stream = peer.GetStream();
                    var request = await DnssecUpstreamFixture.ReadFrameAsync(stream, closure.Token).ConfigureAwait(false);
                    Requests.Enqueue(DnsMessageCodec.DecodeQuery(request).Question!);
                    await DnssecUpstreamFixture.SendFrameAsync(stream, reply(request), closure.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync()
        {
            try { await closure.CancelAsync().ConfigureAwait(false); await Task.WhenAll(workers).ConfigureAwait(false); }
            finally { udp.Dispose(); tcp.Dispose(); closure.Dispose(); }
        }
    }
    private sealed class FixedClock : TimeProvider
    {
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
