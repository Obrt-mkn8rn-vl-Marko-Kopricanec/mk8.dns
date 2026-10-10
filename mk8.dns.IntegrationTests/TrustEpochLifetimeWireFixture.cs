using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.IntegrationTests;

internal sealed class TrustEpochLifetimeWireFixture : IDisposable
{
    private readonly EcdsaP256DnssecSigningKey a = EcdsaP256DnssecSigningKey.Create();
    private readonly EcdsaP256DnssecSigningKey b = EcdsaP256DnssecSigningKey.Create();
    private EcdsaP256DnssecSigningKey? first;
    private EcdsaP256DnssecSigningKey? second;

    internal TrustEpochLifetimeWireFixture()
    {
        Keys = [DnssecKeys.CreateDnskey(Origin, 3600, a.GetPublicKey()), DnssecKeys.CreateDnskey(Origin, 3600, b.GetPublicKey())];
        Verifier = new ElapsedFailureVerifier(Clock);
        var tracker = new DnssecTrustAnchorTracker(Origin, Keys, Native, Clock);
        Store = new PinnedStore(new DnssecStoredAnchorCheckpoint(Origin, 1, tracker.CreateCheckpoint()));
    }

    internal DnsName Origin { get; } = DnsName.Parse("example.");
    internal DnsRecord[] Keys { get; }
    internal EcdsaP256DnssecVerifier Native { get; } = new();
    internal ClockProvider Clock { get; } = new();
    internal ElapsedFailureVerifier Verifier { get; }
    internal PinnedStore Store { get; }
    internal int BootstrapCalls { get; private set; }
    internal int DataCalls { get; private set; }

    internal void SelectPins(DnssecAnchorRefreshSnapshot snapshot)
    {
        first = snapshot.Anchors[0].Record.GetData().AsSpan().SequenceEqual(Keys[0].GetData()) ? a : b;
        second = ReferenceEquals(first, a) ? b : a;
        Verifier.FailedPinPublicKey = first.GetPublicKey();
    }

    internal DnsRecord[] Answer(DnsQuestion question, uint ttl)
    {
        if (first is null || second is null) throw new InvalidOperationException("Pins have not been selected.");
        if (question.Type == 48)
        {
            BootstrapCalls++;
            var good = Sign(Keys, first); var bytes = good.GetData(); bytes[^1] ^= 1;
            Verifier.FailedSignature = bytes[(18 + Origin.ToWire().Length)..];
            return [.. Keys.Select(record => record.WithTtl(ttl)), new DnsRecord(Origin, 46, ttl, bytes), Sign(Keys, second).WithTtl(ttl)];
        }
        DataCalls++;
        var record = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 1]);
        return [record, Sign([record], second)];
    }

    private DnsRecord Sign(DnsRecord[] records, EcdsaP256DnssecSigningKey signer)
        => DnssecRrsetSigner.Sign(records, ReferenceEquals(signer, a) ? Keys[0] : Keys[1], signer, Native, new DnssecSignatureWindow(99, 10_000));

    public void Dispose() { a.Dispose(); b.Dispose(); }

    internal sealed class ClockProvider : TimeProvider
    {
        private long seconds = 100;
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref ticks);
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Interlocked.Read(ref seconds));
        internal void Advance(int elapsed)
        {
            Interlocked.Add(ref ticks, TimeSpan.FromSeconds(elapsed).Ticks);
            Interlocked.Add(ref seconds, elapsed);
        }
    }

    internal sealed class PinnedStore(DnssecStoredAnchorCheckpoint snapshot) : IDnssecAnchorCheckpointStore
    {
        public DnssecStoredAnchorCheckpoint ReadCommitted() => snapshot;
        public long Commit(long expectedRevision, DnssecTrustAnchorTracker candidate, CancellationToken cancellationToken)
            => throw new NotSupportedException("This acquisition control has one immutable committed seed.");
    }

    internal sealed class ElapsedFailureVerifier(ClockProvider clock) : IDnssecSignatureVerifier
    {
        private readonly EcdsaP256DnssecVerifier provider = new();
        internal byte[] FailedPinPublicKey { get; set; } = [];
        internal byte[] FailedSignature { get; set; } = [];
        internal int Calls { get; private set; }
        internal int Failures { get; private set; }
        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        {
            Calls++;
            var valid = provider.VerifyHash(algorithm, publicKey, digest, signature);
            if (!valid && publicKey.SequenceEqual(FailedPinPublicKey) && signature.SequenceEqual(FailedSignature))
            {
                Failures++;
                clock.Advance(2);
            }
            return valid;
        }
    }
}
