using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class TrustEpochLifetimeFixture : IAsyncDisposable
{
    private readonly TrustEpochFixture source = new();
    private readonly bool monotonicOnly;

    private TrustEpochLifetimeFixture(bool monotonicOnly)
    {
        this.monotonicOnly = monotonicOnly;
        Verifier = new ElapsedFailureVerifier(source.Anchors.Keys.Clock, monotonicOnly);
    }

    internal DnssecTrustEpochResolver Resolver { get; private set; } = null!;
    internal ElapsedFailureVerifier Verifier { get; }
    internal int SourceCalls => source.Calls.Count;
    internal int BootstrapCalls => source.Calls.Count(question => question.Type == 48);
    internal DnsQuestion Question => source.Question;

    internal static async Task<TrustEpochLifetimeFixture> CreateAsync(uint recordsTtl, uint signaturesTtl, bool monotonicOnly)
    {
        var fixture = new TrustEpochLifetimeFixture(monotonicOnly);
        try
        {
            await fixture.source.PromoteAsync().ConfigureAwait(false);
            var keys = fixture.source.Anchors.Keys;
            var first = fixture.source.Refresh.Current.Anchors[0].Record.GetData();
            var firstSigner = first.AsSpan().SequenceEqual(keys.Key(keys.A).GetData()) ? keys.A : keys.B;
            var secondSigner = ReferenceEquals(firstSigner, keys.A) ? keys.B : keys.A;
            fixture.Verifier.FailedPinPublicKey = firstSigner.GetPublicKey();
            fixture.source.DataSigner = secondSigner;
            fixture.source.Override = (question, server, _) =>
            {
                if (question.Type != 48) return ValueTask.FromResult(fixture.source.Default(question, server));
                var records = fixture.source.Anchors.Records.Select(record => record.WithTtl(recordsTtl)).ToArray();
                var good = keys.Sign(records, firstSigner, originalTtl: 3600, signatureTtl: signaturesTtl);
                var bytes = good.GetData(); bytes[^1] ^= 1;
                fixture.Verifier.FailedSignature = bytes[(18 + keys.Origin.ToWire().Length)..];
                var bad = new DnsRecord(good.Owner, 46, good.Ttl, bytes);
                var second = keys.Sign(records, secondSigner, originalTtl: 3600, signatureTtl: signaturesTtl);
                return ValueTask.FromResult(fixture.source.Anchors.Reply(question, server, answers: [.. records, bad, second]));
            };
            fixture.Resolver = fixture.source.Create(verifier: fixture.Verifier);
            return fixture;
        }
        catch
        {
            await fixture.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal void Advance(double seconds)
    {
        if (monotonicOnly) source.Anchors.Keys.Clock.SetMonotonic((source.Anchors.Keys.Clock.GetTimestamp() / (double)TimeSpan.TicksPerSecond) + seconds);
        else source.Anchors.Keys.Clock.Advance(seconds);
    }

    public ValueTask DisposeAsync() => source.DisposeAsync();

    internal sealed class ElapsedFailureVerifier(DnssecChainFixture.ClockProvider clock, bool monotonicOnly) : IDnssecSignatureVerifier
    {
        internal int Calls { get; private set; }
        internal int Failures { get; private set; }
        internal byte[] FailedPinPublicKey { get; set; } = [];
        internal byte[] FailedSignature { get; set; } = [];

        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        {
            Calls++;
            var valid = DnssecFixture.Verifier.VerifyHash(algorithm, publicKey, digest, signature);
            if (!valid && publicKey.SequenceEqual(FailedPinPublicKey) && signature.SequenceEqual(FailedSignature))
            {
                Failures++;
                if (monotonicOnly) clock.SetMonotonic((clock.GetTimestamp() / (double)TimeSpan.TicksPerSecond) + 2);
                else clock.Advance(2);
            }
            return valid;
        }
    }
}
