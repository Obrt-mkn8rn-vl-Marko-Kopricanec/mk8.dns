using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

internal sealed class DnssecChainFixture : IDisposable
{
    internal DnssecChainFixture()
    {
        ParentCskRecord = DnssecKeys.CreateDnskey(Parent, 300, ParentCsk.GetPublicKey());
        ParentZskRecord = DnssecKeys.CreateDnskey(Parent, 300, ParentZsk.GetPublicKey(), secureEntryPoint: false);
        ChildCskRecord = DnssecKeys.CreateDnskey(Child, 300, ChildCsk.GetPublicKey());
        ChildZskRecord = DnssecKeys.CreateDnskey(Child, 300, ChildZsk.GetPublicKey(), secureEntryPoint: false);
        ParentRecords = [ParentCskRecord, ParentZskRecord];
        ChildRecords = [ChildCskRecord, ChildZskRecord];
        ParentSignature = Sign(ParentRecords, ParentCskRecord, ParentCsk);
        ChildSignature = Sign(ChildRecords, ChildCskRecord, ChildCsk);
        Delegation = DnssecKeys.CreateDs(ChildCskRecord, 300);
        DelegationSignature = Sign([Delegation], ParentZskRecord, ParentZsk);
        Validator = new DnssecChainValidator(DnssecFixture.Verifier, Clock);
    }

    internal DnsName Parent { get; } = DnsName.Parse("example.");
    internal DnsName Child { get; } = DnsName.Parse("child.example.");
    internal EcdsaP256DnssecSigningKey ParentCsk { get; } = DnssecFixture.Key();
    internal EcdsaP256DnssecSigningKey ParentZsk { get; } = EcdsaP256DnssecSigningKey.Create();
    internal EcdsaP256DnssecSigningKey ChildCsk { get; } = EcdsaP256DnssecSigningKey.Create();
    internal EcdsaP256DnssecSigningKey ChildZsk { get; } = EcdsaP256DnssecSigningKey.Create();
    internal DnsRecord ParentCskRecord { get; }
    internal DnsRecord ParentZskRecord { get; }
    internal DnsRecord ChildCskRecord { get; }
    internal DnsRecord ChildZskRecord { get; }
    internal DnsRecord[] ParentRecords { get; }
    internal DnsRecord[] ChildRecords { get; }
    internal DnsRecord ParentSignature { get; }
    internal DnsRecord ChildSignature { get; }
    internal DnsRecord Delegation { get; }
    internal DnsRecord DelegationSignature { get; }
    internal ClockProvider Clock { get; } = new();
    internal DnssecChainValidator Validator { get; }
    internal static DnsRecord Sign(IReadOnlyList<DnsRecord> records, DnsRecord dnskey, IDnssecSigningKey key, DnssecSignatureWindow? window = null)
        => DnssecRrsetSigner.Sign(records, dnskey, key, DnssecFixture.Verifier, window ?? DnssecFixture.Window);

    internal AuthenticatedDnskeySet Trust(bool dsAnchor = false)
    {
        var anchor = new DnssecTrustAnchor(dsAnchor ? DnssecKeys.CreateDs(ParentCskRecord, 0) : ParentCskRecord.WithTtl(0));
        Assert.True(Validator.TryAuthenticateAnchor(anchor, ParentRecords, [ParentSignature], out var keys));
        return Assert.IsType<AuthenticatedDnskeySet>(keys);
    }

    internal AuthenticatedDnskeySet AuthenticateChild(AuthenticatedDnskeySet? parent = null)
    {
        Assert.True(Validator.TryAuthenticateChild(parent ?? Trust(), Child, [Delegation], [DelegationSignature], ChildRecords, [ChildSignature], out var keys));
        return Assert.IsType<AuthenticatedDnskeySet>(keys);
    }

    public void Dispose()
    {
        ParentCsk.Dispose();
        ParentZsk.Dispose();
        ChildCsk.Dispose();
        ChildZsk.Dispose();
    }

    internal sealed class ClockProvider : TimeProvider
    {
        private long ticks;
        private long seconds = 100;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref ticks);
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Interlocked.Read(ref seconds));
        internal void Advance(double elapsed)
        {
            Interlocked.Add(ref ticks, TimeSpan.FromSeconds(elapsed).Ticks);
            Interlocked.Add(ref seconds, (long)Math.Floor(elapsed));
        }
        internal void SetWall(long value) => Interlocked.Exchange(ref seconds, value);
        internal void SetMonotonic(double elapsed) => Interlocked.Exchange(ref ticks, TimeSpan.FromSeconds(elapsed).Ticks);
    }

    internal sealed class CountingVerifier : IDnssecSignatureVerifier
    {
        internal int Calls { get; private set; }
        internal Action? AfterVerify { get; init; }
        internal void Reset() => Calls = 0;
        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        {
            Calls++;
            var result = DnssecFixture.Verifier.VerifyHash(algorithm, publicKey, digest, signature);
            AfterVerify?.Invoke();
            return result;
        }
    }
}
