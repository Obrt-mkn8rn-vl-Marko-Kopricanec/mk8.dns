using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

internal sealed partial class DnssecResolutionProof
{
    private readonly DnsRecord[] records;
    private readonly DnsRecord[] soa;
    private readonly DnsRecord[] nsecs;
    private readonly bool nsec3;
    private readonly DnsRecord[] signatures;
    private readonly DnssecSignatureWindow[] windows;
    private readonly long received;
    private readonly DnsRecord? synthetic;
    private uint verifiedTtl;
    private long verifiedAt;

    private DnssecResolutionProof(DnssecResolutionProofKind kind, AuthenticatedDnskeySet keys, DnsQuestion question,
        DnsRecord[] records, DnsRecord[] soa, DnsRecord[] nsecs, DnsRecord[] signatures, long received, DnsRecord? synthetic)
    {
        Kind = kind;
        Keys = keys;
        Question = question;
        this.records = records;
        this.soa = [.. soa.Select(record => record.WithTtl(Math.Min(record.Ttl, record.GetSoaMinimum())))];
        this.nsecs = nsecs;
        nsec3 = nsecs.Length != 0 && nsecs[0].Type == 50;
        this.signatures = signatures;
        this.received = received;
        this.synthetic = synthetic;
        windows = [.. signatures.Select(record => Window(record.GetData()))];
    }

    internal DnssecResolutionProofKind Kind { get; }
    internal AuthenticatedDnskeySet Keys { get; }
    internal DnsQuestion Question { get; }

    internal static bool TryCreate(DnssecResolutionProofKind kind, AuthenticatedDnskeySet keys, DnsQuestion question,
        DnsRecord[] records, DnsRecord[] soa, DnsRecord[] nsecs, DnsRecord[] signatures, long received,
        [NotNullWhen(true)] out DnssecResolutionProof? proof, DnsRecord? synthetic = null)
    {
        proof = null;
        if (signatures.Length is 0 or > DnssecChainValidator.MaximumSignatures
            || nsecs.Length > DnssecChainValidator.MaximumNsec3Records
            || nsecs.Any(record => record.Type is not (47 or 50) || record.Type != nsecs[0].Type))
        {
            return false;
        }
        try { proof = new DnssecResolutionProof(kind, keys, question, records, soa, nsecs, signatures, received, synthetic); return true; }
        catch (Exception error) when (error is ArgumentException or FormatException) { return false; }
    }

    internal bool Authenticate(DnssecChainValidator validator, DnssecResolutionClock clock)
    {
        var now = clock.GetTimestamp();
        var data = Age(records, clock, now);
        var negativeSoa = Age(soa, clock, now);
        var denial = Age(nsecs, clock, now);
        var sigs = Age(signatures, clock, now);
        var valid = Kind switch
        {
            DnssecResolutionProofKind.Exact => validator.TryAuthenticateRrset(Keys, Question, data, sigs, out verifiedTtl),
            DnssecResolutionProofKind.Wildcard => nsec3
                ? validator.TryAuthenticateNsec3Wildcard(Keys, Question, data, denial, sigs, out verifiedTtl)
                : validator.TryAuthenticateWildcard(Keys, Question, data, denial, sigs, out verifiedTtl),
            DnssecResolutionProofKind.NoData => nsec3
                ? validator.TryAuthenticateNsec3NoData(Keys, Question, negativeSoa, denial, sigs, out verifiedTtl)
                : validator.TryAuthenticateNoData(Keys, Question, negativeSoa, denial, sigs, out verifiedTtl),
            DnssecResolutionProofKind.NameError => nsec3
                ? validator.TryAuthenticateNsec3NameError(Keys, Question, negativeSoa, denial, sigs, out verifiedTtl)
                : validator.TryAuthenticateNameError(Keys, Question, negativeSoa, denial, sigs, out verifiedTtl),
            DnssecResolutionProofKind.DsAbsence => nsec3
                ? validator.TryAuthenticateNsec3DsAbsence(Keys, Question.Name, denial, sigs, out verifiedTtl, out _)
                : validator.TryAuthenticateDsAbsence(Keys, Question.Name, denial, sigs, out verifiedTtl),
            _ => false,
        };
        verifiedAt = clock.GetTimestamp();
        return valid;
    }

    internal bool WindowsContain(uint now) => windows.All(window => window.Contains(now));
    internal uint WindowLifetime(uint now) => windows.Min(window => unchecked(window.Expiration - now));
    internal uint Remaining(DnssecResolutionClock clock, long now)
        => Math.Min(clock.Age(verifiedTtl, verifiedAt, now), Math.Min(synthetic is null ? uint.MaxValue : clock.Age(synthetic.Ttl, received, now),
            Kind == DnssecResolutionProofKind.DsAbsence && soa.Length == 1 ? clock.Age(soa[0].Ttl, received, now) : uint.MaxValue));
    internal DnsRecord[] Output(DnssecResolutionClock clock, long now)
        => [.. Age(synthetic is not null ? [.. records, synthetic]
                : Kind is DnssecResolutionProofKind.NoData or DnssecResolutionProofKind.NameError ? soa : records, clock, now)
            .Select(record => record.WithTtl(Math.Min(record.Ttl, Remaining(clock, now))))];

    private DnsRecord[] Age(DnsRecord[] input, DnssecResolutionClock clock, long now)
        => [.. input.Select(record => record.WithTtl(clock.Age(record.Ttl, received, now)))];

    private static DnssecSignatureWindow Window(byte[] data)
    {
        if (data.Length < 16) throw new FormatException("Incomplete DNSSEC signature window.");
        return new DnssecSignatureWindow(BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(12)),
            BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(8)));
    }
}
