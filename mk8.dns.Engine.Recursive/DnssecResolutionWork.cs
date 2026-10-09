using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

internal sealed partial class DnssecResolutionWork : IDnssecSignatureVerifier
{
    private readonly IDnssecSignatureVerifier provider;
    private readonly CancellationToken cancellationToken;
    private int exchanges;
    private int aliases;
    private int verificationAttempts;
    private int minimisationSteps;
    private int recordsLeft = 8192;
    private long bytesLeft = 8_388_608;
    private readonly HashSet<DnsName> activeDelegations = [];

    internal DnssecResolutionWork(IDnssecSignatureVerifier provider, DnssecResolutionClock clock, int exchanges,
        int aliases, int verificationAttempts, CancellationToken cancellationToken)
    {
        this.provider = provider;
        this.exchanges = exchanges;
        this.aliases = aliases;
        this.verificationAttempts = verificationAttempts;
        this.cancellationToken = cancellationToken;
        Clock = clock;
        Validator = new DnssecChainValidator(this, clock);
    }

    internal DnssecResolutionClock Clock { get; }
    internal DnssecChainValidator Validator { get; }
    internal List<DnssecResolutionProof> Proofs { get; } = [];
    internal List<DnssecResolutionProof> RoutingProofs { get; } = [];
    internal List<DnssecResolutionProof> DiscoveryProofs { get; } = [];
    internal void SetMinimisationLimit(int steps) => minimisationSteps = steps;
    internal bool TakeMinimisationStep() => Check(--minimisationSteps >= 0);
    internal bool EnterDelegation(DnsName cut) => activeDelegations.Count < 8 && activeDelegations.Add(cut);
    internal void ExitDelegation(DnsName cut) => activeDelegations.Remove(cut);
    internal bool Exhausted { get; private set; }
    internal bool TakeExchange() => Check(--exchanges >= 0);
    internal bool TakeAlias() => Check(--aliases >= 0);
    internal bool TakeEvidence(DnsUpstreamEvidence evidence)
    {
        var records = evidence.Answers.Concat(evidence.Authority).Concat(evidence.Additional).ToArray();
        recordsLeft -= records.Length + (evidence.HasEdns ? 1 : 0);
        bytesLeft -= records.Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length);
        return Check(recordsLeft >= 0 && bytesLeft >= 0);
    }

    public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Check(--verificationAttempts >= 0)) return false;
        var result = provider.VerifyHash(algorithm, publicKey, digest, signature);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    internal DnssecResolutionResult Finish(DnsQuestion original, byte code, DnsName origin, DnsName? unsignedDelegation = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var cutProofs = CutProofs().ToArray();
        var completeProofs = Proofs.Concat(RoutingProofs).Concat(cutProofs).Concat(DiscoveryProofs).Distinct().ToArray();
        if (Proofs.Count == 0 || completeProofs.Any(proof => !proof.Authenticate(Validator, Clock)) || Exhausted)
            return Failure(original);
        var keyStamp = Clock.GetTimestamp();
        var keyTtl = completeProofs.Min(proof => Validator.GetRemainingTtl(proof.Keys));
        var wallStamp = Clock.GetUtcNow();
        var wall = unchecked((uint)wallStamp.ToUnixTimeSeconds());
        var now = Clock.GetTimestamp();
        keyTtl = Clock.Age(keyTtl, keyStamp, now);
        if (keyTtl == 0 || completeProofs.Any(proof => !proof.WindowsContain(wall)))
            return Failure(original);
        var ttl = Math.Min(keyTtl, completeProofs.Min(proof => proof.Remaining(Clock, now)));
        var outputTtl = RoutingProofs.Count == 0 ? keyTtl : Math.Min(keyTtl, RoutingProofs.Min(proof => proof.Remaining(Clock, now)));
        if (cutProofs.Length != 0) outputTtl = Math.Min(outputTtl, cutProofs.Min(proof => proof.Remaining(Clock, now)));
        if (DiscoveryProofs.Count != 0) outputTtl = Math.Min(outputTtl, DiscoveryProofs.Min(proof => proof.Remaining(Clock, now)));
        var answers = unsignedDelegation is null ? Proofs.Where(proof => proof.Kind is DnssecResolutionProofKind.Exact or DnssecResolutionProofKind.Wildcard)
            .SelectMany(proof => proof.Output(Clock, now)).Select(record => record.WithTtl(Math.Min(record.Ttl, outputTtl))).ToArray() : [];
        var authority = unsignedDelegation is null ? Proofs.Where(proof => proof.Kind is DnssecResolutionProofKind.NoData or DnssecResolutionProofKind.NameError)
            .SelectMany(proof => proof.Output(Clock, now)).Select(record => record.WithTtl(Math.Min(record.Ttl, outputTtl))).ToArray() : [];
        if (answers.Length + authority.Length > DnsUpstreamEvidence.MaximumRecords
            || answers.Concat(authority).Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length) > DnsUpstreamEvidence.MaximumExpandedBytes)
            return Failure(original);
        // Flat cache receipt: retain no query worker, verifier, DNSKEY set or proof arrays.
        var validity = Math.Min(keyTtl, completeProofs.Min(proof => proof.WindowLifetime(wall)));
        var lease = unsignedDelegation is null ? new DnssecValidationLease(Clock, now, wallStamp, keyTtl, validity, ttl) : null;
        return new DnssecResolutionResult(original, unsignedDelegation is null ? DnssecResolutionOutcome.Authenticated
            : DnssecResolutionOutcome.UnsignedDelegation, code, origin, unsignedDelegation, ttl, answers, authority, lease);
    }

    internal static DnssecResolutionResult Failure(DnsQuestion question)
        => new(question, DnssecResolutionOutcome.Failure, 2, null, null, 0, [], []);

    private bool Check(bool condition) { Exhausted |= !condition; return !Exhausted; }
}
