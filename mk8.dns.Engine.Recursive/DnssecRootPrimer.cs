using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecRootPrimer
{
    private static readonly DnsName Root = DnsName.Parse(".");
    private readonly IDnssecUpstream upstream;
    private readonly IDnssecSignatureVerifier verifier;
    private readonly DnssecTrustAnchor anchor;
    private readonly DnsServerEndpoint[] bootstrap;
    private readonly ushort authorityPort;
    private readonly int maximumExchanges;
    private readonly int maximumVerificationAttempts;
    private readonly DnssecResolutionClock clock;

    public DnssecRootPrimer(IDnssecUpstream upstream, IDnssecSignatureVerifier verifier, DnssecTrustAnchor anchor,
        IEnumerable<DnsServerEndpoint> bootstrap, ushort authorityPort = 53, int maximumExchanges = 128,
        int maximumVerificationAttempts = 512, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(anchor);
        ArgumentNullException.ThrowIfNull(bootstrap);
        if (!anchor.Origin.Equals(Root)) throw new ArgumentException("Root priming requires an exact root anchor.", nameof(anchor));
        if (authorityPort == 0 || maximumExchanges is < 1 or > 256 || maximumVerificationAttempts is < 1 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(maximumExchanges), "Invalid priming work limits.");
        this.bootstrap = bootstrap.Take(33).ToArray();
        if (this.bootstrap.Length is < 1 or > 32 || this.bootstrap.Any(server => server is null)
            || this.bootstrap.Distinct().Count() != this.bootstrap.Length)
            throw new ArgumentException("Supply one to thirty-two distinct bootstrap endpoints.", nameof(bootstrap));
        this.upstream = upstream; this.verifier = verifier; this.anchor = anchor; this.authorityPort = authorityPort;
        this.maximumExchanges = maximumExchanges; this.maximumVerificationAttempts = maximumVerificationAttempts;
        clock = new DnssecResolutionClock(time ?? TimeProvider.System);
    }

    public async ValueTask<DnsRootPrimingResult?> PrimeAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var work = new DnssecResolutionWork(verifier, clock, maximumExchanges, 1, maximumVerificationAttempts, cancellationToken);
        // Random rotation visits every configured endpoint at most once without a retry loop.
        var start = System.Security.Cryptography.RandomNumberGenerator.GetInt32(bootstrap.Length);
        for (var offset = 0; offset < bootstrap.Length && !work.Exhausted; offset++)
        {
            var server = bootstrap[(start + offset) % bootstrap.Length];
            var keys = await KeysAsync(server, work, cancellationToken).ConfigureAwait(false);
            if (keys is null) continue;
            var result = await PrimeAtAsync(server, keys, work, cancellationToken).ConfigureAwait(false);
            if (result is not null) return result;
        }
        return null;
    }

    private async ValueTask<AuthenticatedDnskeySet?> KeysAsync(DnsServerEndpoint server, DnssecResolutionWork work, CancellationToken token)
    {
        var reply = await ReadAsync(new DnsQuestion(Root, 48, 1), server, work, token).ConfigureAwait(false);
        if (reply is null) return null;
        var keys = reply.Evidence.Answers.Where(record => record.Owner.Equals(Root) && record.Type == 48).ToArray();
        var signatures = Sigs(reply.Evidence.Answers, 48);
        return work.Validator.TryAuthenticateAnchor(anchor, reply.Age(keys, clock), reply.Age(signatures, clock), out var authenticated)
            ? authenticated : null;
    }

    private async ValueTask<DnsRootPrimingResult?> PrimeAtAsync(DnsServerEndpoint server, AuthenticatedDnskeySet keys,
        DnssecResolutionWork work, CancellationToken token)
    {
        var question = new DnsQuestion(Root, 2, 1);
        var reply = await ReadAsync(question, server, work, token).ConfigureAwait(false);
        if (reply is null || reply.Evidence.Authority.Count != 0
            || reply.Evidence.Answers.Any(record => !record.Owner.Equals(Root) || record.Type is not (2 or 46))) return null;
        var records = reply.Evidence.Answers.Where(record => record.Type == 2).ToArray();
        var names = records.Select(record => record.GetTarget()).Distinct().ToArray();
        if (names.Length is < 1 or > 32 || names.Any(name => name.Equals(Root) || name.ToWire() is [1, 42, ..])) return null;
        if (!DnssecResolutionProof.TryCreate(DnssecResolutionProofKind.Exact, keys, question, records, [], [],
            Sigs(reply.Evidence.Answers, 2), reply.Received, out var proof) || !proof.Authenticate(work.Validator, clock)) return null;
        var hints = await AddressesAsync(names, reply, server, work, token).ConfigureAwait(false);
        if (hints.Length == 0 || work.Exhausted) return null;
        work.Proofs.Add(proof);
        try
        {
            var result = work.Finish(question, 0, Root);
            if (result.Outcome != DnssecResolutionOutcome.Authenticated || result.Lease is null || !result.Lease.IsValid()) return null;
            var now = clock.GetTimestamp();
            var lifetime = Math.Min(result.Lease.Remaining(), hints.Min(hint => clock.Age(hint.Ttl, hint.Received, now)));
            return lifetime == 0 ? null : new DnsRootPrimingResult(names, hints.Select(hint => hint.Value).ToArray(), server,
                names.Where(name => !hints.Any(hint => hint.Value.Name.Equals(name))).ToArray(), clock, result.Lease, now, lifetime);
        }
        finally { work.Proofs.Remove(proof); }
    }

    private async ValueTask<DnssecReceivedEvidence?> ReadAsync(DnsQuestion question, DnsServerEndpoint server,
        DnssecResolutionWork work, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!work.TakeExchange()) return null;
        var received = clock.GetTimestamp();
        try
        {
            var reply = await upstream.ExchangeDnssecAsync(question, server, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return reply is null || !work.TakeEvidence(reply) || !reply.Question.Equals(question) || !reply.Server.Equals(server)
                || !reply.Authoritative || reply.ResponseCode != 0 || reply.HasEdns && reply.EdnsVersion != 0
                ? null : new DnssecReceivedEvidence(reply, received);
        }
        catch (Exception error) when (error is IOException or TimeoutException or FormatException)
        {
            token.ThrowIfCancellationRequested(); return null;
        }
    }

    private static DnsRecord[] Sigs(IEnumerable<DnsRecord> records, ushort type)
        => records.Where(record => record.Owner.Equals(Root) && record.Type == 46 && record.GetData().Length >= 2
            && BinaryPrimitives.ReadUInt16BigEndian(record.GetData()) == type).ToArray();
}
