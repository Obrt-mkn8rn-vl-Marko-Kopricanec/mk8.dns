using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private readonly IDnssecUpstream upstream;
    private readonly IDnssecSignatureVerifier verifier;
    private readonly DnssecTrustAnchor anchor;
    private readonly DnsServerEndpoint[] roots;
    private readonly ushort authorityPort;
    private readonly int maximumExchanges;
    private readonly int maximumAliasHops;
    private readonly int maximumVerificationAttempts;
    private readonly DnssecResolutionClock clock;

    public DnssecIterativeResolver(IDnssecUpstream upstream, IDnssecSignatureVerifier verifier, DnssecTrustAnchor anchor,
        IEnumerable<DnsServerEndpoint> roots, ushort authorityPort = 53, int maximumExchanges = 64,
        int maximumAliasHops = 16, int maximumVerificationAttempts = 512, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(anchor);
        ArgumentNullException.ThrowIfNull(roots);
        if (authorityPort == 0 || maximumExchanges is < 1 or > 256 || maximumAliasHops is < 1 or > 32
            || maximumVerificationAttempts is < 1 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(maximumExchanges), "Invalid validating iteration budgets.");
        this.roots = roots.Take(17).ToArray();
        if (this.roots.Length is < 1 or > 16 || this.roots.Any(server => server is null) || this.roots.Distinct().Count() != this.roots.Length)
            throw new ArgumentException("Supply one to sixteen distinct bootstrap endpoints.", nameof(roots));
        this.upstream = upstream;
        this.verifier = verifier;
        this.anchor = anchor;
        this.authorityPort = authorityPort;
        this.maximumExchanges = maximumExchanges;
        this.maximumAliasHops = maximumAliasHops;
        this.maximumVerificationAttempts = maximumVerificationAttempts;
        clock = new DnssecResolutionClock(time ?? TimeProvider.System);
    }

    public async ValueTask<DnssecResolutionResult> ResolveDnssecAsync(DnsQuestion question, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (question.Name is null) throw new ArgumentException("A validating question needs a name.", nameof(question));
        cancellationToken.ThrowIfCancellationRequested();
        if (!Supported(question)) return DnssecResolutionWork.Failure(question);
        var work = new DnssecResolutionWork(verifier, clock, maximumExchanges, maximumAliasHops, maximumVerificationAttempts, cancellationToken);
        var bootstrap = await BootstrapAsync(work, cancellationToken).ConfigureAwait(false);
        return bootstrap is null ? DnssecResolutionWork.Failure(question)
            : await ResolveQuestionAsync(question, bootstrap, work, cancellationToken).ConfigureAwait(false);
    }

    private bool Supported(DnsQuestion question) => question.Class == 1 && question.Type is not (0 or 41 or 46 or >= 249 and <= 255)
        && question.Name.IsSubdomainOf(anchor.Origin) && question.Name.ToWire() is not [1, 42, ..];

    private async ValueTask<DnssecReceivedEvidence?> ReadAsync(DnsQuestion question, DnsServerEndpoint server,
        DnssecResolutionWork work, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!work.TakeExchange()) return null;
        var received = clock.GetTimestamp(); // Age conservatively from before provider/network work.
        try
        {
            var reply = await upstream.ExchangeDnssecAsync(question, server, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (reply is null || !work.TakeEvidence(reply) || !reply.Question.Equals(question) || !reply.Server.Equals(server)
                || reply.ResponseCode is not (0 or 3 or 6) || reply.HasEdns && reply.EdnsVersion != 0)
                return null;
            return new DnssecReceivedEvidence(reply, received);
        }
        catch (Exception error) when (error is IOException or TimeoutException or FormatException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }
    }

    private static DnsRecord[] Rrset(IEnumerable<DnsRecord> records, DnsName owner, ushort type)
        => records.Where(record => record.Owner.Equals(owner) && record.Type == type).ToArray();

    private static DnsRecord[] Signatures(IEnumerable<DnsRecord> records, params DnsRecord[][] rrsets)
    {
        var wanted = rrsets.SelectMany(set => set).Select(record => (record.Owner, record.Type)).ToHashSet();
        return records.Where(record => record.Type == 46 && record.GetData().Length >= 2
            && wanted.Contains((record.Owner, BinaryPrimitives.ReadUInt16BigEndian(record.GetData())))).ToArray();
    }

    private sealed record AuthorityContext(AuthenticatedDnskeySet Keys, DnsServerEndpoint[] Servers);
    private sealed record ResolutionStep(DnssecResolutionProof Proof, byte Code, DnsName? Target);
    private sealed record ReferralTransition(AuthorityContext? Next, DnsName? Unsigned);
}
