using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class NonValidatingIterativeResolver
{
    private readonly bool captureDnssecMaterial;
    internal bool CapturesDnssecMaterial => captureDnssecMaterial;

    /// <summary>
    /// Acquires selected DNSSEC records without authentication. The caller supplies actual correlated acquisition,
    /// permitted egress and a coherent clock. This source owns no upstream, clock, cache or validation state.
    /// </summary>
    public static NonValidatingIterativeResolver CreateWithDnssecMaterial(IDnssecUpstream upstream,
        IEnumerable<DnsServerEndpoint> roots, ushort authorityPort = 53, int maximumExchanges = 64,
        int maximumAliasHops = 16, int maximumDependencyDepth = 8, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        var clock = new DnssecResolutionClock(time ?? TimeProvider.System);
        return new NonValidatingIterativeResolver(new MaterialUpstream(upstream, clock), roots, authorityPort,
            maximumExchanges, maximumAliasHops, maximumDependencyDepth, clock, captureMaterial: true);
    }

    private NonValidatingIterativeResolver(IDnsUpstream upstream, IEnumerable<DnsServerEndpoint> roots, ushort authorityPort,
        int maximumExchanges, int maximumAliasHops, int maximumDependencyDepth, TimeProvider time, bool captureMaterial)
        : this(upstream, roots, authorityPort, maximumExchanges, maximumAliasHops, maximumDependencyDepth, time)
        => captureDnssecMaterial = captureMaterial;

    private static bool FitsMaterial(DnsAnswer answer)
    {
        var records = answer.Answers.Concat(answer.Authority).Concat(answer.Additional).ToArray();
        return records.Length <= DnsUpstreamEvidence.MaximumRecords
            && records.Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length) <= DnsUpstreamEvidence.MaximumExpandedBytes;
    }

    private DnsAnswer AgeMaterialResolution(DnsAnswer answer, long timestamp, DateTimeOffset wall)
    {
        // Charge the entire borrowed resolution, including aliases and dependencies, on both clocks.
        // Per-exchange and inherited alias aging can double-spend time; neither may refill an older input.
        var elapsed = Math.Ceiling(Math.Max(Math.Max(0, time.GetElapsedTime(timestamp, time.GetTimestamp()).TotalSeconds),
            Math.Max(0, (time.GetUtcNow() - wall).TotalSeconds)));
        return new DnsAnswer(answer.ResponseCode, authoritative: false, MaterialUpstream.Age(answer.Answers, elapsed),
            MaterialUpstream.Age(answer.Authority, elapsed), MaterialUpstream.Age(answer.Additional, elapsed));
    }

    private sealed class MaterialUpstream(IDnssecUpstream source, DnssecResolutionClock clock) : IDnsUpstream
    {
        public async ValueTask<DnsAnswer> ExchangeAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            var (timestamp, wall) = (clock.GetTimestamp(), clock.GetUtcNow());
            var reply = await source.ExchangeDnssecAsync(question, server, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!reply.Question.Equals(question) || !reply.Server.Equals(server) || !reply.DnssecOkObserved
                || reply.EdnsVersion != 0 || !reply.CheckingDisabledObserved || reply.ResponseCode > byte.MaxValue)
            {
                throw new FormatException("The unchecked DNSSEC acquisition is outside its correlated CD/DO profile.");
            }
            var elapsed = Math.Ceiling(Math.Max(Math.Max(0, clock.GetElapsedTime(timestamp, clock.GetTimestamp()).TotalSeconds),
                Math.Max(0, (clock.GetUtcNow() - wall).TotalSeconds)));
            return new DnsAnswer((byte)reply.ResponseCode, reply.Authoritative, Age(reply.Answers, elapsed),
                Age(reply.Authority, elapsed), Age(reply.Additional, elapsed));
        }

        internal static DnsRecord[] Age(IReadOnlyList<DnsRecord> records, double elapsed)
            => [.. records.Select(record => record.WithTtl(elapsed >= record.Ttl ? 0 : record.Ttl - (uint)elapsed))];
    }
}
