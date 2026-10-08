using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class OnlineDnssecDnameFixture : IDisposable
{
    internal OnlineDnssecFixture Zones { get; } = new();
    internal DnsRecord Dname { get; set; } = new(DnsName.Parse("branch.example."), 39, 300, DnsName.Parse("example.").ToWire());
    internal DnsRecord[]? Supplied { get; set; }
    internal bool IncludeCname { get; set; } = true;
    internal uint? CnameTtl { get; set; }
    internal ushort Code { get; set; }
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? Transform { get; set; }

    internal OnlineDnssecDnameFixture()
    {
        Zones.Transform = reply =>
        {
            if (reply.Authoritative && reply.Question.Type is not (48 or 43) && !reply.Question.Name.Equals(Dname.Owner) && reply.Question.Name.IsSubdomainOf(Dname.Owner))
            {
                var answers = Supplied ?? new[] { Dname, Zones.Sign([Dname], Dname.Owner.IsSubdomainOf(Zones.Child)) };
                var name = reply.Question.Name.ToWire();
                var prefix = name.Length - Dname.GetOwnerWire().Length;
                var target = Dname.GetData();
                if (IncludeCname && prefix + target.Length <= 255)
                    answers = [.. answers, new DnsRecord(reply.Question.Name, 5, CnameTtl ?? Dname.Ttl,
                        [.. name.AsSpan(0, prefix), .. target])];
                reply = OnlineDnssecFixture.Reply(reply.Question, reply.Server, answers, code: Code);
            }
            return Transform?.Invoke(reply) ?? reply;
        };
    }

    internal static DnsQuestion Question(ushort type = 1) => new(DnsName.Parse("www.branch.example."), type, 1);
    public void Dispose() => Zones.Dispose();
}
