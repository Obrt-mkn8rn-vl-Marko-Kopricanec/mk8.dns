using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

internal sealed class NsecProof
{
    private NsecProof(DnsRecord record, DnsName next, ushort[] types, DnsName origin)
    {
        Record = record;
        Next = next;
        Types = types;
        Delegation = !record.Owner.Equals(origin) && types.Contains((ushort)2) && !types.Contains((ushort)6);
    }

    internal DnsRecord Record { get; }
    internal DnsName Owner => Record.Owner;
    internal DnsName Next { get; }
    internal ushort[] Types { get; }
    internal bool Delegation { get; }

    internal static NsecProof Decode(DnsRecord record, DnsName origin)
    {
        var data = record.GetData();
        var offset = 0;
        var next = DnssecData.ReadName(data, ref offset);
        var types = NsecBitmap.Decode(data.AsSpan(offset));
        DnssecData.Require(record.Owner.IsSubdomainOf(origin) && next.IsSubdomainOf(origin));
        DnssecData.Require(!types.Contains((ushort)6) || record.Owner.Equals(origin));
        // The only circular edge returns to the selected zone apex. A one-node
        // ring is possible only at that apex, not at an arbitrary descendant.
        DnssecData.Require(DnssecNameOrder.Instance.Compare(record.Owner, next) < 0 || next.Equals(origin));
        var result = new NsecProof(record, next, types, origin);
        DnssecData.Require(!result.Delegation || !DnssecData.IsWildcard(record.Owner));
        DnssecData.Require(!types.Contains((ushort)43) || result.Delegation);
        return result;
    }

    internal bool Covers(DnsName name)
    {
        if (Owner.Equals(name) || Next.Equals(name))
            return false;
        var order = DnssecNameOrder.Instance;
        return order.Compare(Owner, Next) < 0
            ? order.Compare(Owner, name) < 0 && order.Compare(name, Next) < 0
            : order.Compare(Owner, name) < 0 || order.Compare(name, Next) < 0 || Owner.Equals(Next);
    }

    internal bool Blocks(DnsQuestion question)
        => question.Name.IsSubdomainOf(Owner) && (Delegation && (!question.Name.Equals(Owner) || question.Type != 43)
            || Types.Contains((ushort)39) && !question.Name.Equals(Owner));

    internal bool Lacks(ushort type) => type is not (46 or 47) && !Types.Contains(type) && !Types.Contains((ushort)5);
}
