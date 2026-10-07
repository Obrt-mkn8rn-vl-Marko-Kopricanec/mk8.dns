using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed class DnssecNameOrder : IComparer<DnsName>
{
    public static DnssecNameOrder Instance { get; } = new();

    private DnssecNameOrder() { }

    public int Compare(DnsName? x, DnsName? y)
    {
        if (ReferenceEquals(x, y))
            return 0;
        if (x is null)
            return -1;
        if (y is null)
            return 1;
        var left = x.ToWire();
        var right = y.ToWire();
        Span<int> leftStarts = stackalloc int[x.LabelCount];
        Span<int> rightStarts = stackalloc int[y.LabelCount];
        IndexLabels(left, leftStarts);
        IndexLabels(right, rightStarts);
        for (var depth = 1; depth <= Math.Min(leftStarts.Length, rightStarts.Length); depth++)
        {
            var a = leftStarts[^depth];
            var b = rightStarts[^depth];
            var comparison = left.AsSpan(a + 1, left[a]).SequenceCompareTo(right.AsSpan(b + 1, right[b]));
            if (comparison != 0)
                return comparison;
        }
        return leftStarts.Length.CompareTo(rightStarts.Length);
    }

    private static void IndexLabels(ReadOnlySpan<byte> name, Span<int> starts)
    {
        var offset = 0;
        foreach (ref var start in starts)
        {
            start = offset;
            offset += name[offset] + 1;
        }
    }
}
