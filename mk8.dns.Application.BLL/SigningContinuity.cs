using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

internal static class SigningContinuity
{
    internal static void Require(ZoneContents? previous, ZoneContents next)
    {
        if (previous is null || !previous.IsSigned)
            return;
        if (!next.IsSigned)
            throw new InvalidOperationException("Unsigned replacement requires an explicit future transition workflow.");
        var currentKeys = previous.GetSecurityRecords().Where(record => record.Type == 48).ToArray();
        var nextKeys = next.GetSecurityRecords().Where(record => record.Type == 48).ToArray();
        if (currentKeys.Length != 1 || nextKeys.Length != 1 || !currentKeys[0].GetData().AsSpan().SequenceEqual(nextKeys[0].GetData()))
            throw new InvalidOperationException("Signing-key replacement requires an explicit future rollover workflow.");
    }
}
