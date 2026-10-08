using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecRootPrimer
{
    private async ValueTask<ReceivedHint[]> AddressesAsync(DnsName[] names, DnssecReceivedEvidence reply, DnsServerEndpoint server,
        DnssecResolutionWork work, CancellationToken token)
    {
        List<ReceivedHint> hints = [];
        foreach (var name in names)
        {
            foreach (var type in new ushort[] { 1, 28 })
            {
                var records = reply.Evidence.Additional.Where(record => record.Owner.Equals(name) && record.Type == type).ToArray();
                AddHints(hints, name, records, reply.Received, DnsRootHintSource.Additional);
                if (!hints.Any(hint => hint.Value.Name.Equals(name) && hint.Value.Server.GetAddress().Length == (type == 1 ? 4 : 16)))
                {
                    var address = await ReadAsync(new DnsQuestion(name, type, 1), server, work, token).ConfigureAwait(false);
                    if (address is not null && !address.Evidence.Answers.Any(record => record.Owner.Equals(name) && record.Type is not (1 or 28 or 46)))
                        AddHints(hints, name, address.Evidence.Answers.Where(record => record.Owner.Equals(name) && record.Type == type).ToArray(),
                            address.Received, DnsRootHintSource.DirectAddressAnswer);
                }
                if (hints.Count == 32 || work.Exhausted) return hints.ToArray();
            }
        }
        return hints.ToArray();
    }

    private void AddHints(List<ReceivedHint> hints, DnsName name, DnsRecord[] records, long received, DnsRootHintSource source)
    {
        if (records.Length == 0) return;
        var ttl = records.Min(record => record.Ttl);
        if (clock.Age(ttl, received, clock.GetTimestamp()) == 0) return;
        foreach (var record in records)
        {
            try
            {
                var server = new DnsServerEndpoint(record.GetData(), authorityPort);
                if (!hints.Any(hint => hint.Value.Name.Equals(name) && hint.Value.Server.Equals(server)))
                    hints.Add(new ReceivedHint(new DnsRootRoutingHint(name, server, source), ttl, received));
            }
            catch (ArgumentException) { continue; }
            if (hints.Count == 32) return;
        }
    }

    private sealed record ReceivedHint(DnsRootRoutingHint Value, uint Ttl, long Received);
}
