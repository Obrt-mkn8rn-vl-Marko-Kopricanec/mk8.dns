using System.Security.Cryptography;
using System.Text;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

internal static class ManagementFingerprint
{
    internal static string Edit(ManagementRequest request, string actor, string targetNode, ZoneSnapshot intent)
    {
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        WriteIdentity(writer, "M8I1"u8, request, actor, targetNode, intent.Origin);
        writer.Write(Convert.FromHexString(intent.ContentHash));
        writer.Flush();
        return Convert.ToHexStringLower(SHA256.HashData(output.ToArray()));
    }

    internal static string Patch(ManagementRequest request, string actor, string targetNode, DnsName origin, RrsetPatch patch)
    {
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        WriteIdentity(writer, "M8R1"u8, request, actor, targetNode, origin);
        patch.WriteIntent(writer);
        writer.Flush();
        return Convert.ToHexStringLower(SHA256.HashData(output.ToArray()));
    }

    private static void WriteIdentity(BinaryWriter writer, ReadOnlySpan<byte> purpose, ManagementRequest request, string actor, string targetNode, DnsName origin)
    {
        writer.Write(purpose);
        writer.Write(request.TenantId.ToByteArray());
        writer.Write(request.ZoneId.ToByteArray());
        writer.Write(request.ExpectedRevision);
        writer.Write(actor);
        writer.Write(targetNode);
        writer.Write(origin.ToWire());
    }
}
