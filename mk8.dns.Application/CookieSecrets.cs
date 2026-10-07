using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Configuration;
using Mk8.Dns.Infrastructure;

namespace Mk8.Dns.Application;

internal static class CookieSecrets
{
    internal static DnsCookieService Load(ApplicationSettings settings)
    {
        if (settings.CookieSecretFile is null)
            return DnsCookieService.CreateEphemeral(TimeProvider.System);
        var bytes = PrivateFile.Read(settings.CookieSecretFile, 49);
        byte[]? primary = null;
        byte[]? alternate = null;
        try
        {
            if (bytes.Length is not (25 or 49) || bytes[0] != 1)
                throw new InvalidDataException("Cookie secrets require a version-one file with one or two dated keys.");
            var created = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(1)));
            primary = bytes.AsSpan(9, 16).ToArray();
            DateTimeOffset? alternateCreated = null;
            if (bytes.Length == 49)
            {
                alternateCreated = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(25)));
                alternate = bytes.AsSpan(33, 16).ToArray();
            }
            return new DnsCookieService(primary, created, alternate, alternateCreated, TimeProvider.System);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (primary is not null)
                CryptographicOperations.ZeroMemory(primary);
            if (alternate is not null)
                CryptographicOperations.ZeroMemory(alternate);
        }
    }
}
