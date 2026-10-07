using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;

namespace Mk8.Dns.Infrastructure;

public sealed class DnsCookieService : IDnsCookieService, IDisposable
{
    private readonly Lock sync = new();
    private readonly TimeProvider clock;
    private readonly bool ephemeral;
    private byte[] primary;
    private byte[]? alternate;
    private DateTimeOffset primaryCreated;
    private DateTimeOffset alternateExpires;
    private DateTimeOffset rotateAt;
    private bool disposed;

    public DnsCookieService(byte[] primarySecret, DateTimeOffset primaryCreatedAt, byte[]? alternateSecret, DateTimeOffset? alternateCreatedAt, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(primarySecret);
        ArgumentNullException.ThrowIfNull(clock);
        ValidateSecret(primarySecret, primaryCreatedAt, clock.GetUtcNow());
        if ((alternateSecret is null) != (alternateCreatedAt is null))
            throw new ArgumentException("Alternate secret and creation time must be supplied together.", nameof(alternateSecret));
        if (alternateSecret is not null)
            ValidateSecret(alternateSecret, alternateCreatedAt!.Value, clock.GetUtcNow());
        primary = (byte[])primarySecret.Clone();
        alternate = alternateSecret is null ? null : (byte[])alternateSecret.Clone();
        primaryCreated = primaryCreatedAt;
        alternateExpires = alternateCreatedAt?.AddDays(36) ?? DateTimeOffset.MinValue;
        this.clock = clock;
    }

    private DnsCookieService(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        this.clock = clock;
        ephemeral = true;
        primary = RandomNumberGenerator.GetBytes(16);
        primaryCreated = clock.GetUtcNow();
        ScheduleRotation();
    }

    public static DnsCookieService CreateEphemeral(TimeProvider clock) => new(clock);

    public bool IsAvailable
    {
        get
        {
            lock (sync)
            {
                if (disposed)
                    return false;
                var now = Refresh();
                return Usable(now);
            }
        }
    }

    public byte[]? Create(ReadOnlySpan<byte> clientCookie, ReadOnlySpan<byte> peerAddress)
    {
        CheckPeer(peerAddress);
        if (clientCookie.Length != 8)
            throw new ArgumentException("A client cookie contains eight octets.", nameof(clientCookie));
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            var now = Refresh();
            if (!Usable(now))
                return null;
            var cookie = new byte[24];
            clientCookie.CopyTo(cookie);
            cookie[8] = 1;
            BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(12), unchecked((uint)now.ToUnixTimeSeconds()));
            WriteHash(cookie, peerAddress, primary, cookie.AsSpan(16));
            return cookie;
        }
    }

    public bool Validate(ReadOnlySpan<byte> cookie, ReadOnlySpan<byte> peerAddress)
    {
        CheckPeer(peerAddress);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            var now = Refresh();
            if (cookie.Length != 24 || cookie[8] != 1 || !Usable(now))
                return false;
            var age = unchecked((int)((uint)now.ToUnixTimeSeconds() - BinaryPrimitives.ReadUInt32BigEndian(cookie[12..])));
            if (age is < -300 or > 3600)
                return false;
            Span<byte> expected = stackalloc byte[8];
            WriteHash(cookie, peerAddress, primary, expected);
            var matches = CryptographicOperations.FixedTimeEquals(expected, cookie[16..]);
            if (alternate is not null && now < alternateExpires)
            {
                WriteHash(cookie, peerAddress, alternate, expected);
                matches |= CryptographicOperations.FixedTimeEquals(expected, cookie[16..]);
            }
            return matches;
        }
    }

    private DateTimeOffset Refresh()
    {
        var now = clock.GetUtcNow();
        if (ephemeral && (now >= rotateAt || now < primaryCreated.AddMinutes(-5)))
        {
            if (alternate is not null)
                CryptographicOperations.ZeroMemory(alternate);
            alternate = primary;
            alternateExpires = now.AddHours(1);
            primary = RandomNumberGenerator.GetBytes(16);
            primaryCreated = now;
            ScheduleRotation();
        }
        if (alternate is not null && now >= alternateExpires)
        {
            CryptographicOperations.ZeroMemory(alternate);
            alternate = null;
        }
        return now;
    }

    private void ScheduleRotation() => rotateAt = primaryCreated.AddSeconds(RandomNumberGenerator.GetInt32(43_200, 86_401));
    private bool Usable(DateTimeOffset now) => now >= primaryCreated.AddMinutes(-5) && now < primaryCreated.AddDays(36);

    private static void ValidateSecret(byte[] secret, DateTimeOffset createdAt, DateTimeOffset now)
    {
        if (secret.Length != 16 || createdAt <= now.AddDays(-36) || createdAt > now.AddMinutes(5))
            throw new ArgumentException("A secret requires sixteen octets and a current creation time.", nameof(secret));
    }

    private static void CheckPeer(ReadOnlySpan<byte> address)
    {
        if (address.Length is not (4 or 16))
            throw new ArgumentException("Cookie binding requires an IPv4 or IPv6 source.", nameof(address));
    }

    private static void WriteHash(ReadOnlySpan<byte> cookie, ReadOnlySpan<byte> peerAddress, ReadOnlySpan<byte> secret, Span<byte> output)
    {
        Span<byte> input = stackalloc byte[32];
        cookie[..16].CopyTo(input);
        peerAddress.CopyTo(input[16..]);
        BinaryPrimitives.WriteUInt64LittleEndian(output, SipHash24.Hash(input[..(16 + peerAddress.Length)], secret));
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed)
                return;
            disposed = true;
            CryptographicOperations.ZeroMemory(primary);
            if (alternate is not null)
                CryptographicOperations.ZeroMemory(alternate);
        }
    }
}
