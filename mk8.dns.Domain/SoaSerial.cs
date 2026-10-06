namespace Mk8.Dns.Domain;

public static class SoaSerial
{
    public static uint Next(uint serial) => unchecked(serial + 1);

    public static bool IsNewer(uint candidate, uint current)
    {
        var delta = unchecked(candidate - current);
        if (delta == 0x80000000)
            throw new ArgumentException("Serial ordering is undefined at half the sequence space.", nameof(candidate));
        return delta is > 0 and < 0x80000000;
    }
}
