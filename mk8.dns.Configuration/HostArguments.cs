namespace Mk8.Dns.Configuration;

internal static class HostArguments
{
    internal static Dictionary<string, string> Parse(string[] args, string[] allowed)
    {
        ArgumentNullException.ThrowIfNull(args);
        Dictionary<string, string> result = new(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length || !allowed.Contains(args[index], StringComparer.Ordinal) || string.IsNullOrEmpty(args[index + 1]) || !result.TryAdd(args[index], args[index + 1]))
                throw new ArgumentException("Unknown, duplicated, missing, or empty host argument.", nameof(args));
        }
        return result;
    }

    internal static string Required(Dictionary<string, string> values, string key) => values.TryGetValue(key, out var value)
        ? value
        : throw new ArgumentException("Required host argument is missing.", nameof(values));

    internal static string AbsolutePath(Dictionary<string, string> values, string key)
    {
        var value = Required(values, key);
        if (!Path.IsPathFullyQualified(value))
            throw new ArgumentException("Host paths must be absolute.", nameof(values));
        return Path.GetFullPath(value);
    }
}
