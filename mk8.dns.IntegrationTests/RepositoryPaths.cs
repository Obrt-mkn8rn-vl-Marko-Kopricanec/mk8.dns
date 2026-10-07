namespace Mk8.Dns.IntegrationTests;

internal static class RepositoryPaths
{
    internal static string Root
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("MK8_DNS_TEST_REPOSITORY");
            if (configured is not null)
            {
                if (!Path.IsPathFullyQualified(configured) || !File.Exists(Path.Combine(configured, "mk8.dns.slnx")))
                    throw new InvalidOperationException("Invalid explicit test checkout.");
                return configured;
            }
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "mk8.dns.slnx")))
                directory = directory.Parent;
            directory ??= new DirectoryInfo(Directory.GetCurrentDirectory());
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "mk8.dns.slnx")))
                directory = directory.Parent;
            return directory?.FullName ?? throw new InvalidOperationException("Cannot locate the test checkout.");
        }
    }

    internal static string HostAssembly(string name)
    {
        var artifacts = Environment.GetEnvironmentVariable("ArtifactsPath");
        var path = artifacts is not null && string.Equals(Environment.GetEnvironmentVariable("UseArtifactsOutput"), "true", StringComparison.Ordinal)
            ? Path.Combine(artifacts, "bin", name, "release", name + ".dll")
            : Path.Combine(Root, name, "bin", "Release", "net10.0", name + ".dll");
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
            throw new InvalidOperationException("Cannot locate the exact test host output.");
        return path;
    }
}
