namespace Mk8.Dns.IntegrationTests;

internal static class RepositoryPaths
{
    internal static string Root
    {
        get
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "mk8.dns.slnx")))
                directory = directory.Parent;
            return directory?.FullName ?? throw new InvalidOperationException("Cannot locate the test checkout.");
        }
    }

    internal static string HostAssembly(string name) => Path.Combine(Root, name, "bin", "Release", "net10.0", name + ".dll");
}
