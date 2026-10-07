using System.Xml.Linq;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ArchitectureTests
{
    [Fact]
    public void ProjectReferencesPreserveLayersAndAnAcyclicGraph()
    {
        Dictionary<string, HashSet<string>> graph = new(StringComparer.Ordinal);
        foreach (var directory in Directory.EnumerateDirectories(RepositoryPaths.Root, "mk8.dns.*"))
        {
            var project = Path.Combine(directory, Path.GetFileName(directory) + ".csproj");
            Assert.True(File.Exists(project));
            var xml = XDocument.Load(project);
            var references = new HashSet<string>(StringComparer.Ordinal);
            foreach (var reference in xml.Descendants("ProjectReference"))
                references.Add(Path.GetFileNameWithoutExtension(reference.Attribute("Include")!.Value));
            graph.Add(Path.GetFileName(directory), references);
        }
        CheckLayers(graph);

        HashSet<string> visited = new(StringComparer.Ordinal);
        HashSet<string> active = new(StringComparer.Ordinal);
        foreach (var project in graph.Keys)
            Visit(project);
        HashSet<string> gatewayClosure = new(StringComparer.Ordinal);
        Collect("mk8.dns.Gateway");
        Assert.DoesNotContain("mk8.dns.Application.BLL", gatewayClosure);
        Assert.DoesNotContain("mk8.dns.Application.DAL", gatewayClosure);
        Assert.DoesNotContain("mk8.dns.Application", gatewayClosure);
        Assert.DoesNotContain("mk8.dns.Engine.Authoritative", gatewayClosure);
        Assert.DoesNotContain("mk8.dns.Engine.Dnssec", gatewayClosure);
        Assert.DoesNotContain("mk8.dns.Infrastructure.Cryptography", gatewayClosure);

        void Visit(string node)
        {
            Assert.DoesNotContain(node, active);
            if (!visited.Add(node))
                return;
            active.Add(node);
            foreach (var dependency in graph[node])
                Visit(dependency);
            active.Remove(node);
        }

        void Collect(string node)
        {
            if (!gatewayClosure.Add(node))
                return;
            foreach (var dependency in graph[node])
                Collect(dependency);
        }
    }

    private static void CheckLayers(Dictionary<string, HashSet<string>> graph)
    {
        var allowedGateway = new HashSet<string>(["mk8.dns.Configuration", "mk8.dns.Transport", "mk8.dns.Presentation"], StringComparer.Ordinal);
        Assert.True(graph["mk8.dns.Gateway"].SetEquals(allowedGateway));
        Assert.Empty(graph["mk8.dns.Domain"]);
        Assert.Empty(graph["mk8.dns.Contracts"]);
        Assert.True(graph["mk8.dns.Wire"].SetEquals(["mk8.dns.Domain"]));
        Assert.True(graph["mk8.dns.Engine.Authoritative"].SetEquals(["mk8.dns.Domain", "mk8.dns.Engine.Dnssec"]));
        Assert.True(graph["mk8.dns.Engine.Dnssec"].SetEquals(["mk8.dns.Domain"]));
        Assert.True(graph["mk8.dns.Infrastructure.Cryptography"].SetEquals(["mk8.dns.Domain"]));
        Assert.DoesNotContain("mk8.dns.Application.DAL", graph["mk8.dns.Application.BLL"]);
    }
}
