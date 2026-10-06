using System.Security.Cryptography;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecordScopeAuthorizationTests
{
    private readonly Guid tenant = Guid.NewGuid();
    private readonly Guid zone = Guid.NewGuid();
    private readonly byte[] credential = RandomNumberGenerator.GetBytes(32);
    private static readonly DnsName Challenge = DnsName.Parse("_acme-challenge.example.");

    [Theory]
    [InlineData("action")]
    [InlineData("name")]
    [InlineData("type")]
    [InlineData("replace")]
    [InlineData("empty")]
    [InlineData("multiple")]
    [InlineData("length")]
    [InlineData("padding")]
    [InlineData("alphabet")]
    [InlineData("pad-bits")]
    [InlineData("ttl-low")]
    [InlineData("ttl-high")]
    [InlineData("records")]
    public void AcmeCannotExpandItsRecordOrMutationScope(string invalid)
    {
        var request = Request();
        var change = request.Changes[0];
        var data = Text();
        switch (invalid)
        {
            case "action": request = request with { Action = "edit" }; break;
            case "name": change = change with { Owner = DnsName.Parse("_acme-challenge.other.example.").ToWire() }; break;
            case "type": change = change with { Type = 1 }; break;
            case "replace": change = change with { Replace = true }; break;
            case "empty": change = change with { Add = Array.Empty<ReadOnlyMemory<byte>>() }; break;
            case "multiple": change = change with { Remove = new ReadOnlyMemory<byte>[] { Text() } }; break;
            case "length": data = new byte[43]; break;
            case "padding": data[4] = (byte)'='; break;
            case "alphabet": data[4] = (byte)'+'; break;
            case "pad-bits": data[^1] = (byte)'B'; break;
            case "ttl-low": change = change with { Ttl = 59 }; break;
            case "ttl-high": change = change with { Ttl = 3601 }; break;
            case "records": request = request with { Records = new[] { new ZoneRecordData(Challenge.ToWire(), 16, 300, Text()) } }; break;
        }
        if (invalid is "length" or "padding" or "alphabet" or "pad-bits")
            change = change with { Add = new ReadOnlyMemory<byte>[] { data } };
        request = request with { Changes = new[] { change } };
        _ = Assert.Throws<UnauthorizedAccessException>(() => Authorizer().Authorize(request));
    }

    [Fact]
    public void AcmeAllowsCanonicalNamesAndValueSpecificCleanup()
    {
        var authorizer = Authorizer();
        var request = Request();
        Assert.Equal("acme-test", authorizer.Authorize(request));
        var change = request.Changes[0] with { Owner = DnsName.Parse("_ACME-CHALLENGE.EXAMPLE.").ToWire(), Add = Array.Empty<ReadOnlyMemory<byte>>(), Remove = new ReadOnlyMemory<byte>[] { Text() } };
        Assert.Equal("acme-test", authorizer.Authorize(request with { Changes = new[] { change } }));
        var read = request with { Action = "read", Changes = Array.Empty<RrsetChange>(), Selection = new[] { new RrsetKey(Challenge.ToWire(), 16) } };
        Assert.Equal("acme-test", authorizer.Authorize(read));
        _ = Assert.Throws<UnauthorizedAccessException>(() => authorizer.Authorize(read with { Selection = new[] { new RrsetKey(DnsName.Parse("example.").ToWire(), 16) } }));
    }

    [Theory]
    [InlineData("delegation")]
    [InlineData("cname")]
    [InlineData("dname")]
    public void AcmeRequiresDirectAuthorityOverTheChallengeName(string obstruction)
    {
        var owner = DnsName.Parse("_acme-challenge.child.example.");
        var authorizer = new ScopedManagementAuthorizer([Grant() with { RecordScopes = new[] { new ManagementRecordScope(owner, 16) } }], TimeProvider.System);
        var record = obstruction switch
        {
            "delegation" => AuthorityFixture.Record("child.example.", 2, DnsName.Parse("ns.other.").ToWire()),
            "cname" => AuthorityFixture.Record(owner.ToString(), 5, DnsName.Parse("challenge.other.").ToWire()),
            _ => AuthorityFixture.Record("child.example.", 39, DnsName.Parse("other.").ToWire()),
        };
        var request = Request() with { Changes = new[] { Request().Changes[0] with { Owner = owner.ToWire() } } };
        _ = Assert.Throws<UnauthorizedAccessException>(() => authorizer.AuthorizeZone(request, AuthorityFixture.Zone(record)));
    }

    [Fact]
    public void RecordCredentialsCanReadOnlyTheirActorsOperationReceipts()
    {
        var authorizer = Authorizer();
        var request = Request() with { Action = "status", Changes = Array.Empty<RrsetChange>() };
        authorizer.AuthorizeOperation(request, "acme-test");
        _ = Assert.Throws<UnauthorizedAccessException>(() => authorizer.AuthorizeOperation(request, "other-actor"));
    }

    [Fact]
    public void GrantActionsAndRecordScopesArePinnedAndReadOnlyIsEnforced()
    {
        string[] actions = ["read"];
        ManagementRecordScope[] scopes = [new(Challenge, 16)];
        var authorizer = new ScopedManagementAuthorizer([Grant() with { Profile = "records", Actions = actions, RecordScopes = scopes }], TimeProvider.System);
        actions[0] = "patch";
        scopes[0] = new ManagementRecordScope(DnsName.Parse("elsewhere.example."), 16);
        var request = Request();
        _ = Assert.Throws<UnauthorizedAccessException>(() => authorizer.Authorize(request));
        Assert.Equal("acme-test", authorizer.Authorize(request with { Action = "read", Changes = Array.Empty<RrsetChange>(), Selection = new[] { new RrsetKey(Challenge.ToWire(), 16) } }));
    }

    [Theory]
    [InlineData("profile")]
    [InlineData("action")]
    [InlineData("outside")]
    [InlineData("ordinary-name")]
    [InlineData("wildcard")]
    [InlineData("type")]
    [InlineData("duplicate-scope")]
    [InlineData("empty-scope")]
    [InlineData("duplicate-actor")]
    [InlineData("duplicate-credential")]
    public void InvalidOrAmbiguousGrantsFailBeforeServing(string invalid)
    {
        var grant = Grant();
        grant = invalid switch
        {
            "profile" => grant with { Profile = "all" },
            "action" => grant with { Actions = new[] { "edit" } },
            "outside" => grant with { RecordScopes = new[] { new ManagementRecordScope(DnsName.Parse("_acme-challenge.other."), 16) } },
            "ordinary-name" => grant with { RecordScopes = new[] { new ManagementRecordScope(DnsName.Parse("www.example."), 16) } },
            "wildcard" => grant with { RecordScopes = new[] { new ManagementRecordScope(DnsName.Parse("_acme-challenge.*.example."), 16) } },
            "type" => grant with { RecordScopes = new[] { new ManagementRecordScope(Challenge, 1) } },
            "duplicate-scope" => grant with { RecordScopes = new[] { new ManagementRecordScope(Challenge, 16), new ManagementRecordScope(Challenge, 16) } },
            "empty-scope" => grant with { RecordScopes = Array.Empty<ManagementRecordScope>() },
            _ => grant,
        };
        var grants = invalid switch
        {
            "duplicate-actor" => new[] { grant, grant with { CredentialHash = SHA256.HashData(RandomNumberGenerator.GetBytes(32)) } },
            "duplicate-credential" => new[] { grant, grant with { Actor = "different" } },
            _ => new[] { grant },
        };
        _ = Assert.Throws<ArgumentException>(() => new ScopedManagementAuthorizer(grants, TimeProvider.System));
    }

    private ScopedManagementAuthorizer Authorizer() => new([Grant()], TimeProvider.System);
    private ManagementGrant Grant() => new(tenant, zone, DnsName.Parse("example."), "acme-test", DateTimeOffset.UtcNow.AddHours(1), SHA256.HashData(credential))
    {
        Profile = "acme",
        Actions = ["patch", "read", "status"],
        RecordScopes = [new(Challenge, 16)],
    };
    private ManagementRequest Request() => new("patch", tenant, zone, Guid.NewGuid(), 1, DnsName.Parse("example.").ToWire(), Array.Empty<ZoneRecordData>(), credential)
    {
        Changes = [new(Challenge.ToWire(), 16, 300, new ReadOnlyMemory<byte>[] { Text() }, Array.Empty<ReadOnlyMemory<byte>>(), Replace: false)],
    };
    private static byte[] Text() => new[] { (byte)43 }.Concat(Enumerable.Repeat((byte)'A', 43)).ToArray();
}
