using Mk8.Dns.Application.DAL;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorStoragePathTests
{
    [Theory]
    [InlineData("unknown")]
    [InlineData("0000000000000000.anchor")]
    [InlineData("0000000000000101.anchor")]
    [InlineData("000000000000000A.anchor")]
    [InlineData("not-a-guid.tmp")]
    public void UnknownOrNoncanonicalRegularEntryIsNotHidden(string entry)
    {
        using var f = new AnchorStorageFixture(); using (f.Create()) { }
        AnchorStorageFixture.Write(Path.Combine(f.Root, entry), [1]);
        var before = f.Image();
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(); });
        Assert.Equal(before, f.Image());
    }

    [Theory]
    [InlineData("active.bin", false)]
    [InlineData("active.bin", true)]
    [InlineData(".writer.lock", false)]
    [InlineData(".writer.lock", true)]
    [InlineData("0000000000000001.anchor", false)]
    [InlineData("0000000000000001.anchor", true)]
    public void DirectoryOrSymlinkCannotImpersonateStorageFile(string entry, bool symlink)
    {
        using var f = new AnchorStorageFixture(); using (f.Create()) { }
        var target = Path.Combine(f.Root, entry); var original = File.ReadAllBytes(target); File.Delete(target);
        if (symlink)
        {
            var backing = Path.Combine(f.Root, "backing.tmp"); AnchorStorageFixture.Write(backing, original);
            _ = File.CreateSymbolicLink(target, backing);
        }
        else Directory.CreateDirectory(target);
        Assert.ThrowsAny<IOException>(() => { using var ignored = f.Open(); });
        Assert.True(Directory.Exists(target) || new FileInfo(target).LinkTarget is not null);
    }

    [Fact]
    public void NonDirectoryAncestorCannotBecomeFreshStorage()
    {
        using var parent = new TemporaryDirectory();
        var file = Path.Combine(parent.Path, "file"); File.WriteAllBytes(file, [7]);
        using var f = new AnchorStorageFixture();
        Assert.ThrowsAny<IOException>(() =>
        { using var ignored = FileAnchorCheckpointStore.Create(Path.Combine(file, "state"), f.Identity, f.Keys.Tracker(f.Keys.A), f.Secret); });
        Assert.Equal(new byte[] { 7 }, File.ReadAllBytes(file));
    }

    [Fact]
    public void RecoveryDoesNotCreateAbsentRootAndRegularGuidTemporariesAreOnlyUnacknowledgedDebris()
    {
        using var f = new AnchorStorageFixture();
        Assert.Throws<IOException>(() => { using var ignored = f.Open(); });
        Assert.False(Directory.Exists(f.Root));
        using var store = f.Create(); store.Dispose();
        var temporary = Path.Combine(f.Root, Guid.NewGuid().ToString("N") + ".tmp"); AnchorStorageFixture.Write(temporary, [5]);
        using var recovered = f.Open(); Assert.Equal(1, recovered.Revision);
        Assert.Equal(new byte[] { 5 }, File.ReadAllBytes(temporary));
    }

    [Fact]
    public void PrivateModesAreRequiredAndWrittenWithoutWorldAccess()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        using var f = new AnchorStorageFixture(); using (f.Create()) { }
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(f.Root));
        foreach (var file in Directory.EnumerateFiles(f.Root)) Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
        File.SetUnixFileMode(f.Head, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
        Assert.Throws<IOException>(() => { using var ignored = f.Open(); });
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead, File.GetUnixFileMode(f.Head));
    }
}
