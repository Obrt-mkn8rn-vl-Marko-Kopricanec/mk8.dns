using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Mk8.Dns.Application.DAL;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorStorageLeaseTests
{
    [Theory]
    [InlineData(-1, 95)]
    [InlineData(-1, 13)]
    [InlineData(-1, 5)]
    [InlineData(-1, 4)]
    [InlineData(-1, 11)]
    [InlineData(1, 0)]
    public void FailedNativeAcquisitionCannotInitializeAndReleasesItsActualHandle(int result, int error)
    {
        using var fixture = new AnchorStorageFixture();
        SafeFileHandle? acquired = null;
        var exception = Assert.Throws<IOException>(() =>
        {
            using var ignored = FileAnchorCheckpointStore.CreateCore(fixture.Root, fixture.Identity,
                fixture.Keys.Tracker(fixture.Keys.A), fixture.Secret, null, (handle, operation) =>
                {
                    Assert.False(handle.IsInvalid);
                    Assert.False(handle.IsClosed);
                    Assert.Equal(6, operation);
                    acquired = handle;
                    Marshal.SetLastPInvokeError(error);
                    return result;
                });
        });
        Assert.Equal(error, Assert.IsType<Win32Exception>(exception.InnerException).NativeErrorCode);
        Assert.NotNull(acquired);
        Assert.True(acquired.IsClosed);
        Assert.Empty(fixture.Image());
        Assert.Empty(File.ReadAllBytes(fixture.Marker));
        using var successor = fixture.Create();
        Assert.Equal(1, successor.Revision);
    }

    [Fact]
    public void ExclusiveOwnershipDoesNotDependOnManagedFileSharing()
    {
        using var fixture = new AnchorStorageFixture();
        var controlPath = Path.Combine(Path.GetDirectoryName(fixture.Root)!, "sharing-control");
        using (var control = new FileStream(controlPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            if (string.Equals(Environment.GetEnvironmentVariable("DOTNET_SYSTEM_IO_DISABLEFILELOCKING"), "1", StringComparison.Ordinal))
            {
                using var unleased = new FileStream(controlPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                Assert.Equal(control.Length, unleased.Length);
            }
            else
                Assert.Throws<IOException>(() => { using var ignored = new FileStream(controlPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None); });
        }

        var holder = fixture.Create();
        try
        {
            Assert.Throws<IOException>(() => { using var ignored = fixture.Open(); });
            Assert.Equal(1, holder.Revision);
        }
        finally
        {
            holder.Dispose();
        }
        using var successor = fixture.Open();
        Assert.Equal(1, successor.Revision);
        Assert.Equal(2, successor.Save(1));
    }
}
