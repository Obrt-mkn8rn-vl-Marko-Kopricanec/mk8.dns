using System.Buffers.Binary;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SipHashTests
{
    [Theory]
    [InlineData(0, "310e0edd47db6f72")]
    [InlineData(1, "fd67dc93c539f874")]
    [InlineData(2, "5a4fa9d909806c0d")]
    [InlineData(3, "2d7efbd796666785")]
    [InlineData(4, "b7877127e09427cf")]
    [InlineData(5, "8da699cd64557618")]
    [InlineData(6, "cee3fe586e46c9cb")]
    [InlineData(7, "37d1018bf50002ab")]
    [InlineData(8, "6224939a79f5f593")]
    [InlineData(9, "b0e4a90bdf82009e")]
    [InlineData(10, "f3b9dd94c5bb5d7a")]
    [InlineData(11, "a7ad6b22462fb3f4")]
    [InlineData(12, "fbe50e86bc8f1e75")]
    [InlineData(13, "903d84c02756ea14")]
    [InlineData(14, "eef27a8e90ca23f7")]
    [InlineData(15, "e545be4961ca29a1")]
    [InlineData(16, "db9bc2577fcc2a3f")]
    [InlineData(17, "9447be2cf5e99a69")]
    [InlineData(18, "9cd38d96f0b3c14b")]
    [InlineData(19, "bd6179a71dc96dbb")]
    [InlineData(20, "98eea21af25cd6be")]
    [InlineData(21, "c7673b2eb0cbf2d0")]
    [InlineData(22, "883ea3e395675393")]
    [InlineData(23, "c8ce5ccd8c030ca8")]
    [InlineData(24, "94af49f6c650adb8")]
    [InlineData(25, "eab8858ade92e1bc")]
    [InlineData(26, "f315bb5bb835d817")]
    [InlineData(27, "adcf6b0763612e2f")]
    [InlineData(28, "a5c91da7acaa4dde")]
    [InlineData(29, "716595876650a2a6")]
    [InlineData(30, "28ef495c53a387ad")]
    [InlineData(31, "42c341d8fa92d832")]
    [InlineData(32, "ce7cf2722f512771")]
    [InlineData(33, "e37859f94623f3a7")]
    [InlineData(34, "381205bb1ab0e012")]
    [InlineData(35, "ae97a10fd434e015")]
    [InlineData(36, "b4a31508beff4d31")]
    [InlineData(37, "81396229f0907902")]
    [InlineData(38, "4d0cf49ee5d4dcca")]
    [InlineData(39, "5c73336a76d8bf9a")]
    [InlineData(40, "d0a704536ba93e0e")]
    [InlineData(41, "925958fcd6420cad")]
    [InlineData(42, "a915c29bc8067318")]
    [InlineData(43, "952b79f3bc0aa6d4")]
    [InlineData(44, "f21df2e41d4535f9")]
    [InlineData(45, "87577519048f53a9")]
    [InlineData(46, "10a56cf5dfcd9adb")]
    [InlineData(47, "eb75095ccd986cd0")]
    [InlineData(48, "51a9cb9ecba312e6")]
    [InlineData(49, "96afadfc2ce666c7")]
    [InlineData(50, "72fe52975a4364ee")]
    [InlineData(51, "5a1645b276d592a1")]
    [InlineData(52, "b274cb8ebf87870a")]
    [InlineData(53, "6f9bb4203de7b381")]
    [InlineData(54, "eaecb2a30b22a87f")]
    [InlineData(55, "9924a43cc1315724")]
    [InlineData(56, "bd838d3aafbf8db7")]
    [InlineData(57, "0b1a2a3265d51aea")]
    [InlineData(58, "135079a3231ce660")]
    [InlineData(59, "932b2846e4d70666")]
    [InlineData(60, "e1915f5cb1eca46c")]
    [InlineData(61, "f325965ca16d629f")]
    [InlineData(62, "575ff28e60381be5")]
    [InlineData(63, "724506eb4c328a95")]
    public void PublishedReferenceVectorsAgree(int length, string expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        var sequence = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();
        var key = sequence[..16];
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(result, SipHash24.Hash(sequence.AsSpan(0, length), key));
        Assert.Equal(Convert.FromHexString(expected), result);
    }
}
