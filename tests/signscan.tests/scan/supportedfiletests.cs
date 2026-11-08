using signscan.Scan;

namespace signscan.tests.Scan;

public class SupportedFileTests
{
    [Theory]
    [InlineData("x.exe")]
    [InlineData("x.EXE")]
    [InlineData("x.dll")]
    [InlineData("x.sys")]
    [InlineData("x.drv")]
    [InlineData("x.ocx")]
    [InlineData("x.cpl")]
    [InlineData("x.scr")]
    [InlineData("x.msi")]
    [InlineData("x.msp")]
    [InlineData("x.mst")]
    public void SupportsExpectedExtensions(string filePath)
        => Assert.True(SupportedFile.IsSupported(filePath));

    [Theory]
    [InlineData("x.txt")]
    [InlineData("x.pyd")]
    [InlineData("x.node")]
    [InlineData("x.mui")]
    [InlineData("x.efi")]
    [InlineData("x.winmd")]
    [InlineData("x")]
    [InlineData("x.dll.bak")]
    public void RejectsOtherExtensions(string filePath)
        => Assert.False(SupportedFile.IsSupported(filePath));
}
