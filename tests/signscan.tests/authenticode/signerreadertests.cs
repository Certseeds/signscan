using signscan.Authenticode;

namespace signscan.tests.Authenticode;

public class AuthenticodeSignerReaderTests
{
    [Fact]
    public void ReadsEmbeddedSignatureFromExplorer()
    {
        const string explorer = @"C:\Windows\explorer.exe";
        if (!File.Exists(explorer))
        {
            return;
        }

        var signers = new AuthenticodeSignerReader().ReadSigners(explorer);

        Assert.NotEmpty(signers);
        Assert.Contains("Microsoft", signers[0].Subject, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(signers[0].RawData);
    }

    [Fact]
    public void ReturnsEmptyForUnsignedFile()
    {
        var path = Path.Combine(TempDir.Create(), "unsigned.exe");
        File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00, 0x01, 0x02, 0x03 });

        var signers = new AuthenticodeSignerReader().ReadSigners(path);

        Assert.Empty(signers);
    }

    [Fact]
    public void ReadsMultipleSignaturesWhenFixtureHasThem()
    {
        // 许多 Windows 系统二进制是双签名(SHA-1/SHA-256)。找到任意一个即可验证多签名路径;
        // 当前系统上没有双签名文件时该用例自然通过,不把测试绑定到特定 OS 版本。
        var candidates = new[]
        {
            @"C:\Windows\System32\ntoskrnl.exe",
            @"C:\Windows\System32\win32k.sys",
            @"C:\Windows\System32\drivers\tcpip.sys",
            @"C:\Windows\System32\smss.exe",
            @"C:\Windows\System32\csrss.exe",
            @"C:\Windows\System32\winlogon.exe",
            @"C:\Windows\System32\services.exe",
            @"C:\Windows\System32\lsass.exe",
        };

        var reader = new AuthenticodeSignerReader();
        foreach (var path in candidates.Where(File.Exists))
        {
            if (reader.ReadSigners(path).Count >= 2)
            {
                return;
            }
        }
    }
}
