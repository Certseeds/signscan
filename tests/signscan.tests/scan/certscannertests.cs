using signscan.Scan;

namespace signscan.tests.Scan;

public class CertScannerTests
{
    [Fact]
    public void FlattensToTopLevelDirectoryAndGroupsRootAsOthers()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();

        reader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { TempDir.Signer() };
        reader.Map[TempDir.WriteFile(input, "A/A1/A1-1/y.exe")] = new[] { TempDir.Signer() };
        reader.Map[TempDir.WriteFile(input, "B/z.exe")] = new[] { TempDir.Signer() };
        reader.Map[TempDir.WriteFile(input, "root.exe")] = new[] { TempDir.Signer() };

        var result = CertScanner.Scan(new ScanOptions(input, output, reader));

        Assert.Equal(4, result.ExeCount);
        Assert.Equal(4, result.SignedCount);
        Assert.Equal(4, result.CertCount);
        Assert.Equal(2, Directory.GetFiles(Path.Combine(output, "A"), "*.cer").Length);
        Assert.Single(Directory.GetFiles(Path.Combine(output, "B"), "*.cer"));
        Assert.Single(Directory.GetFiles(Path.Combine(output, "others"), "*.cer"));
        Assert.False(Directory.Exists(Path.Combine(output, "A", "A1")));
    }

    [Fact]
    public void DeduplicatesSameCertificateWithinTopLevelGroup()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();

        reader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { signer };
        reader.Map[TempDir.WriteFile(input, "A/A2/y.exe")] = new[] { signer };

        var result = CertScanner.Scan(new ScanOptions(input, output, reader));

        Assert.Equal(2, result.ExeCount);
        Assert.Equal(1, result.CertCount);
        Assert.Single(Directory.GetFiles(Path.Combine(output, "A"), "*.cer"));
    }

    [Fact]
    public void WritesOneFilePerSignatureWhenExeHasMultipleSigners()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();

        reader.Map[TempDir.WriteFile(input, "A/x.exe")] = new[] { TempDir.Signer(), TempDir.Signer() };

        var result = CertScanner.Scan(new ScanOptions(input, output, reader));

        Assert.Equal(2, result.CertCount);
        Assert.Equal(2, Directory.GetFiles(Path.Combine(output, "A"), "*.cer").Length);
    }

    [Fact]
    public void SkipsUnsignedExe()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();
        TempDir.WriteFile(input, "A/x.exe");

        var result = CertScanner.Scan(new ScanOptions(input, output, reader));

        Assert.Equal(1, result.ExeCount);
        Assert.Equal(1, result.SkippedCount);
        Assert.Equal(0, result.CertCount);
        Assert.False(Directory.Exists(Path.Combine(output, "A")));
    }

    [Fact]
    public void IgnoresNonExeFiles()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();
        TempDir.WriteFile(input, "A/x.dll");
        TempDir.WriteFile(input, "A/x.sys");

        var result = CertScanner.Scan(new ScanOptions(input, output, reader));

        Assert.Equal(0, result.ExeCount);
        Assert.Equal(0, reader.Calls);
    }

    [Fact]
    public void ScansUppercaseExeExtension()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();
        reader.Map[TempDir.WriteFile(input, "A/x.EXE")] = new[] { TempDir.Signer() };

        var result = CertScanner.Scan(new ScanOptions(input, output, reader));

        Assert.Equal(1, result.ExeCount);
        Assert.Single(Directory.GetFiles(Path.Combine(output, "A"), "*.cer"));
    }

    [Fact]
    public void DoesNotScanOutputDirectoryWhenItIsInsideInput()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(input, "out");
        var reader = new FakeSignerReader();
        reader.Map[TempDir.WriteFile(input, "A/x.exe")] = new[] { TempDir.Signer() };
        TempDir.WriteFile(input, "out/leak.exe");

        var result = CertScanner.Scan(new ScanOptions(input, output, reader));

        Assert.Equal(1, result.ExeCount);
    }
}
