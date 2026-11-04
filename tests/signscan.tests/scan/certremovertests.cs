using signscan.Naming;
using signscan.Scan;

namespace signscan.tests.Scan;

public class CertRemoverTests
{
    [Fact]
    public void RemovesCertificateOnlyFromItsOwnTopLevelGroup()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);

        reader.Map[TempDir.WriteFile(allow, "A/x.exe")] = new[] { signer };
        var own = TempDir.WriteFile(output, Path.Combine("A", name));
        var other = TempDir.WriteFile(output, Path.Combine("B", name));

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(1, result.ExeCount);
        Assert.Equal(1, result.SignedCount);
        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(0, result.MissingCount);
        Assert.False(File.Exists(own));
        Assert.True(File.Exists(other));
    }

    [Fact]
    public void RootDirectoryExeMapsToOthers()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        reader.Map[TempDir.WriteFile(allow, "x.exe")] = new[] { signer };
        var target = TempDir.WriteFile(output, Path.Combine("others", CertFileName.From(signer)));

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(1, result.RemovedCount);
        Assert.False(File.Exists(target));
    }

    [Fact]
    public void RemovesAllCertificatesForMultiSignedExe()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        var first = TempDir.Signer();
        var second = TempDir.Signer();
        reader.Map[TempDir.WriteFile(allow, "A/x.exe")] = new[] { first, second };
        var firstTarget = TempDir.WriteFile(output, Path.Combine("A", CertFileName.From(first)));
        var secondTarget = TempDir.WriteFile(output, Path.Combine("A", CertFileName.From(second)));

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(2, result.RemovedCount);
        Assert.False(File.Exists(firstTarget));
        Assert.False(File.Exists(secondTarget));
    }

    [Fact]
    public void DeduplicatesSameCertificateAcrossWhitelistExes()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        reader.Map[TempDir.WriteFile(allow, "A/x.exe")] = new[] { signer };
        reader.Map[TempDir.WriteFile(allow, "A/y.exe")] = new[] { signer };
        var target = TempDir.WriteFile(output, Path.Combine("A", CertFileName.From(signer)));

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(1, result.RemovedCount);
        Assert.Equal(0, result.MissingCount);
        Assert.Empty(result.Warnings);
        Assert.False(File.Exists(target));
    }

    [Fact]
    public void SameCertificateInTwoWhitelistGroupsRemovesBoth()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);
        reader.Map[TempDir.WriteFile(allow, "A/x.exe")] = new[] { signer };
        reader.Map[TempDir.WriteFile(allow, "B/y.exe")] = new[] { signer };
        var inA = TempDir.WriteFile(output, Path.Combine("A", name));
        var inB = TempDir.WriteFile(output, Path.Combine("B", name));

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(2, result.RemovedCount);
        Assert.False(File.Exists(inA));
        Assert.False(File.Exists(inB));
    }

    [Fact]
    public void MissingCertificateCountsAndWarns()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);
        reader.Map[TempDir.WriteFile(allow, "A/x.exe")] = new[] { signer };

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(0, result.RemovedCount);
        Assert.Equal(1, result.MissingCount);
        Assert.Contains(result.Warnings, w => w.Contains(name, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SkipsUnsignedExe()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        TempDir.WriteFile(allow, "A/x.exe");

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(1, result.ExeCount);
        Assert.Equal(0, result.SignedCount);
        Assert.Equal(1, result.SkippedCount);
        Assert.Equal(0, result.RemovedCount);
        Assert.False(Directory.Exists(Path.Combine(output, "A")));
    }

    [Fact]
    public void IgnoresNonExeFiles()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        TempDir.WriteFile(allow, "A/x.dll");
        TempDir.WriteFile(allow, "A/x.sys");

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(0, result.ExeCount);
        Assert.Equal(0, reader.Calls);
    }

    [Fact]
    public void EmptyAllowDirectoryReturnsZeroCounts()
    {
        var (allow, output) = CreateDirs();

        var result = CertRemover.Remove(new RemoveOptions(allow, output, new FakeSignerReader()));

        Assert.Equal(0, result.ExeCount);
        Assert.Equal(0, result.RemovedCount);
        Assert.Equal(0, result.MissingCount);
        Assert.Empty(Directory.GetDirectories(output));
    }

    [Fact]
    public void CountsErrorAndContinuesWhenCertificateIsLocked()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        var lockedSigner = TempDir.Signer();
        var freeSigner = TempDir.Signer();
        var lockedName = CertFileName.From(lockedSigner);
        var freeName = CertFileName.From(freeSigner);
        reader.Map[TempDir.WriteFile(allow, "A/x.exe")] = new[] { lockedSigner, freeSigner };
        var locked = TempDir.WriteFile(output, Path.Combine("A", lockedName));
        var free = TempDir.WriteFile(output, Path.Combine("A", freeName));

        using (File.Open(locked, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

            Assert.Equal(1, result.RemovedCount);
            Assert.Equal(1, result.ErrorCount);
            Assert.True(File.Exists(locked));
            Assert.False(File.Exists(free));
            Assert.Contains(result.Warnings, w => w.Contains(lockedName, StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void ThrowsWhenAllowDirectoryIsMissing()
    {
        var root = TempDir.Create();
        var output = Path.Combine(root, "output");
        Directory.CreateDirectory(output);

        Assert.Throws<DirectoryNotFoundException>(
            () => CertRemover.Remove(new RemoveOptions(Path.Combine(root, "missing"), output, new FakeSignerReader())));
    }

    [Fact]
    public void ThrowsWhenOutputDirectoryIsMissing()
    {
        var root = TempDir.Create();
        var allow = Path.Combine(root, "allow");
        Directory.CreateDirectory(allow);

        Assert.Throws<DirectoryNotFoundException>(
            () => CertRemover.Remove(new RemoveOptions(allow, Path.Combine(root, "missing"), new FakeSignerReader())));
    }

    [Fact]
    public void ScansUppercaseExeExtension()
    {
        var (allow, output) = CreateDirs();
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        reader.Map[TempDir.WriteFile(allow, "A/x.EXE")] = new[] { signer };
        var target = TempDir.WriteFile(output, Path.Combine("A", CertFileName.From(signer)));

        var result = CertRemover.Remove(new RemoveOptions(allow, output, reader));

        Assert.Equal(1, result.RemovedCount);
        Assert.False(File.Exists(target));
    }

    private static (string Allow, string Output) CreateDirs()
    {
        var root = TempDir.Create();
        var allow = Path.Combine(root, "allow");
        var output = Path.Combine(root, "output");
        Directory.CreateDirectory(allow);
        Directory.CreateDirectory(output);
        return (allow, output);
    }
}
