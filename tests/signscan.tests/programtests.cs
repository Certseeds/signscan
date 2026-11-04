using signscan.Naming;

namespace signscan.tests;

public class ProgramTests
{
    [Fact]
    public void RejectsWhenNeitherDirectoryIsProvided()
        => Assert.NotNull(Program.ValidateMode(null, null));

    [Fact]
    public void RejectsWhenBothDirectoriesAreProvided()
        => Assert.NotNull(Program.ValidateMode(new DirectoryInfo("in"), new DirectoryInfo("allow")));

    [Fact]
    public void AcceptsInputDirectoryOnly()
        => Assert.Null(Program.ValidateMode(new DirectoryInfo("in"), null));

    [Fact]
    public void AcceptsAllowDirectoryOnly()
        => Assert.Null(Program.ValidateMode(null, new DirectoryInfo("allow")));

    [Fact]
    public void ReturnsExitCodeTwoWhenAllowDirectoryIsMissing()
    {
        var root = TempDir.Create();
        var output = Path.Combine(root, "output");
        Directory.CreateDirectory(output);

        Assert.Equal(2, Program.Run(null, new DirectoryInfo(Path.Combine(root, "missing")), new DirectoryInfo(output)));
    }

    [Fact]
    public void ReturnsExitCodeTwoWhenOutputDirectoryIsMissing()
    {
        var root = TempDir.Create();
        var allow = Path.Combine(root, "allow");
        Directory.CreateDirectory(allow);

        Assert.Equal(2, Program.Run(null, new DirectoryInfo(allow), new DirectoryInfo(Path.Combine(root, "missing"))));
    }

    [Fact]
    public void ReturnsExitCodeTwoWhenNoArgumentsAreProvided()
    {
        Assert.Equal(2, Program.Main(Array.Empty<string>()));
    }

    [Fact]
    public void ReturnsExitCodeOneWhenCertificateDeletionFails()
    {
        var root = TempDir.Create();
        var allow = Path.Combine(root, "allow");
        var output = Path.Combine(root, "output");
        Directory.CreateDirectory(allow);
        Directory.CreateDirectory(output);
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);
        reader.Map[TempDir.WriteFile(allow, "A/x.exe")] = new[] { signer };
        var target = TempDir.WriteFile(output, Path.Combine("A", name));

        using (File.Open(target, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.Equal(1, Program.RunAllow(new DirectoryInfo(allow), new DirectoryInfo(output), reader));
        }
    }
}
