namespace signscan.tests;

public class AtomicFileTests
{
    [Fact]
    public void WritesContentAndLeavesOnlyTheDestination()
    {
        var dir = TempDir.Create();
        var path = Path.Combine(dir, "cert.cer");
        var content = new byte[] { 1, 2, 3 };

        AtomicFile.WriteAllBytes(path, content);

        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(dir));
    }

    [Fact]
    public void OverwritesExistingFile()
    {
        var dir = TempDir.Create();
        var path = Path.Combine(dir, "cert.cer");
        File.WriteAllBytes(path, new byte[] { 9 });

        AtomicFile.WriteAllBytes(path, new byte[] { 1 });

        Assert.Equal(new byte[] { 1 }, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(dir));
    }

    [Fact]
    public void KeepsOriginalAndRemovesTemporaryFileWhenReplacementFails()
    {
        var dir = TempDir.Create();
        var path = Path.Combine(dir, "cert.cer");
        File.WriteAllBytes(path, new byte[] { 9 });

        using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var exception = Record.Exception(() => AtomicFile.WriteAllBytes(path, new byte[] { 1 }));
            Assert.True(exception is IOException or UnauthorizedAccessException);
        }

        Assert.Equal(new byte[] { 9 }, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(dir));
    }
}
