using signscan.Authenticode;

namespace signscan.tests.Authenticode;

public class PeCertificateTableTests
{
    [Fact]
    public void ReadsBlobsFromSignedFile()
    {
        const string explorer = @"C:\Windows\explorer.exe";
        if (!File.Exists(explorer))
        {
            return;
        }

        var blobs = PeCertificateTable.ReadBlobs(explorer);

        Assert.NotEmpty(blobs);
        Assert.All(blobs, blob => Assert.NotEmpty(blob));
    }

    [Fact]
    public void ReturnsEmptyForInvalidPe()
    {
        var path = Path.Combine(TempDir.Create(), "invalid.exe");
        File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00, 0x01, 0x02, 0x03 });

        Assert.Empty(PeCertificateTable.ReadBlobs(path));
    }
}
