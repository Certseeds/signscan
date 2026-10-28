using System.Security.Cryptography;
using signscan.Naming;

namespace signscan.tests.Naming;

public class CertFileNameTests
{
    [Fact]
    public void UsesUtcDatesAndLowercaseSha256()
    {
        var signer = TempDir.Signer(
            new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            new DateTime(2026, 6, 30, 0, 0, 0, DateTimeKind.Utc));

        var name = CertFileName.From(signer);
        var expectedHash = Convert.ToHexString(SHA256.HashData(signer.RawData)).ToLowerInvariant();

        Assert.Equal($"20210101-20260630-{expectedHash}.cer", name);
        Assert.Matches("^20210101-20260630-[0-9a-f]{64}\\.cer$", name);
    }

    [Fact]
    public void DifferentCertificatesProduceDifferentNames()
    {
        var first = TempDir.Signer();
        var second = TempDir.Signer();

        Assert.NotEqual(CertFileName.From(first), CertFileName.From(second));
    }
}
