using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using OpenMcdf;
using signscan.Authenticode;
using signscan.Naming;

namespace signscan.tests.Authenticode;

public class MsiSignerReaderTests
{
    [Fact]
    public void ReadsSignerFromDigitalSignatureStream()
    {
        var path = Path.Combine(TempDir.Create(), "signed.msi");
        var (blob, signer) = CreateSignature();
        WriteMsi(path, blob);

        var signers = new MsiSignerReader().ReadSigners(path);

        Assert.Single(signers);
        Assert.Contains(signer.Subject, signers[0].Subject, StringComparison.Ordinal);
        Assert.NotEmpty(signers[0].RawData);
    }

    [Theory]
    [InlineData("renamed.exe")]
    [InlineData("patch.msp")]
    [InlineData("transform.mst")]
    public void DispatchesCfbByHeader(string fileName)
    {
        var path = Path.Combine(TempDir.Create(), fileName);
        var (blob, signer) = CreateSignature();
        WriteMsi(path, blob);

        var signers = new FileSignerReader().ReadSigners(path);

        Assert.Single(signers);
        Assert.Contains(signer.Subject, signers[0].Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void AllowModeRemovesMsiCertificate()
    {
        var root = TempDir.Create();
        var allow = Path.Combine(root, "allow");
        var output = Path.Combine(root, "output");
        Directory.CreateDirectory(output);

        var msi = Path.Combine(allow, "A", "setup.msi");
        Directory.CreateDirectory(Path.GetDirectoryName(msi)!);
        var (blob, signer) = CreateSignature();
        WriteMsi(msi, blob);

        var target = TempDir.WriteFile(output, Path.Combine("A", CertFileName.From(signer)));

        var exit = Program.Run(null, new DirectoryInfo(allow), new DirectoryInfo(output));

        Assert.Equal(0, exit);
        Assert.False(File.Exists(target));
    }

    [Fact]
    public void ReturnsEmptyWhenSignatureStreamMissing()
    {
        var path = Path.Combine(TempDir.Create(), "unsigned.msi");
        using (var root = RootStorage.Create(path, OpenMcdf.Version.V3, StorageModeFlags.Transacted))
        {
            root.Commit();
        }

        Assert.Empty(new MsiSignerReader().ReadSigners(path));
    }

    [Fact]
    public void ReturnsEmptyForInvalidSignatureData()
    {
        var path = Path.Combine(TempDir.Create(), "corrupt.msi");
        WriteMsi(path, new byte[] { 1, 2, 3 });

        Assert.Empty(new MsiSignerReader().ReadSigners(path));
    }

    [Fact]
    public void ReturnsEmptyForNonCfbFile()
    {
        var path = Path.Combine(TempDir.Create(), "not-cfb.msi");
        File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x00 });

        Assert.Empty(new MsiSignerReader().ReadSigners(path));
    }

    private static void WriteMsi(string path, byte[] signature)
    {
        using var root = RootStorage.Create(path, OpenMcdf.Version.V3, StorageModeFlags.Transacted);
        using (var stream = root.CreateStream("\u0005DigitalSignature"))
        {
            stream.Write(signature);
        }

        root.Commit();
    }

    private static (byte[] Blob, SignerCertificate Signer) CreateSignature()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=msi-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        var cms = new SignedCms(new ContentInfo(new byte[] { 1, 2, 3 }), detached: false);
        cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert)
        {
            IncludeOption = X509IncludeOption.EndCertOnly,
        });

        var signer = new SignerCertificate(
            cert.RawData,
            cert.NotBefore.ToUniversalTime(),
            cert.NotAfter.ToUniversalTime(),
            cert.Subject);
        return (cms.Encode(), signer);
    }
}
