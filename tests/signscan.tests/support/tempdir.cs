using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace signscan.tests.Support;

internal static class TempDir
{
    internal static string Create()
    {
        var path = Path.Combine(Path.GetTempPath(), "signscan-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    internal static string WriteFile(string root, string relativePath, byte[]? content = null)
    {
        var full = Path.Combine(root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, content ?? Array.Empty<byte>());
        return Path.GetFullPath(full);
    }

    internal static SignerCertificate Signer(
        DateTime? notBefore = null,
        DateTime? notAfter = null,
        string subject = "CN=signscan-test")
    {
        var start = notBefore ?? new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var end = notAfter ?? new DateTime(2026, 6, 30, 0, 0, 0, DateTimeKind.Utc);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.3") }, critical: false));

        using var cert = request.CreateSelfSigned(
            new DateTimeOffset(start),
            new DateTimeOffset(end));

        return new SignerCertificate(
            cert.RawData,
            cert.NotBefore.ToUniversalTime(),
            cert.NotAfter.ToUniversalTime(),
            cert.Subject);
    }
}
