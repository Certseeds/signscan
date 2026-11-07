using System.Security.Cryptography;
using OpenMcdf;

namespace signscan.Authenticode;

/// <summary>从 Windows Installer 复合文档(MSI/MSP/MST)的 \u0005DigitalSignature 流读取 PKCS#7 签名。</summary>
internal sealed class MsiSignerReader : ISignerReader
{
    private const string DigitalSignatureStreamName = "\u0005DigitalSignature";
    private const long MaxSignatureBytes = 16 * 1024 * 1024;

    public IReadOnlyList<SignerCertificate> ReadSigners(string filePath)
    {
        var path = Path.GetFullPath(filePath);
        if (!File.Exists(path))
        {
            return Array.Empty<SignerCertificate>();
        }

        try
        {
            using var root = RootStorage.OpenRead(path, StorageModeFlags.None);
            if (!root.TryOpenStream(DigitalSignatureStreamName, out var stream))
            {
                return Array.Empty<SignerCertificate>();
            }

            using (stream)
            {
                if (stream.Length <= 0 || stream.Length > MaxSignatureBytes)
                {
                    return Array.Empty<SignerCertificate>();
                }

                var blob = new byte[(int)stream.Length];
                stream.ReadExactly(blob);
                return SignedCmsCertificateReader.Read(blob);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or FileFormatException or CryptographicException
                                       or InvalidOperationException or ArgumentException)
        {
            return Array.Empty<SignerCertificate>();
        }
    }
}
