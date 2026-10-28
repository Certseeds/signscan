using System.Globalization;

namespace signscan.Naming;

internal static class CertFileName
{
    internal static string From(SignerCertificate cert)
    {
        var notBefore = cert.NotBeforeUtc.ToUniversalTime().ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var notAfter = cert.NotAfterUtc.ToUniversalTime().ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        return $"{notBefore}-{notAfter}-{cert.Sha256}.cer";
    }
}
