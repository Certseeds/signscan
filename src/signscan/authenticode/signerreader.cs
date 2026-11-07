namespace signscan.Authenticode;

/// <summary>
/// 用 PEReader 定位 PE 证书表,用 SignedCms 解析 PKCS#7,
/// 并递归读取 /as 生成的嵌套签名。
/// </summary>
internal sealed class AuthenticodeSignerReader : ISignerReader
{
    public IReadOnlyList<SignerCertificate> ReadSigners(string filePath)
    {
        var path = Path.GetFullPath(filePath);
        if (!File.Exists(path))
        {
            return Array.Empty<SignerCertificate>();
        }

        var result = new List<SignerCertificate>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var blob in PeCertificateTable.ReadBlobs(path))
        {
            SignedCmsCertificateReader.Read(blob, result, seen, depth: 0);
        }

        return result;
    }
}
