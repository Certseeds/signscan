using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace signscan.Authenticode;

/// <summary>解析 PKCS#7 blob,提取签名者证书,并递归处理嵌套签名。</summary>
internal static class SignedCmsCertificateReader
{
    private const string NestedSignatureOid = "1.3.6.1.4.1.311.2.4.1";
    private const int MaxNestedDepth = 8;

    internal static IReadOnlyList<SignerCertificate> Read(byte[] blob)
    {
        var result = new List<SignerCertificate>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        Read(blob, result, seen, depth: 0);
        return result;
    }

    internal static void Read(
        byte[] blob,
        List<SignerCertificate> result,
        HashSet<string> seen,
        int depth)
    {
        if (depth > MaxNestedDepth || blob.Length == 0 || !TryDecode(blob, out var cms))
        {
            return;
        }

        foreach (SignerInfo signer in cms.SignerInfos)
        {
            var cert = signer.Certificate;
            if (cert is not null)
            {
                var signerCertificate = new SignerCertificate(
                    cert.RawData,
                    cert.NotBefore.ToUniversalTime(),
                    cert.NotAfter.ToUniversalTime(),
                    cert.Subject);

                if (seen.Add(signerCertificate.Sha256))
                {
                    result.Add(signerCertificate);
                }
            }

            foreach (var nested in FindNestedSignatureBlobs(signer))
            {
                Read(nested, result, seen, depth + 1);
            }
        }
    }

    private static bool TryDecode(byte[] blob, out SignedCms cms)
    {
        cms = new SignedCms();
        try
        {
            cms.Decode(blob);
            return true;
        }
        catch (CryptographicException)
        {
        }

        // 嵌套签名属性里的值可能带一层 OCTET STRING,先拆掉再试。
        if (TryUnwrapOctetString(blob, out var content))
        {
            var unwrapped = new SignedCms();
            try
            {
                unwrapped.Decode(content);
                cms = unwrapped;
                return true;
            }
            catch (CryptographicException)
            {
            }
        }

        return false;
    }

    private static IEnumerable<byte[]> FindNestedSignatureBlobs(SignerInfo signer)
    {
        var attributes = signer.UnsignedAttributes;
        if (attributes is null)
        {
            yield break;
        }

        foreach (CryptographicAttributeObject attribute in attributes)
        {
            if (!string.Equals(attribute.Oid.Value, NestedSignatureOid, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (AsnEncodedData value in attribute.Values)
            {
                yield return value.RawData;
            }
        }
    }

    private static bool TryUnwrapOctetString(byte[] blob, out byte[] content)
    {
        content = Array.Empty<byte>();
        try
        {
            var reader = new AsnReader(blob, AsnEncodingRules.BER);
            var inner = reader.ReadOctetString();
            if (reader.HasData)
            {
                return false;
            }

            content = inner;
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }
}
