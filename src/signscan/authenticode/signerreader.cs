using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace signscan.Authenticode;

/// <summary>
/// 解析 PE 证书表,并对每个 PKCS#7 blob 递归读取全部签名者。
/// 既处理多个 WIN_CERTIFICATE,也处理 /as 生成的嵌套签名
/// (unsigned attribute OID 1.3.6.1.4.1.311.2.4.1)。
/// </summary>
internal sealed partial class AuthenticodeSignerReader : ISignerReader
{
    private const uint EncodingType = 0x00010001; // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
    private const uint CmsgSignerCountParam = 5;
    private const uint CmsgSignerInfoParam = 6;
    private const string NestedSignatureOid = "1.3.6.1.4.1.311.2.4.1";
    private const int MaxNestedDepth = 8;

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
            ReadMessage(blob, result, seen, depth: 0);
        }

        return result;
    }

    private static void ReadMessage(
        byte[] blob,
        List<SignerCertificate> result,
        HashSet<string> seen,
        int depth)
    {
        if (depth > MaxNestedDepth || blob.Length == 0)
        {
            return;
        }

        var msg = CryptMsgOpenToDecode(EncodingType, 0, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (msg == IntPtr.Zero)
        {
            return;
        }

        try
        {
            if (!UpdateMessage(msg, blob))
            {
                return;
            }

            var store = CertOpenStore(new IntPtr(1), EncodingType, IntPtr.Zero, 0, msg);
            if (store == IntPtr.Zero)
            {
                return;
            }

            try
            {
                CollectSigners(msg, store, result, seen, depth);
            }
            finally
            {
                CertCloseStore(store, 0);
            }
        }
        finally
        {
            CryptMsgClose(msg);
        }
    }

    private static bool UpdateMessage(IntPtr msg, byte[] blob)
    {
        var handle = GCHandle.Alloc(blob, GCHandleType.Pinned);
        try
        {
            return CryptMsgUpdate(msg, handle.AddrOfPinnedObject(), (uint)blob.Length, fFinal: true);
        }
        finally
        {
            handle.Free();
        }
    }

    private static void CollectSigners(
        IntPtr msg,
        IntPtr store,
        List<SignerCertificate> result,
        HashSet<string> seen,
        int depth)
    {
        var count = ReadSignerCount(msg);
        for (uint index = 0; index < count; index++)
        {
            var signer = ReadSignerInfo(msg, index, out var buffer);
            try
            {
                var issuer = CopyBlob(signer.Issuer);
                var serialNumber = CopyBlob(signer.SerialNumber);

                foreach (var cert in FindMatchingCertificates(store, issuer, serialNumber))
                {
                    if (seen.Add(cert.Sha256))
                    {
                        result.Add(cert);
                    }
                }

                foreach (var nested in FindNestedSignatureBlobs(signer.UnauthAttrs))
                {
                    ReadMessage(nested, result, seen, depth + 1);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static List<byte[]> FindNestedSignatureBlobs(CryptAttributes attributes)
    {
        var blobs = new List<byte[]>();
        if (attributes.cAttr == 0 || attributes.rgAttr == IntPtr.Zero)
        {
            return blobs;
        }

        var attributeSize = Marshal.SizeOf<CryptAttribute>();
        var valueSize = Marshal.SizeOf<CryptAttributeBlob>();

        for (uint i = 0; i < attributes.cAttr; i++)
        {
            var attribute = Marshal.PtrToStructure<CryptAttribute>(
                IntPtr.Add(attributes.rgAttr, (int)(i * (uint)attributeSize)));

            var oid = attribute.pszObjId == IntPtr.Zero
                ? null
                : Marshal.PtrToStringAnsi(attribute.pszObjId);

            if (!string.Equals(oid, NestedSignatureOid, StringComparison.Ordinal)
                || attribute.cValue == 0
                || attribute.rgValue == IntPtr.Zero)
            {
                continue;
            }

            for (uint j = 0; j < attribute.cValue; j++)
            {
                var value = Marshal.PtrToStructure<CryptAttributeBlob>(
                    IntPtr.Add(attribute.rgValue, (int)(j * (uint)valueSize)));

                if (value.cbData == 0 || value.pbData == IntPtr.Zero || value.cbData > int.MaxValue)
                {
                    continue;
                }

                var bytes = new byte[(int)value.cbData];
                Marshal.Copy(value.pbData, bytes, 0, bytes.Length);
                blobs.Add(bytes);
            }
        }

        return blobs;
    }

    private static uint ReadSignerCount(IntPtr msg)
    {
        var size = (uint)sizeof(uint);
        var buffer = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            if (!CryptMsgGetParam(msg, CmsgSignerCountParam, 0, buffer, ref size))
            {
                throw new InvalidOperationException(
                    $"读取签名数量失败(CryptMsgGetParam):Win32 {Marshal.GetLastWin32Error()}");
            }

            return (uint)Marshal.ReadInt32(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static CmsgSignerInfo ReadSignerInfo(IntPtr msg, uint index, out IntPtr buffer)
    {
        var size = 0u;
        if (!CryptMsgGetParam(msg, CmsgSignerInfoParam, index, IntPtr.Zero, ref size) || size == 0)
        {
            throw new InvalidOperationException(
                $"读取签名信息大小失败(CryptMsgGetParam):Win32 {Marshal.GetLastWin32Error()}");
        }

        buffer = Marshal.AllocHGlobal((int)size);
        if (!CryptMsgGetParam(msg, CmsgSignerInfoParam, index, buffer, ref size))
        {
            Marshal.FreeHGlobal(buffer);
            throw new InvalidOperationException(
                $"读取签名信息失败(CryptMsgGetParam):Win32 {Marshal.GetLastWin32Error()}");
        }

        return Marshal.PtrToStructure<CmsgSignerInfo>(buffer);
    }

    private static IEnumerable<SignerCertificate> FindMatchingCertificates(
        IntPtr store,
        byte[] issuer,
        byte[] serialNumber)
    {
        var context = IntPtr.Zero;
        while ((context = CertEnumCertificatesInStore(store, context)) != IntPtr.Zero)
        {
            var certContext = Marshal.PtrToStructure<CertContext>(context);
            var certInfo = Marshal.PtrToStructure<CertInfoHeader>(certContext.pCertInfo);

            if (!BlobEquals(certInfo.Issuer, issuer) || !BlobEquals(certInfo.SerialNumber, serialNumber))
            {
                continue;
            }

            var raw = new byte[(int)certContext.cbCertEncoded];
            Marshal.Copy(certContext.pbCertEncoded, raw, 0, raw.Length);

            using var cert = X509CertificateLoader.LoadCertificate(raw);
            yield return new SignerCertificate(
                cert.RawData,
                cert.NotBefore.ToUniversalTime(),
                cert.NotAfter.ToUniversalTime(),
                cert.Subject);
        }
    }

    private static byte[] CopyBlob(CryptDataBlob blob)
    {
        if (blob.cbData == 0 || blob.cbData > int.MaxValue)
        {
            return Array.Empty<byte>();
        }

        var bytes = new byte[(int)blob.cbData];
        Marshal.Copy(blob.pbData, bytes, 0, bytes.Length);
        return bytes;
    }

    private static bool BlobEquals(CryptDataBlob blob, byte[] value)
    {
        if (blob.cbData != (uint)value.Length)
        {
            return false;
        }

        if (blob.cbData == 0)
        {
            return true;
        }

        var bytes = new byte[(int)blob.cbData];
        Marshal.Copy(blob.pbData, bytes, 0, bytes.Length);
        return bytes.AsSpan().SequenceEqual(value);
    }

    [LibraryImport("crypt32.dll", EntryPoint = "CryptMsgOpenToDecode", SetLastError = true)]
    private static partial IntPtr CryptMsgOpenToDecode(
        uint dwMsgEncodingType,
        uint dwFlags,
        uint dwMsgType,
        IntPtr hCryptProv,
        IntPtr pRecipientInfo,
        IntPtr pStreamInfo);

    [LibraryImport("crypt32.dll", EntryPoint = "CryptMsgUpdate", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptMsgUpdate(
        IntPtr hCryptMsg,
        IntPtr pbData,
        uint cbData,
        [MarshalAs(UnmanagedType.Bool)] bool fFinal);

    [LibraryImport("crypt32.dll", EntryPoint = "CryptMsgGetParam", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptMsgGetParam(
        IntPtr hCryptMsg,
        uint dwParamType,
        uint dwIndex,
        IntPtr pvData,
        ref uint pcbData);

    [LibraryImport("crypt32.dll", EntryPoint = "CertOpenStore", SetLastError = true)]
    private static partial IntPtr CertOpenStore(
        IntPtr lpszStoreProvider,
        uint dwEncodingType,
        IntPtr hCryptProv,
        uint dwFlags,
        IntPtr pvPara);

    [LibraryImport("crypt32.dll", EntryPoint = "CertEnumCertificatesInStore", SetLastError = true)]
    private static partial IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

    [LibraryImport("crypt32.dll", EntryPoint = "CertCloseStore", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

    [LibraryImport("crypt32.dll", EntryPoint = "CryptMsgClose", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptMsgClose(IntPtr hCryptMsg);

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptDataBlob
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptAlgorithmIdentifier
    {
        public IntPtr pszObjId;
        public CryptDataBlob Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptAttributes
    {
        public uint cAttr;
        public IntPtr rgAttr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptAttribute
    {
        public IntPtr pszObjId;
        public uint cValue;
        public IntPtr rgValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptAttributeBlob
    {
        public uint cbData;
        public IntPtr pbData;
    }

    /// <summary>CERT_INFO 的前三个字段足够定位签名者。</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct CertInfoHeader
    {
        public uint dwVersion;
        public CryptDataBlob SerialNumber;
        public CryptAlgorithmIdentifier SignatureAlgorithm;
        public CryptDataBlob Issuer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertContext
    {
        public uint dwCertEncodingType;
        public IntPtr pbCertEncoded;
        public uint cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CmsgSignerInfo
    {
        public uint dwVersion;
        public CryptDataBlob Issuer;
        public CryptDataBlob SerialNumber;
        public CryptAlgorithmIdentifier HashAlgorithm;
        public CryptAlgorithmIdentifier HashEncryptionAlgorithm;
        public CryptDataBlob EncryptedHash;
        public CryptAttributes AuthAttrs;
        public CryptAttributes UnauthAttrs;
    }
}
