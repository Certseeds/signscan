using System.Reflection.PortableExecutable;

namespace signscan.Authenticode;

/// <summary>用 PEReader 读取 PE 的 IMAGE_DIRECTORY_ENTRY_SECURITY 证书表,返回每个 PKCS#7 blob。</summary>
internal static class PeCertificateTable
{
    private const int MaxHeaderSize = 64 * 1024;
    private const ushort WinCertTypePkcsSignedData = 2;

    internal static IReadOnlyList<byte[]> ReadBlobs(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return ReadBlobs(stream);
    }

    /// <summary>
    /// PEReader 只接受剩余长度不超过 int.MaxValue 的流,因此只把头部前缀交给它;
    /// 证书表按文件偏移直接从原流读取,超过 2 GB 的 exe 也能扫描。
    /// </summary>
    internal static IReadOnlyList<byte[]> ReadBlobs(Stream stream)
    {
        var blobs = new List<byte[]>();

        try
        {
            var headerSize = (int)Math.Min(stream.Length - stream.Position, MaxHeaderSize);
            if (headerSize < 64)
            {
                return blobs;
            }

            var header = new byte[headerSize];
            stream.ReadExactly(header);

            using var peReader = new PEReader(new MemoryStream(header, writable: false));
            var peHeader = peReader.PEHeaders.PEHeader;
            if (peHeader is null)
            {
                return blobs;
            }

            // 证书表的 VirtualAddress 在 PE 规范里是文件偏移,PEReader 原样暴露。
            var fileOffset = peHeader.CertificateTableDirectory.RelativeVirtualAddress;
            var size = peHeader.CertificateTableDirectory.Size;
            if (fileOffset <= 0 || size <= 0 || (long)fileOffset + size > stream.Length)
            {
                return blobs;
            }

            stream.Position = fileOffset;
            var table = new byte[size];
            stream.ReadExactly(table);

            var offset = 0;
            while (offset + 8 <= table.Length)
            {
                var length = BitConverter.ToUInt32(table, offset);
                var type = BitConverter.ToUInt16(table, offset + 6);

                if (length < 8 || (long)offset + length > table.Length)
                {
                    break;
                }

                if (type == WinCertTypePkcsSignedData)
                {
                    var blob = new byte[length - 8];
                    Array.Copy(table, offset + 8, blob, 0, blob.Length);
                    blobs.Add(blob);
                }

                var aligned = ((long)length + 7) & ~7L;
                if (aligned > int.MaxValue)
                {
                    break;
                }

                offset += (int)aligned;
            }
        }
        catch (BadImageFormatException)
        {
            return blobs;
        }

        return blobs;
    }
}
