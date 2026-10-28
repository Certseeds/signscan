namespace signscan.Authenticode;

/// <summary>读取 PE 的 IMAGE_DIRECTORY_ENTRY_SECURITY 证书表,返回每个 PKCS#7 blob。</summary>
internal static class PeCertificateTable
{
    private const int PeSignature = 0x00004550;
    private const ushort Pe32Magic = 0x10B;
    private const ushort Pe32PlusMagic = 0x20B;
    private const int SecurityDirectoryIndex = 4;
    private const ushort WinCertTypePkcsSignedData = 2;

    internal static IReadOnlyList<byte[]> ReadBlobs(string filePath)
    {
        var blobs = new List<byte[]>();

        using var stream = File.OpenRead(filePath);
        using var reader = new BinaryReader(stream);

        if (stream.Length < 64)
        {
            return blobs;
        }

        stream.Position = 0x3C;
        var peOffset = reader.ReadInt32();
        if (peOffset <= 0 || peOffset + 24L > stream.Length)
        {
            return blobs;
        }

        stream.Position = peOffset;
        if (reader.ReadUInt32() != PeSignature)
        {
            return blobs;
        }

        var optionalHeaderOffset = peOffset + 24L;
        stream.Position = optionalHeaderOffset;
        var magic = reader.ReadUInt16();
        var dataDirectoryOffset = magic switch
        {
            Pe32Magic => optionalHeaderOffset + 96,
            Pe32PlusMagic => optionalHeaderOffset + 112,
            _ => -1L,
        };

        if (dataDirectoryOffset < 0 || dataDirectoryOffset + 8L * (SecurityDirectoryIndex + 1) > stream.Length)
        {
            return blobs;
        }

        stream.Position = dataDirectoryOffset + 8L * SecurityDirectoryIndex;
        var fileOffset = reader.ReadUInt32();
        var size = reader.ReadUInt32();

        if (fileOffset == 0 || size == 0 || size > int.MaxValue)
        {
            return blobs;
        }

        if ((long)fileOffset + size > stream.Length)
        {
            return blobs;
        }

        stream.Position = fileOffset;
        var table = reader.ReadBytes((int)size);
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

        return blobs;
    }
}
