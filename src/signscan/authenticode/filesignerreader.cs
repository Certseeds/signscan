namespace signscan.Authenticode;

/// <summary>按文件头选择 PE 或 Windows Installer(MSI/MSP/MST) 签名读取器;改名的文件也能正确处理。</summary>
internal sealed class FileSignerReader : ISignerReader
{
    private static readonly byte[] CfbMagic = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private readonly AuthenticodeSignerReader _exe = new();
    private readonly MsiSignerReader _msi = new();

    public IReadOnlyList<SignerCertificate> ReadSigners(string filePath)
    {
        var path = Path.GetFullPath(filePath);
        if (!File.Exists(path))
        {
            return Array.Empty<SignerCertificate>();
        }

        Span<byte> header = stackalloc byte[8];
        using (var stream = File.OpenRead(path))
        {
            var read = stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
            if (read == header.Length && header.SequenceEqual(CfbMagic))
            {
                return _msi.ReadSigners(path);
            }
        }

        return _exe.ReadSigners(path);
    }
}
