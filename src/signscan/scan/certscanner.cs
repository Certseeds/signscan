using System.Security.Cryptography;
using signscan.Naming;

namespace signscan.Scan;

internal static class CertScanner
{
    internal static ScanResult Scan(ScanOptions options)
    {
        var inputFull = Path.GetFullPath(options.InputDir);
        var outputFull = Path.GetFullPath(options.OutputDir);

        if (!Directory.Exists(inputFull))
        {
            throw new DirectoryNotFoundException($"输入目录不存在:{inputFull}");
        }

        if (string.Equals(inputFull, outputFull, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("输入目录和输出目录不能相同");
        }

        Directory.CreateDirectory(outputFull);

        var outputPrefix = outputFull.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            IgnoreInaccessible = true,
            MatchCasing = MatchCasing.CaseInsensitive,
        };

        var warnings = new List<string>();
        var exeCount = 0;
        var signedCount = 0;
        var certCount = 0;
        var skippedCount = 0;
        var errorCount = 0;

        foreach (var file in Directory.EnumerateFiles(inputFull, "*", enumeration))
        {
            if (!string.Equals(Path.GetExtension(file), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (file.StartsWith(outputPrefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            exeCount++;

            IReadOnlyList<SignerCertificate> signers;
            try
            {
                signers = options.Reader.ReadSigners(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                           or CryptographicException or InvalidOperationException)
            {
                errorCount++;
                warnings.Add($"{file}:{ex.Message}");
                continue;
            }

            if (signers.Count == 0)
            {
                skippedCount++;
                continue;
            }

            signedCount++;
            var group = TopLevelGroup.For(inputFull, file);
            var groupDir = Path.Combine(outputFull, group);
            Directory.CreateDirectory(groupDir);

            foreach (var cert in signers)
            {
                var certPath = Path.Combine(groupDir, CertFileName.From(cert));
                if (File.Exists(certPath))
                {
                    continue;
                }

                AtomicFile.WriteAllBytes(certPath, cert.RawData);
                certCount++;
            }
        }

        return new ScanResult(exeCount, signedCount, certCount, skippedCount, errorCount, warnings);
    }
}
