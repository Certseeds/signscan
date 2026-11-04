using System.Security.Cryptography;
using signscan.Naming;

namespace signscan.Scan;

internal static class CertRemover
{
    internal static RemoveResult Remove(RemoveOptions options)
    {
        var allowFull = Path.GetFullPath(options.AllowDir);
        var outputFull = Path.GetFullPath(options.OutputDir);

        if (!Directory.Exists(allowFull))
        {
            throw new DirectoryNotFoundException($"白名单目录不存在:{allowFull}");
        }

        if (!Directory.Exists(outputFull))
        {
            throw new DirectoryNotFoundException($"输出目录不存在:{outputFull}");
        }

        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            IgnoreInaccessible = true,
            MatchCasing = MatchCasing.CaseInsensitive,
        };

        var warnings = new List<string>();
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var exeCount = 0;
        var signedCount = 0;
        var skippedCount = 0;
        var errorCount = 0;

        foreach (var file in Directory.EnumerateFiles(allowFull, "*", enumeration))
        {
            if (!string.Equals(Path.GetExtension(file), ".exe", StringComparison.OrdinalIgnoreCase))
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
            var group = TopLevelGroup.For(allowFull, file);
            foreach (var cert in signers)
            {
                targets.Add(Path.Combine(outputFull, group, CertFileName.From(cert)));
            }
        }

        var removedCount = 0;
        var missingCount = 0;

        foreach (var target in targets)
        {
            if (!File.Exists(target))
            {
                missingCount++;
                warnings.Add($"未命中:{target}");
                continue;
            }

            try
            {
                File.Delete(target);
                removedCount++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errorCount++;
                warnings.Add($"{target}:{ex.Message}");
            }
        }

        return new RemoveResult(
            exeCount,
            signedCount,
            removedCount,
            missingCount,
            skippedCount,
            errorCount,
            warnings);
    }
}
