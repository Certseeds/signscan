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
        var targets = new Dictionary<string, (string Company, string CertFile)>(
            StringComparer.OrdinalIgnoreCase);
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
                var certFile = CertFileName.From(cert);
                targets[Path.Combine(outputFull, group, certFile)] = (group, certFile);
            }
        }

        var removedCount = 0;
        var missingCount = 0;
        var mappingUpdates = new List<(string Company, string CertFile)>();

        foreach (var (target, info) in targets)
        {
            if (!File.Exists(target))
            {
                missingCount++;
                warnings.Add($"未命中:{target}");
                mappingUpdates.Add(info);
                continue;
            }

            try
            {
                File.Delete(target);
                removedCount++;
                mappingUpdates.Add(info);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errorCount++;
                warnings.Add($"{target}:{ex.Message}");
            }
        }

        CertMappings.Remove(outputFull, mappingUpdates);

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
