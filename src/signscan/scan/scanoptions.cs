namespace signscan.Scan;

internal sealed record ScanOptions(string InputDir, string OutputDir, ISignerReader Reader);

internal sealed record ScanResult(
    int ExeCount,
    int SignedCount,
    int CertCount,
    int SkippedCount,
    int ErrorCount,
    IReadOnlyList<string> Warnings);

internal sealed record RemoveOptions(string AllowDir, string OutputDir, ISignerReader Reader);

internal sealed record RemoveResult(
    int ExeCount,
    int SignedCount,
    int RemovedCount,
    int MissingCount,
    int SkippedCount,
    int ErrorCount,
    IReadOnlyList<string> Warnings);
