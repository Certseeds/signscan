namespace signscan.Scan;

internal static class SupportedFile
{
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe",
        ".dll",
        ".sys",
        ".drv",
        ".ocx",
        ".cpl",
        ".scr",
        ".msi",
        ".msp",
        ".mst",
    };

    internal static bool IsSupported(string filePath)
        => Extensions.Contains(Path.GetExtension(filePath));
}
