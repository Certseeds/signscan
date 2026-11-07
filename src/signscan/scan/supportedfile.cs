namespace signscan.Scan;

internal static class SupportedFile
{
    internal static bool IsSupported(string filePath)
    {
        var extension = Path.GetExtension(filePath);
        return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".msi", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".msp", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".mst", StringComparison.OrdinalIgnoreCase);
    }
}
