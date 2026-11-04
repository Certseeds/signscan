namespace signscan.Scan;

internal static class TopLevelGroup
{
    internal const string Others = "others";

    internal static string For(string rootFull, string file)
    {
        var relative = Path.GetRelativePath(rootFull, file);
        var separator = relative.IndexOfAny(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar });
        return separator < 0 ? Others : relative[..separator];
    }
}
