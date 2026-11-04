namespace signscan.Scan;

internal readonly record struct CompanyAppPath(string Company, string Codename)
{
    internal static CompanyAppPath From(string rootFull, string file)
    {
        var relative = Path.GetRelativePath(rootFull, file);
        var parts = relative.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries);

        var codename = parts.Length > 2 ? parts[1] : TopLevelGroup.Others;
        return new CompanyAppPath(TopLevelGroup.For(rootFull, file), codename);
    }
}
