namespace signscan;

/// <summary>
/// 在目标所在目录写临时文件再原子替换,保证目标目录里出现的 .cer 一定是完整的。
/// </summary>
internal static class AtomicFile
{
    internal static void WriteAllBytes(string path, byte[] contents)
    {
        var destination = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(destination)!;
        var tempPath = Path.Combine(directory, Path.GetRandomFileName());

        try
        {
            File.WriteAllBytes(tempPath, contents);
            File.Move(tempPath, destination, overwrite: true);
        }
        finally
        {
            try
            {
                File.Delete(tempPath);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
