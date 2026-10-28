using System.CommandLine;
using signscan.Authenticode;
using signscan.Scan;

namespace signscan;

internal static class Program
{
    private static int Main(string[] args)
    {
        var inputOption = new Option<DirectoryInfo>("--input-dir")
        {
            Description = "要递归扫描的目录(只扫描 .exe 安装包)。",
            Required = true,
        };
        var outputOption = new Option<DirectoryInfo>("--output-dir")
        {
            Description = "输出根目录;证书按输入的顶层目录拓平。",
            Required = true,
        };

        var root = new RootCommand("从安装包 exe 中提取 Authenticode 签名证书。")
        {
            inputOption,
            outputOption,
        };

        root.SetAction(parseResult => Run(
            parseResult.GetValue(inputOption)!,
            parseResult.GetValue(outputOption)!));

        try
        {
            return root.Parse(args).Invoke();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"未处理的错误:{ex.Message}");
            return 1;
        }
    }

    private static int Run(DirectoryInfo input, DirectoryInfo output)
    {
        if (!input.Exists)
        {
            Console.Error.WriteLine($"输入目录不存在:{input.FullName}");
            return 2;
        }

        try
        {
            var result = CertScanner.Scan(new ScanOptions(
                input.FullName,
                output.FullName,
                new AuthenticodeSignerReader()));

            Console.WriteLine($"扫描 exe      : {result.ExeCount}");
            Console.WriteLine($"有内嵌签名    : {result.SignedCount}");
            Console.WriteLine($"提取证书      : {result.CertCount}");
            Console.WriteLine($"跳过(无签名)  : {result.SkippedCount}");
            Console.WriteLine($"错误          : {result.ErrorCount}");
            Console.WriteLine($"输出          : {output.FullName}");

            foreach (var warning in result.Warnings.Take(20))
            {
                Console.Error.WriteLine($"警告:{warning}");
            }

            if (result.Warnings.Count > 20)
            {
                Console.Error.WriteLine($"...还有 {result.Warnings.Count - 20} 条警告");
            }

            return 0;
        }
        catch (DirectoryNotFoundException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine($"扫描失败:{ex.Message}");
            return 1;
        }
    }
}
