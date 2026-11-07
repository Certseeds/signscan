using System.CommandLine;
using signscan.Authenticode;
using signscan.Scan;

namespace signscan;

internal static class Program
{
    internal static int Main(string[] args)
    {
        var inputOption = new Option<DirectoryInfo>("--input-dir")
        {
            Description = "要递归扫描的目录(扫描 .exe 与 .msi/.msp/.mst 安装包)。",
        };
        var allowOption = new Option<DirectoryInfo>("--allow-dir")
        {
            Description = "白名单目录;扫描其中的 exe,并从输出目录的同名分组中移除其证书。",
        };
        var outputOption = new Option<DirectoryInfo>("--output-dir")
        {
            Description = "输出根目录;证书按输入的顶层目录拓平。",
            Required = true,
        };

        var root = new RootCommand("从安装包 exe 中提取 Authenticode 签名证书。")
        {
            inputOption,
            allowOption,
            outputOption,
        };

        root.SetAction(parseResult => Run(
            parseResult.GetValue(inputOption),
            parseResult.GetValue(allowOption),
            parseResult.GetValue(outputOption)!));

        try
        {
            var parseResult = root.Parse(args);
            if (parseResult.Errors.Count > 0)
            {
                foreach (var error in parseResult.Errors)
                {
                    Console.Error.WriteLine(error.Message);
                }

                return 2;
            }

            return parseResult.Invoke();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"未处理的错误:{ex.Message}");
            return 1;
        }
    }

    internal static string? ValidateMode(DirectoryInfo? input, DirectoryInfo? allow) => (input, allow) switch
    {
        (null, null) => "必须指定 --input-dir 或 --allow-dir",
        (not null, not null) => "不能同时指定 --input-dir 和 --allow-dir",
        _ => null,
    };

    internal static int Run(DirectoryInfo? input, DirectoryInfo? allow, DirectoryInfo output)
    {
        var modeError = ValidateMode(input, allow);
        if (modeError is not null)
        {
            Console.Error.WriteLine(modeError);
            return 2;
        }

        return allow is not null
            ? RunAllow(allow, output)
            : RunScan(input!, output);
    }

    private static int RunScan(DirectoryInfo input, DirectoryInfo output)
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
                new FileSignerReader()));

            Console.WriteLine($"扫描安装包    : {result.ExeCount}");
            Console.WriteLine($"有内嵌签名    : {result.SignedCount}");
            Console.WriteLine($"提取证书      : {result.CertCount}");
            Console.WriteLine($"跳过(无签名)  : {result.SkippedCount}");
            Console.WriteLine($"错误          : {result.ErrorCount}");
            Console.WriteLine($"输出          : {output.FullName}");

            PrintWarnings(result.Warnings);

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

    private static int RunAllow(DirectoryInfo allow, DirectoryInfo output) =>
        RunAllow(allow, output, new FileSignerReader());

    internal static int RunAllow(DirectoryInfo allow, DirectoryInfo output, ISignerReader reader)
    {
        if (!allow.Exists)
        {
            Console.Error.WriteLine($"白名单目录不存在:{allow.FullName}");
            return 2;
        }

        if (!output.Exists)
        {
            Console.Error.WriteLine($"输出目录不存在:{output.FullName}");
            return 2;
        }

        try
        {
            var result = CertRemover.Remove(new RemoveOptions(
                allow.FullName,
                output.FullName,
                reader));

            Console.WriteLine($"白名单安装包  : {result.ExeCount}");
            Console.WriteLine($"有内嵌签名    : {result.SignedCount}");
            Console.WriteLine($"移除证书      : {result.RemovedCount}");
            Console.WriteLine($"未命中        : {result.MissingCount}");
            Console.WriteLine($"跳过(无签名)  : {result.SkippedCount}");
            Console.WriteLine($"错误          : {result.ErrorCount}");
            Console.WriteLine($"输出          : {output.FullName}");

            PrintWarnings(result.Warnings);
            return result.ErrorCount == 0 ? 0 : 1;
        }
        catch (DirectoryNotFoundException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine($"移除失败:{ex.Message}");
            return 1;
        }
    }

    private static void PrintWarnings(IReadOnlyList<string> warnings)
    {
        foreach (var warning in warnings.Take(20))
        {
            Console.Error.WriteLine($"警告:{warning}");
        }

        if (warnings.Count > 20)
        {
            Console.Error.WriteLine($"...还有 {warnings.Count - 20} 条警告");
        }
    }
}
