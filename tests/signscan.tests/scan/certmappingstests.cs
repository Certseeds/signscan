using System.Text.Json;
using signscan.Naming;
using signscan.Scan;

namespace signscan.tests.Scan;

public class CertMappingsTests
{
    private const string ForwardFile = "company-app-to-cert.json";
    private const string ReverseFile = "cert-to-company-app.json";

    [Fact]
    public void ForwardMappingGroupsCompanyAndCodename()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();
        var first = TempDir.Signer();
        var second = TempDir.Signer();
        var third = TempDir.Signer();
        var fourth = TempDir.Signer();

        reader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { first };
        reader.Map[TempDir.WriteFile(input, "A/A1/y.exe")] = new[] { second };
        reader.Map[TempDir.WriteFile(input, "A/A2/z.exe")] = new[] { first };
        reader.Map[TempDir.WriteFile(input, "A/company.exe")] = new[] { third };
        reader.Map[TempDir.WriteFile(input, "root.exe")] = new[] { fourth };

        CertScanner.Scan(new ScanOptions(input, output, reader));

        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile)));
        var rootElement = doc.RootElement;

        Assert.Equal(
            new[] { "A", "others" },
            rootElement.EnumerateArray().Select(e => e.GetProperty("company").GetString()!).ToArray());

        var companyA = FindCompany(rootElement, "A");
        Assert.Equal(
            new[] { "A1", "A2", "others" },
            companyA.GetProperty("codenames").EnumerateArray()
                .Select(e => e.GetProperty("codename").GetString()!).ToArray());

        Assert.Equal(
            Sorted(CertFileName.From(first), CertFileName.From(second)),
            Cerfiles(companyA, "A1"));
        Assert.Equal(new[] { CertFileName.From(first) }, Cerfiles(companyA, "A2"));
        Assert.Equal(new[] { CertFileName.From(third) }, Cerfiles(companyA, "others"));
        Assert.Equal(new[] { CertFileName.From(fourth) }, Cerfiles(FindCompany(rootElement, "others"), "others"));
    }

    [Fact]
    public void ReverseMappingMergesSharedCertificates()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);

        reader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { signer };
        reader.Map[TempDir.WriteFile(input, "A/A2/y.exe")] = new[] { signer };
        reader.Map[TempDir.WriteFile(input, "B/B1/z.exe")] = new[] { signer };

        CertScanner.Scan(new ScanOptions(input, output, reader));

        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ReverseFile)));
        Assert.Contains(name, ReverseCerlFiles(doc.RootElement));
        Assert.Equal(new[] { "A1", "A2" }, ReverseCodenames(doc.RootElement, name, "A"));
        Assert.Equal(new[] { "B1" }, ReverseCodenames(doc.RootElement, name, "B"));
    }

    [Fact]
    public void MapsEverySignatureOfAnExe()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();
        var first = TempDir.Signer();
        var second = TempDir.Signer();
        reader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { first, second };

        CertScanner.Scan(new ScanOptions(input, output, reader));

        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile)));
        Assert.Equal(
            Sorted(CertFileName.From(first), CertFileName.From(second)),
            Cerfiles(FindCompany(doc.RootElement, "A"), "A1"));
    }

    [Fact]
    public void EmptyInputWritesEmptyArrays()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        Directory.CreateDirectory(input);

        CertScanner.Scan(new ScanOptions(input, output, new FakeSignerReader()));

        Assert.Equal(0, JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile))).RootElement.GetArrayLength());
        Assert.Equal(0, JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ReverseFile))).RootElement.GetArrayLength());
    }

    [Fact]
    public void MapsCertificatesThatAlreadyExistInOutput()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var reader = new FakeSignerReader();
        var signer = TempDir.Signer();
        reader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { signer };
        TempDir.WriteFile(output, Path.Combine("A", CertFileName.From(signer)));

        var result = CertScanner.Scan(new ScanOptions(input, output, reader));

        Assert.Equal(0, result.CertCount);
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile)));
        Assert.Equal(
            new[] { CertFileName.From(signer) },
            Cerfiles(FindCompany(doc.RootElement, "A"), "A1"));
    }

    [Fact]
    public void AllowRemovesCertificateFromAllCodenamesUnderCompany()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var allow = Path.Combine(root, "allow");
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);

        var scanReader = new FakeSignerReader();
        scanReader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { signer };
        scanReader.Map[TempDir.WriteFile(input, "A/A2/y.exe")] = new[] { signer };
        CertScanner.Scan(new ScanOptions(input, output, scanReader));

        var allowReader = new FakeSignerReader();
        allowReader.Map[TempDir.WriteFile(allow, "A/A1/w.exe")] = new[] { signer };
        var result = CertRemover.Remove(new RemoveOptions(allow, output, allowReader));

        Assert.Equal(1, result.RemovedCount);
        using var forward = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile)));
        Assert.DoesNotContain("A", Companies(forward.RootElement));
        using var reverse = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ReverseFile)));
        Assert.DoesNotContain(name, ReverseCerlFiles(reverse.RootElement));
    }

    [Fact]
    public void AllowKeepsOtherCompaniesSharingCertificate()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var allow = Path.Combine(root, "allow");
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);

        var scanReader = new FakeSignerReader();
        scanReader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { signer };
        scanReader.Map[TempDir.WriteFile(input, "B/B1/y.exe")] = new[] { signer };
        CertScanner.Scan(new ScanOptions(input, output, scanReader));

        var allowReader = new FakeSignerReader();
        allowReader.Map[TempDir.WriteFile(allow, "A/A1/w.exe")] = new[] { signer };
        CertRemover.Remove(new RemoveOptions(allow, output, allowReader));

        using var forward = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile)));
        Assert.DoesNotContain("A", Companies(forward.RootElement));
        Assert.Equal(new[] { name }, Cerfiles(FindCompany(forward.RootElement, "B"), "B1"));

        using var reverse = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ReverseFile)));
        Assert.Equal(new[] { "B" }, ReverseCompanies(reverse.RootElement, name));
        Assert.Equal(new[] { "B1" }, ReverseCodenames(reverse.RootElement, name, "B"));
    }

    [Fact]
    public void AllowKeepsMappingWhenCertificateDeletionFails()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var allow = Path.Combine(root, "allow");
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);

        var scanReader = new FakeSignerReader();
        scanReader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { signer };
        CertScanner.Scan(new ScanOptions(input, output, scanReader));

        var allowReader = new FakeSignerReader();
        allowReader.Map[TempDir.WriteFile(allow, "A/A1/w.exe")] = new[] { signer };
        var target = Path.Combine(output, "A", name);

        using (File.Open(target, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var result = CertRemover.Remove(new RemoveOptions(allow, output, allowReader));
            Assert.Equal(0, result.RemovedCount);
            Assert.Equal(1, result.ErrorCount);
        }

        using var forward = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile)));
        Assert.Equal(new[] { name }, Cerfiles(FindCompany(forward.RootElement, "A"), "A1"));
        using var reverse = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ReverseFile)));
        Assert.Equal(new[] { "A" }, ReverseCompanies(reverse.RootElement, name));
    }

    [Fact]
    public void AllowCleansMappingWhenCertificateFileIsMissing()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var allow = Path.Combine(root, "allow");
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);

        var scanReader = new FakeSignerReader();
        scanReader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { signer };
        CertScanner.Scan(new ScanOptions(input, output, scanReader));
        File.Delete(Path.Combine(output, "A", name));

        var allowReader = new FakeSignerReader();
        allowReader.Map[TempDir.WriteFile(allow, "A/A1/w.exe")] = new[] { signer };
        var result = CertRemover.Remove(new RemoveOptions(allow, output, allowReader));

        Assert.Equal(1, result.MissingCount);
        using var forward = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile)));
        Assert.DoesNotContain("A", Companies(forward.RootElement));
        using var reverse = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ReverseFile)));
        Assert.DoesNotContain(name, ReverseCerlFiles(reverse.RootElement));
    }

    [Fact]
    public void AllowSucceedsWhenMappingFilesAreMissing()
    {
        var root = TempDir.Create();
        var output = Path.Combine(root, "output");
        var allow = Path.Combine(root, "allow");
        Directory.CreateDirectory(output);
        var signer = TempDir.Signer();

        var allowReader = new FakeSignerReader();
        allowReader.Map[TempDir.WriteFile(allow, "A/A1/w.exe")] = new[] { signer };
        var result = CertRemover.Remove(new RemoveOptions(allow, output, allowReader));

        Assert.Equal(1, result.MissingCount);
        Assert.False(File.Exists(Path.Combine(output, ForwardFile)));
        Assert.False(File.Exists(Path.Combine(output, ReverseFile)));
    }

    [Fact]
    public void AllowMatchesCompanyCaseInsensitively()
    {
        var root = TempDir.Create();
        var input = Path.Combine(root, "input");
        var output = Path.Combine(root, "output");
        var allow = Path.Combine(root, "allow");
        var signer = TempDir.Signer();
        var name = CertFileName.From(signer);

        var scanReader = new FakeSignerReader();
        scanReader.Map[TempDir.WriteFile(input, "A/A1/x.exe")] = new[] { signer };
        CertScanner.Scan(new ScanOptions(input, output, scanReader));

        var allowReader = new FakeSignerReader();
        allowReader.Map[TempDir.WriteFile(allow, "a/A1/w.exe")] = new[] { signer };
        var result = CertRemover.Remove(new RemoveOptions(allow, output, allowReader));

        Assert.Equal(1, result.RemovedCount);
        using var forward = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ForwardFile)));
        Assert.DoesNotContain("A", Companies(forward.RootElement));
        using var reverse = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, ReverseFile)));
        Assert.DoesNotContain(name, ReverseCerlFiles(reverse.RootElement));
    }

    private static JsonElement FindCompany(JsonElement root, string company)
        => root.EnumerateArray().Single(e => e.GetProperty("company").GetString() == company);

    private static string[] Cerfiles(JsonElement company, string codename)
        => company.GetProperty("codenames").EnumerateArray()
            .Single(e => e.GetProperty("codename").GetString() == codename)
            .GetProperty("cerfiles").EnumerateArray()
            .Select(e => e.GetString()!).ToArray();

    private static string[] Companies(JsonElement root)
        => root.EnumerateArray().Select(e => e.GetProperty("company").GetString()!).ToArray();

    private static string[] ReverseCerlFiles(JsonElement root)
        => root.EnumerateArray().Select(e => e.GetProperty("cerfile").GetString()!).ToArray();

    private static string[] ReverseCompanies(JsonElement root, string certFile)
        => root.EnumerateArray()
            .Where(e => e.GetProperty("cerfile").GetString() == certFile)
            .SelectMany(e => e.GetProperty("companies").EnumerateArray())
            .Select(e => e.GetProperty("company").GetString()!)
            .ToArray();

    private static string[] ReverseCodenames(JsonElement root, string certFile, string company)
        => root.EnumerateArray()
            .Single(e => e.GetProperty("cerfile").GetString() == certFile)
            .GetProperty("companies").EnumerateArray()
            .Single(e => e.GetProperty("company").GetString() == company)
            .GetProperty("codenames").EnumerateArray()
            .Select(e => e.GetString()!)
            .ToArray();

    private static string[] Sorted(params string[] values)
        => values.OrderBy(v => v, StringComparer.Ordinal).ToArray();
}
