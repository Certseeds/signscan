using System.Buffers;
using System.Text.Json;

namespace signscan.Scan;

/// <summary>公司/应用与证书文件的双向映射,写入输出根目录的两个 JSON 文件。</summary>
internal sealed class CertMappings
{
    internal const string ForwardFileName = "company-app-to-cert.json";
    internal const string ReverseFileName = "cert-to-company-app.json";

    private readonly SortedDictionary<string, SortedDictionary<string, SortedSet<string>>> _byCompany =
        new(StringComparer.Ordinal);

    internal void Add(string company, string codename, string certFile)
    {
        if (!_byCompany.TryGetValue(company, out var codenames))
        {
            codenames = new SortedDictionary<string, SortedSet<string>>(StringComparer.Ordinal);
            _byCompany.Add(company, codenames);
        }

        if (!codenames.TryGetValue(codename, out var files))
        {
            files = new SortedSet<string>(StringComparer.Ordinal);
            codenames.Add(codename, files);
        }

        files.Add(certFile);
    }

    internal static void Remove(
        string outputDirectory,
        IReadOnlyCollection<(string Company, string CertFile)> entries)
    {
        if (entries.Count == 0)
        {
            return;
        }

        var path = Path.Combine(outputDirectory, ForwardFileName);
        if (!File.Exists(path))
        {
            return;
        }

        var mappings = new CertMappings();
        using (var document = JsonDocument.Parse(File.ReadAllBytes(path)))
        {
            foreach (var companyElement in document.RootElement.EnumerateArray())
            {
                var company = companyElement.GetProperty("company").GetString()!;
                foreach (var codenameElement in companyElement.GetProperty("codenames").EnumerateArray())
                {
                    var codename = codenameElement.GetProperty("codename").GetString()!;
                    foreach (var fileElement in codenameElement.GetProperty("cerfiles").EnumerateArray())
                    {
                        mappings.Add(company, codename, fileElement.GetString()!);
                    }
                }
            }
        }

        foreach (var (company, certFile) in entries)
        {
            mappings.RemoveFromCompany(company, certFile);
        }

        mappings.Write(outputDirectory);
    }

    private void RemoveFromCompany(string company, string certFile)
    {
        var matches = _byCompany.Keys
            .Where(key => string.Equals(key, company, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        foreach (var key in matches)
        {
            var codenames = _byCompany[key];
            foreach (var files in codenames.Values)
            {
                files.Remove(certFile);
            }

            foreach (var empty in codenames.Where(pair => pair.Value.Count == 0).Select(pair => pair.Key).ToArray())
            {
                codenames.Remove(empty);
            }

            if (codenames.Count == 0)
            {
                _byCompany.Remove(key);
            }
        }
    }

    internal void Write(string outputDirectory)
    {
        AtomicFile.WriteAllBytes(
            Path.Combine(outputDirectory, ForwardFileName),
            WriteForward());
        AtomicFile.WriteAllBytes(
            Path.Combine(outputDirectory, ReverseFileName),
            WriteReverse());
    }

    private byte[] WriteForward()
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartArray();
            foreach (var (company, codenames) in _byCompany)
            {
                writer.WriteStartObject();
                writer.WriteString("company", company);
                writer.WriteStartArray("codenames");
                foreach (var (codename, files) in codenames)
                {
                    writer.WriteStartObject();
                    writer.WriteString("codename", codename);
                    writer.WriteStartArray("cerfiles");
                    foreach (var file in files)
                    {
                        writer.WriteStringValue(file);
                    }

                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private byte[] WriteReverse()
    {
        var reverse = BuildReverse();
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartArray();
            foreach (var (certFile, companies) in reverse)
            {
                writer.WriteStartObject();
                writer.WriteString("cerfile", certFile);
                writer.WriteStartArray("companies");
                foreach (var (company, codenames) in companies)
                {
                    writer.WriteStartObject();
                    writer.WriteString("company", company);
                    writer.WriteStartArray("codenames");
                    foreach (var codename in codenames)
                    {
                        writer.WriteStringValue(codename);
                    }

                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private SortedDictionary<string, SortedDictionary<string, SortedSet<string>>> BuildReverse()
    {
        var reverse = new SortedDictionary<string, SortedDictionary<string, SortedSet<string>>>(
            StringComparer.Ordinal);

        foreach (var (company, codenames) in _byCompany)
        {
            foreach (var (codename, files) in codenames)
            {
                foreach (var file in files)
                {
                    if (!reverse.TryGetValue(file, out var companies))
                    {
                        companies = new SortedDictionary<string, SortedSet<string>>(StringComparer.Ordinal);
                        reverse.Add(file, companies);
                    }

                    if (!companies.TryGetValue(company, out var names))
                    {
                        names = new SortedSet<string>(StringComparer.Ordinal);
                        companies.Add(company, names);
                    }

                    names.Add(codename);
                }
            }
        }

        return reverse;
    }
}
