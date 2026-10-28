namespace signscan.tests.Support;

internal sealed class FakeSignerReader : ISignerReader
{
    internal Dictionary<string, IReadOnlyList<SignerCertificate>> Map { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    internal int Calls { get; private set; }

    public IReadOnlyList<SignerCertificate> ReadSigners(string filePath)
    {
        Calls++;
        return Map.TryGetValue(filePath, out var certs) ? certs : Array.Empty<SignerCertificate>();
    }
}
