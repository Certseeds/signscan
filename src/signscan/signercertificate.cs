using System.Security.Cryptography;

namespace signscan;

internal sealed record SignerCertificate(
    byte[] RawData,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    string Subject)
{
    internal string Sha256 { get; } = Convert.ToHexString(SHA256.HashData(RawData)).ToLowerInvariant();
}
