namespace signscan;

internal interface ISignerReader
{
    IReadOnlyList<SignerCertificate> ReadSigners(string filePath);
}
