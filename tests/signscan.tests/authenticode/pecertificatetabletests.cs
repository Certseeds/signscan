using signscan.Authenticode;

namespace signscan.tests.Authenticode;

public class PeCertificateTableTests
{
    [Fact]
    public void ReadsBlobsFromSignedFile()
    {
        const string explorer = @"C:\Windows\explorer.exe";
        if (!File.Exists(explorer))
        {
            return;
        }

        var blobs = PeCertificateTable.ReadBlobs(explorer);

        Assert.NotEmpty(blobs);
        Assert.All(blobs, blob => Assert.NotEmpty(blob));
    }

    [Fact]
    public void ReturnsEmptyForInvalidPe()
    {
        var path = Path.Combine(TempDir.Create(), "invalid.exe");
        File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00, 0x01, 0x02, 0x03 });

        Assert.Empty(PeCertificateTable.ReadBlobs(path));
    }

    [Fact]
    public void ReadsBlobsWhenStreamLengthExceedsIntMax()
    {
        const string explorer = @"C:\Windows\explorer.exe";
        if (!File.Exists(explorer))
        {
            return;
        }

        using var inner = File.OpenRead(explorer);
        using var padded = new LengthPaddedStream(inner, 3_000_000_000L);

        var blobs = PeCertificateTable.ReadBlobs(padded);

        Assert.NotEmpty(blobs);
    }

    private sealed class LengthPaddedStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _length;

        internal LengthPaddedStream(Stream inner, long length)
        {
            _inner = inner;
            _length = length;
        }

        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite => false;

        public override long Length => _length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

        public override void Flush()
        {
        }

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
