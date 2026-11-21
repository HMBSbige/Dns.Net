using Dns.Net.Abstractions;
using System.Net;
using System.Runtime.InteropServices;
using static Dns.Net.Tests.Wire;

namespace Dns.Net.Tests;

public class DnsStreamExtensionsTest
{
	private static readonly DnsMessage Query = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("example.com"), DnsRecordType.A)) with { Id = 0x1234 };

	private static readonly DnsMessage Response = Query.CreateResponse() with
	{
		Answers = [new DnsResourceRecord(DnsName.Parse("example.com"), TimeSpan.FromMinutes(5), new DnsAddressData(IPAddress.Parse("192.0.2.1")))]
	};

	[Test]
	public async Task WritesTheLengthAndTheMessageInOneWrite(CancellationToken cancellationToken)
	{
		RecordingStream stream = new();

		await stream.WriteDnsMessageAsync(Query, cancellationToken);

		byte[] encoded = Query.Encode();
		byte[] write = await Assert.That(stream.Writes).HasSingleItem();
		await Assert.That(Convert.ToHexString(write)).IsEqualTo(Convert.ToHexString([0, (byte)encoded.Length, .. encoded]));
	}

	[Test]
	public async Task ReadsMessagesFromAStreamThatReturnsOneByteAtATime(CancellationToken cancellationToken)
	{
		byte[] query = Query.Encode();
		byte[] response = Response.Encode();
		TrickleStream stream = new([0, (byte)query.Length, .. query, (byte)(response.Length >> 8), (byte)response.Length, .. response]);

		DnsMessage? first = await stream.ReadDnsMessageAsync(cancellationToken);
		long afterFirst = stream.Position;
		DnsMessage? second = await stream.ReadDnsMessageAsync(cancellationToken);
		DnsMessage? end = await stream.ReadDnsMessageAsync(cancellationToken);

		await Assert.That(first).IsEqualTo(Query);
		await Assert.That(afterFirst).IsEqualTo(2 + query.Length);
		await Assert.That(second).IsEqualTo(Response);
		await Assert.That(end).IsNull();
	}

	[Test]
	public async Task WrittenMessagesReadBack(CancellationToken cancellationToken)
	{
		using MemoryStream stream = new();

		await stream.WriteDnsMessageAsync(Query, cancellationToken);
		await stream.WriteDnsMessageAsync(Response, cancellationToken);
		stream.Position = 0;

		await Assert.That(await stream.ReadDnsMessageAsync(cancellationToken)).IsEqualTo(Query);
		await Assert.That(await stream.ReadDnsMessageAsync(cancellationToken)).IsEqualTo(Response);
		await Assert.That(await stream.ReadDnsMessageAsync(cancellationToken)).IsNull();
	}

	[Test]
	public async Task EndOfStreamInsideAMessageThrows()
	{
		byte[] query = Query.Encode();

		// The stream ends inside the length, inside the message, and right after the length.
		foreach (byte[] data in (byte[][])[[0], [0, (byte)query.Length, .. query.AsSpan(0, 10)], [0, (byte)query.Length]])
		{
			TrickleStream stream = new(data);
			await Assert.That(async () => await stream.ReadDnsMessageAsync()).Throws<EndOfStreamException>();
		}
	}

	[Test]
	public async Task MalformedMessagesThrowInvalidData()
	{
		await Assert.That(async () => await new TrickleStream([0, 3, 1, 2, 3]).ReadDnsMessageAsync()).Throws<InvalidDataException>();
		await Assert.That(async () => await new TrickleStream([0, 0]).ReadDnsMessageAsync()).Throws<InvalidDataException>();
	}

	[Test]
	public async Task ArgumentsMustNotBeNull()
	{
		Stream? missing = null;

		// The methods check their arguments before they return a task.
		await Assert.That(() => { _ = missing!.WriteDnsMessageAsync(Query); }).Throws<ArgumentNullException>().WithParameterName("stream");
		await Assert.That(() => { _ = missing!.ReadDnsMessageAsync(); }).Throws<ArgumentNullException>().WithParameterName("stream");
		await Assert.That(() => { _ = new RecordingStream().WriteDnsMessageAsync(null!); }).Throws<ArgumentNullException>().WithParameterName("message");
	}

	[Test]
	public async Task MessagesThatCannotBeEncodedAreNotWritten()
	{
		RecordingStream stream = new();

		await Assert.That(async () => await stream.WriteDnsMessageAsync(new DnsMessage { ResponseCode = (DnsResponseCode)16 })).Throws<InvalidOperationException>();
		await Assert.That(stream.Writes).IsEmpty();
	}

	[Test]
	public async Task AReadThatWaitsForTheLengthHoldsNoBufferForAWholeMessage(CancellationToken cancellationToken)
	{
		EmptyStream stream = new();

		await Assert.That(await stream.ReadDnsMessageAsync(cancellationToken)).IsNull();

		await Assert.That(stream.ArrayLengths.Count).IsEqualTo(1);
		await Assert.That(stream.ArrayLengths[0]).IsBetween(2, 1023);
	}

	[Test]
	public async Task AWriteThatWaitsForTheStreamHoldsNoBufferForAWholeMessage()
	{
		PendingWriteStream stream = new();

		ValueTask write = stream.WriteDnsMessageAsync(Query, CancellationToken.None);

		await Assert.That(write.IsCompleted).IsFalse();
		await Assert.That(stream.ArrayLengths.Count).IsEqualTo(1);
		await Assert.That(stream.ArrayLengths[0]).IsBetween(2 + Query.Encode().Length, 1023);
	}

	[Test]
	public async Task FramesComeAsReceivedSoThatAMalformedRequestCanBeAnsweredAndTheNextOneRead(CancellationToken cancellationToken)
	{
		// Decoding rejects the 3-byte A record.
		byte[] malformed = Concat(Header(0x4242, 0x0100, 1, 0, 0, 1), Name("example", "com"), U16(1), U16(1), Record([0], 1, [192, 0, 2]));
		byte[] query = Query.Encode();
		TrickleStream stream = new([.. U16(malformed.Length), .. malformed, .. U16(query.Length), .. query]);

		byte[]? first = await stream.ReadDnsFrameAsync(cancellationToken);
		byte[]? second = await stream.ReadDnsFrameAsync(cancellationToken);
		byte[]? end = await stream.ReadDnsFrameAsync(cancellationToken);

		await Assert.That(first).IsNotNull();
		await Assert.That(Convert.ToHexString(first!)).IsEqualTo(Convert.ToHexString(malformed));
		await Assert.That(DnsMessage.TryDecode(first, out _)).IsFalse();
		await Assert.That(DnsMessage.CreateErrorResponse(first)?.Id).IsEqualTo((ushort)0x4242);
		await Assert.That(second).IsNotNull();
		await Assert.That(Convert.ToHexString(second!)).IsEqualTo(Convert.ToHexString(query));
		await Assert.That(end).IsNull();
	}

	[Test]
	public async Task AFrameKeepsTheBytesThatEncodingAgainWouldChange(CancellationToken cancellationToken)
	{
		// The encoder would compress this owner; a signature covers the bytes as sent (RFC 8945, Sec. 4.3.2).
		byte[] request = Concat(Header(0x0101, 0x0100, 1, 0, 0, 1), Name("example", "com"), U16(1), U16(1), Record(Name("example", "com"), 1, [192, 0, 2, 1]));
		using MemoryStream stream = new([.. U16(request.Length), .. request]);

		byte[]? frame = await stream.ReadDnsFrameAsync(cancellationToken);

		await Assert.That(frame).IsNotNull();
		await Assert.That(Convert.ToHexString(frame!)).IsEqualTo(Convert.ToHexString(request));
		await Assert.That(Convert.ToHexString(DnsMessage.Decode(frame).Encode())).IsNotEqualTo(Convert.ToHexString(request));
	}

	[Test]
	public async Task AFrameReadEndsWithNullAtACleanEndAndThrowsInsideAFrame(CancellationToken cancellationToken)
	{
		await Assert.That(await new TrickleStream([]).ReadDnsFrameAsync(cancellationToken)).IsNull();

		// An empty frame is a frame, not the end of the stream.
		await Assert.That(await new TrickleStream([0, 0]).ReadDnsFrameAsync(cancellationToken)).IsEquivalentTo(Array.Empty<byte>());

		// The stream ends inside the length, inside the frame, and right after the length.
		foreach (byte[] data in (byte[][])[[0], [0, 5, 1, 2, 3], [0, 5]])
		{
			TrickleStream stream = new(data);
			await Assert.That(async () => await stream.ReadDnsFrameAsync(cancellationToken)).Throws<EndOfStreamException>();
		}
	}

	[Test]
	public async Task AFrameReadThatWaitsForTheLengthHoldsNoBufferForAWholeFrame(CancellationToken cancellationToken)
	{
		EmptyStream stream = new();

		await Assert.That(await stream.ReadDnsFrameAsync(cancellationToken)).IsNull();

		await Assert.That(stream.ArrayLengths.Count).IsEqualTo(1);
		await Assert.That(stream.ArrayLengths[0]).IsBetween(2, 1023);
	}

	[Test]
	public async Task WritesTheLengthAndTheFrameInOneWrite(CancellationToken cancellationToken)
	{
		byte[] largest = new byte[ushort.MaxValue];
		Random.Shared.NextBytes(largest);
		RecordingStream stream = new();

		await stream.WriteDnsFrameAsync(new byte[] { 1, 2, 3 }, cancellationToken);
		await stream.WriteDnsFrameAsync(largest, cancellationToken);

		await Assert.That(stream.Writes.Count).IsEqualTo(2);
		await Assert.That(Convert.ToHexString(stream.Writes[0])).IsEqualTo("0003010203");
		await Assert.That(Convert.ToHexString(stream.Writes[1])).IsEqualTo(Convert.ToHexString([0xFF, 0xFF, .. largest]));
	}

	[Test]
	public async Task AFrameTooLongForItsLengthIsNotWritten()
	{
		RecordingStream stream = new();

		await Assert.That(() => { _ = stream.WriteDnsFrameAsync(new byte[ushort.MaxValue + 1]); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("message");
		await Assert.That(stream.Writes).IsEmpty();
	}

	[Test]
	public async Task FrameArgumentsMustNotBeNull()
	{
		Stream? missing = null;

		await Assert.That(() => { _ = missing!.WriteDnsFrameAsync(new byte[1]); }).Throws<ArgumentNullException>().WithParameterName("stream");
		await Assert.That(() => { _ = missing!.ReadDnsFrameAsync(); }).Throws<ArgumentNullException>().WithParameterName("stream");
	}

	[Test]
	public async Task WrittenFramesReadBack(CancellationToken cancellationToken)
	{
		using MemoryStream stream = new();
		byte[] response = Response.Encode();

		await stream.WriteDnsFrameAsync(response, cancellationToken);
		await stream.WriteDnsMessageAsync(Query, cancellationToken);
		stream.Position = 0;

		await Assert.That(await stream.ReadDnsMessageAsync(cancellationToken)).IsEqualTo(Response);
		await Assert.That(Convert.ToHexString((await stream.ReadDnsFrameAsync(cancellationToken))!)).IsEqualTo(Convert.ToHexString(Query.Encode()));
		await Assert.That(await stream.ReadDnsFrameAsync(cancellationToken)).IsNull();
	}

	[Test]
	[MatrixDataSource]
	public async Task AWriteThatWaitsForTheStreamEndsWhenItsTokenIsCanceled([Matrix] bool frame)
	{
		using CancellationTokenSource source = new();
		PendingWriteStream stream = new();

		Task write = (frame ? stream.WriteDnsFrameAsync(Query.Encode(), source.Token) : stream.WriteDnsMessageAsync(Query, source.Token)).AsTask();

		await AssertCanceledBy(write, stream.Token, source);
	}

	[Test]
	[MatrixDataSource]
	public async Task AReadThatWaitsForTheLengthEndsWhenItsTokenIsCanceled([Matrix] bool frame)
	{
		using CancellationTokenSource source = new();
		PendingReadStream stream = new([]);

		Task read = frame ? stream.ReadDnsFrameAsync(source.Token).AsTask() : stream.ReadDnsMessageAsync(source.Token).AsTask();

		await AssertCanceledBy(read, stream.Token, source);
	}

	[Test]
	[MatrixDataSource]
	public async Task AReadThatWaitsForTheMessageAfterItsLengthEndsWhenItsTokenIsCanceled([Matrix] bool frame)
	{
		using CancellationTokenSource source = new();
		PendingReadStream stream = new(U16(Query.Encode().Length));

		Task read = frame ? stream.ReadDnsFrameAsync(source.Token).AsTask() : stream.ReadDnsMessageAsync(source.Token).AsTask();

		await AssertCanceledBy(read, stream.Token, source);
	}

	// Asserts that the stream got the token of source and that canceling source cancels task.
	// The token is checked first, so that a lost token fails the test instead of hanging it.
	private static async Task AssertCanceledBy(Task task, CancellationToken streamToken, CancellationTokenSource source)
	{
		await Assert.That(task.IsCompleted).IsFalse();
		await Assert.That(streamToken).IsEqualTo(source.Token);

		await source.CancelAsync();

		OperationCanceledException? exception = await Assert.That(async () => await task).Throws<OperationCanceledException>();
		await Assert.That(exception?.CancellationToken).IsEqualTo(source.Token);
	}

	// Ends at once; records the array length behind each read buffer, or -1.
	private sealed class EmptyStream : Stream
	{
		public List<int> ArrayLengths { get; } = [];

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => false;

		public override long Length => throw new NotSupportedException();

		public override long Position
		{
			get => throw new NotSupportedException();
			set => throw new NotSupportedException();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}

		public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			ArrayLengths.Add(MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment) && segment.Array is { } array ? array.Length : -1);
			return ValueTask.FromResult(0);
		}

		public override void Flush()
		{
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}
	}

	// Completes no write until canceled; records the array length behind each write buffer, or -1, and the last token.
	private sealed class PendingWriteStream : Stream
	{
		public List<int> ArrayLengths { get; } = [];

		public CancellationToken Token { get; private set; }

		public override bool CanRead => false;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length => throw new NotSupportedException();

		public override long Position
		{
			get => throw new NotSupportedException();
			set => throw new NotSupportedException();
		}

		public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
		{
			ArrayLengths.Add(MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment) && segment.Array is { } array ? array.Length : -1);
			Token = cancellationToken;
			return new ValueTask(Task.Delay(Timeout.Infinite, cancellationToken));
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}

		public override void Flush()
		{
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}
	}

	// Returns data, then completes no read until canceled; records the last token.
	private sealed class PendingReadStream(byte[] data) : Stream
	{
		private int _position;

		public CancellationToken Token { get; private set; }

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => false;

		public override long Length => throw new NotSupportedException();

		public override long Position
		{
			get => throw new NotSupportedException();
			set => throw new NotSupportedException();
		}

		public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			Token = cancellationToken;

			if (_position == data.Length)
			{
				return new ValueTask<int>(WaitAsync(cancellationToken));
			}

			int count = Math.Min(buffer.Length, data.Length - _position);
			data.AsSpan(_position, count).CopyTo(buffer.Span);
			_position += count;
			return ValueTask.FromResult(count);

			static async Task<int> WaitAsync(CancellationToken cancellationToken)
			{
				await Task.Delay(Timeout.Infinite, cancellationToken);
				return 0;
			}
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}

		public override void Flush()
		{
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}
	}

	// Records every write as a separate array, whichever overload makes it.
	private sealed class RecordingStream : Stream
	{
		public List<byte[]> Writes { get; } = [];

		public override bool CanRead => false;

		public override bool CanSeek => false;

		public override bool CanWrite => true;

		public override long Length => throw new NotSupportedException();

		public override long Position
		{
			get => throw new NotSupportedException();
			set => throw new NotSupportedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			Writes.Add(buffer.AsSpan(offset, count).ToArray());
		}

		public override void Write(ReadOnlySpan<byte> buffer)
		{
			Writes.Add(buffer.ToArray());
		}

		public override void WriteByte(byte value)
		{
			Writes.Add([value]);
		}

		public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			Writes.Add(buffer.AsSpan(offset, count).ToArray());
			return Task.CompletedTask;
		}

		public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
		{
			Writes.Add(buffer.ToArray());
			return ValueTask.CompletedTask;
		}

		public override void Flush()
		{
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}
	}

	// Returns at most one byte from each read.
	private sealed class TrickleStream(byte[] data) : Stream
	{
		private int _position;

		public override bool CanRead => true;

		public override bool CanSeek => false;

		public override bool CanWrite => false;

		public override long Length => data.Length;

		public override long Position
		{
			get => _position;
			set => throw new NotSupportedException();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			return Read(buffer.AsSpan(offset, count));
		}

		public override int Read(Span<byte> buffer)
		{
			if (buffer.IsEmpty || _position == data.Length)
			{
				return 0;
			}

			buffer[0] = data[_position++];
			return 1;
		}

		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			return Task.FromResult(Read(buffer.AsSpan(offset, count)));
		}

		public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			return ValueTask.FromResult(Read(buffer.Span));
		}

		public override void Flush()
		{
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}
	}
}
