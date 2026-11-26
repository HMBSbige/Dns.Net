using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Dns.Net.Abstractions;

/// <summary>
/// Provides the 2-byte length framing of DNS messages on streams, as over TCP, TLS and QUIC (RFC 1035, Sec. 4.2.2).
/// </summary>
/// <remarks>
/// <para>Each write method passes the length and the message to the stream in a single write (RFC 7766, Sec. 8).</para>
/// <para>None of the methods ends the writing side of the stream, which DNS over QUIC needs after each message (RFC 9250, Sec. 4.2).</para>
/// <para>A read or write that is canceled or fails may leave part of a frame, after which the stream cannot carry further frames.</para>
/// </remarks>
public static class DnsStreamExtensions
{
	private const int LengthPrefixLength = sizeof(ushort);

	/// <param name="stream">The stream that carries the messages.</param>
	extension(Stream stream)
	{
		/// <summary>
		/// Asynchronously writes <paramref name="message" /> in wire format, preceded by its length as a 16-bit big-endian integer.
		/// </summary>
		/// <remarks>The message is encoded before anything is written.</remarks>
		/// <param name="message">The message to write.</param>
		/// <param name="cancellationToken">The token used to cancel the write.</param>
		/// <returns>A value task that completes when the stream has accepted the bytes.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="stream" /> or <paramref name="message" /> is <see langword="null" />.</exception>
		/// <exception cref="InvalidOperationException"><paramref name="message" /> cannot be encoded, as <see cref="DnsMessage.Encode" /> describes.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask WriteDnsMessageAsync(DnsMessage message, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(stream);
			ArgumentNullException.ThrowIfNull(message);

			return WriteMessageAsync(stream, message, cancellationToken);
		}

		/// <summary>
		/// Asynchronously reads a message that is preceded by its length as a 16-bit big-endian integer.
		/// </summary>
		/// <remarks>The bytes of a frame that does not decode are lost; a server transport reads requests with <see cref="ReadDnsFrameAsync" /> instead.</remarks>
		/// <param name="cancellationToken">The token used to cancel the read.</param>
		/// <returns>A value task whose result is the message, or <see langword="null" /> if the stream ended cleanly before the length.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="stream" /> is <see langword="null" />.</exception>
		/// <exception cref="EndOfStreamException">The stream ended inside the length or the message.</exception>
		/// <exception cref="InvalidDataException">The bytes are not a well-formed message, as <see cref="DnsMessage.Decode" /> describes.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask<DnsMessage?> ReadDnsMessageAsync(CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(stream);

			return ReadMessageAsync(stream, cancellationToken);
		}

		/// <summary>
		/// Asynchronously writes the bytes of a message, preceded by their length as a 16-bit big-endian integer.
		/// </summary>
		/// <remarks>The bytes are not checked.</remarks>
		/// <param name="message">The message in wire format.</param>
		/// <param name="cancellationToken">The token used to cancel the write.</param>
		/// <returns>A value task that completes when the stream has accepted the bytes.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="stream" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentOutOfRangeException"><paramref name="message" /> is longer than 65535 bytes.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask WriteDnsFrameAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(stream);
			ArgumentOutOfRangeException.ThrowIfGreaterThan(message.Length, ushort.MaxValue, nameof(message));

			return WriteFrameAsync(stream, message, cancellationToken);
		}

		/// <summary>
		/// Asynchronously reads the bytes of a message that is preceded by their length as a 16-bit big-endian integer, without decoding them.
		/// </summary>
		/// <remarks>The method reads nothing after the frame. The bytes are those received, as <see cref="DnsMessage.CreateErrorResponse" /> and signature checks need.</remarks>
		/// <param name="cancellationToken">The token used to cancel the read.</param>
		/// <returns>A value task whose result is a new array with the bytes, or <see langword="null" /> if the stream ended cleanly before the length.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="stream" /> is <see langword="null" />.</exception>
		/// <exception cref="EndOfStreamException">The stream ended inside the length or the message.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask<byte[]?> ReadDnsFrameAsync(CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(stream);

			return ReadFrameAsync(stream, cancellationToken);
		}
	}

	private static ValueTask WriteMessageAsync(Stream stream, DnsMessage message, CancellationToken cancellationToken)
	{
		byte[] encoded = ArrayPool<byte>.Shared.Rent(DnsMessage.MaxEncodedLength);

		try
		{
			int length = DnsMessageCodec.Encode(message, encoded.AsSpan(0, DnsMessage.MaxEncodedLength));

			// WriteFrameAsync copies the bytes into a frame of their own length before its first await, so encoded goes back at once
			// and a write that waits for the peer holds no buffer for the longest message.
			return WriteFrameAsync(stream, encoded.AsMemory(0, length), cancellationToken);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(encoded);
		}
	}

	private static async ValueTask WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
	{
		byte[] frame = ArrayPool<byte>.Shared.Rent(LengthPrefixLength + message.Length);

		try
		{
			BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)message.Length);
			message.Span.CopyTo(frame.AsSpan(LengthPrefixLength));
			await stream.WriteAsync(frame.AsMemory(0, LengthPrefixLength + message.Length), cancellationToken).ConfigureAwait(false);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(frame);
		}
	}

	[AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
	private static async ValueTask<DnsMessage?> ReadMessageAsync(Stream stream, CancellationToken cancellationToken)
	{
		if (await ReadLengthAsync(stream, cancellationToken).ConfigureAwait(false) is not { } length)
		{
			return null;
		}

		byte[] buffer = ArrayPool<byte>.Shared.Rent(length);

		try
		{
			await stream.ReadExactlyAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
			return DnsMessage.Decode(buffer.AsSpan(0, length));
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	[AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
	private static async ValueTask<byte[]?> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
	{
		if (await ReadLengthAsync(stream, cancellationToken).ConfigureAwait(false) is not { } length)
		{
			return null;
		}

		byte[] frame = GC.AllocateUninitializedArray<byte>(length);
		await stream.ReadExactlyAsync(frame, cancellationToken).ConfigureAwait(false);
		return frame;
	}

	[AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
	private static async ValueTask<int?> ReadLengthAsync(Stream stream, CancellationToken cancellationToken)
	{
		// In a buffer of its own, so that a read that waits on an idle connection holds no buffer for a whole message.
		byte[] prefix = ArrayPool<byte>.Shared.Rent(LengthPrefixLength);

		try
		{
			int read = await stream.ReadAtLeastAsync(prefix.AsMemory(0, LengthPrefixLength), LengthPrefixLength, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);

			if (read is 0)
			{
				return null;
			}

			if (read < LengthPrefixLength)
			{
				throw new EndOfStreamException("The stream ended inside a message.");
			}

			return BinaryPrimitives.ReadUInt16BigEndian(prefix);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(prefix);
		}
	}
}
