using System.Buffers;
using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of a record whose type has no class of its own, or that the class of its type cannot hold, kept in wire format (RFC 3597).
/// </summary>
/// <remarks>
/// <para>
/// Decoding expands the names in the data of the older types whose names may be compressed (RFC 3597, Sec. 4), such as MINFO and NAPTR, so the data holds no compression pointers.
/// The data of other types is kept unchecked.
/// </para>
/// <para>
/// Data that the class of its type can hold, such as that of an A record of class IN, must use that class:
/// decoding never gives it this class, so a message that holds it does not equal the message that it decodes to.
/// </para>
/// </remarks>
/// <param name="Type">The record type, other than <see cref="DnsRecordType.Opt" />.</param>
/// <param name="RawData">The RDATA in wire format, without compression pointers; the record shares the bytes, which must not be changed afterwards.</param>
/// <exception cref="ArgumentException"><paramref name="Type" /> is <see cref="DnsRecordType.Opt" />.</exception>
public sealed record DnsUnknownData(DnsRecordType Type, ReadOnlyMemory<byte> RawData) : DnsRecordData
{
	private const DnsRecordType Md = (DnsRecordType)3;

	private const DnsRecordType Mf = (DnsRecordType)4;

	private const DnsRecordType Mb = (DnsRecordType)7;

	private const DnsRecordType Mg = (DnsRecordType)8;

	private const DnsRecordType Mr = (DnsRecordType)9;

	private const DnsRecordType MInfo = (DnsRecordType)14;

	private const DnsRecordType Rp = (DnsRecordType)17;

	private const DnsRecordType Afsdb = (DnsRecordType)18;

	private const DnsRecordType Rt = (DnsRecordType)21;

	private const DnsRecordType Px = (DnsRecordType)26;

	private const DnsRecordType Nxt = (DnsRecordType)30;

	/// <summary>
	/// Gets the record type, which is never <see cref="DnsRecordType.Opt" />.
	/// </summary>
	public override DnsRecordType Type { get; } = CheckType(Type);

	/// <summary>
	/// Determines whether <paramref name="other" /> has the same type and the same bytes.
	/// </summary>
	/// <param name="other">The data to compare with.</param>
	/// <returns><see langword="true" /> if the data are equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsUnknownData? other)
	{
		return ReferenceEquals(this, other) || other is not null && Type == other.Type && RawData.Span.SequenceEqual(other.RawData.Span);
	}

	/// <summary>
	/// Returns a hash code consistent with <see cref="Equals(DnsUnknownData)" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(Type);
		hash.AddBytes(RawData.Span);
		return hash.ToHashCode();
	}

	// The generic format of RFC 3597, Sec. 5: \#, the length, and the bytes in hexadecimal.
	internal override void AppendPresentation(StringBuilder builder)
	{
		builder.Append($@"\# {RawData.Length}");

		if (!RawData.IsEmpty)
		{
			builder.Append(' ').Append(Convert.ToHexString(RawData.Span));
		}
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		writer.WriteBytes(RawData.Span);
	}

	// Reads the RDATA up to the limit, expanding the names of the older types; isInternet tells whether the data is in class IN.
	internal static DnsUnknownData? Read(ref DnsWireReader reader, DnsRecordType type, bool isInternet)
	{
		ExpandedData data = new(reader.Remaining);

		try
		{
			bool? read = type switch
			{
				// A name (RFC 1035, Sec. 3.3).
				Md or Mf or Mb or Mg or Mr => data.Name(ref reader),
				// Two names (RFC 1035, Sec. 3.3.7; RFC 1183, Sec. 2.2).
				MInfo or Rp => data.Name(ref reader) && data.Name(ref reader),
				// A 16-bit subtype or preference, then a name (RFC 1183, Sec. 1 and 3.3).
				Afsdb or Rt => data.Bytes(ref reader, sizeof(ushort)) && data.Name(ref reader),
				// 18 bytes of fixed fields, the name of the signer, then the signature (RFC 2535, Sec. 4.1).
				DnsRecordType.Sig => data.Bytes(ref reader, 18) && data.Name(ref reader) && data.Rest(ref reader),
				// A 16-bit preference, then two names (RFC 2163); the type belongs to class IN.
				Px when isInternet => data.Bytes(ref reader, sizeof(ushort)) && data.Name(ref reader) && data.Name(ref reader),
				// The next name, then the type bitmap (RFC 2535, Sec. 5.2).
				Nxt => data.Name(ref reader) && data.Rest(ref reader),
				// Order and preference, the strings flags, services and regexp, then the replacement (RFC 3403, Sec. 4.1).
				DnsRecordType.Naptr => data.Bytes(ref reader, 2 * sizeof(ushort)) && data.CharacterString(ref reader) && data.CharacterString(ref reader) && data.CharacterString(ref reader) && data.Name(ref reader),
				_ => null
			};

			if (read is null)
			{
				return new DnsUnknownData(type, reader.ReadToLimit().ToArray());
			}

			if (read is false)
			{
				return null;
			}

			if (data.Length > ushort.MaxValue)
			{
				reader.Fail("The RDATA is longer than 65535 bytes with its names expanded.");
				return null;
			}

			return new DnsUnknownData(type, data.Data.ToArray());
		}
		finally
		{
			data.Dispose();
		}
	}

	private static DnsRecordType CheckType(DnsRecordType type)
	{
		if (type is DnsRecordType.Opt)
		{
			throw new ArgumentException("The OPT pseudo-record is not a record; DnsMessage.Edns represents it.", nameof(Type));
		}

		return type;
	}

	// Copies RDATA field by field, with every name expanded, into a pooled buffer; the record keeps an exact-length copy.
	private ref struct ExpandedData(int remaining)
	{
		// At most two names, each growing by at most 253 bytes, when a 2-byte pointer stands for a 255-byte name.
		private const int MaxGrowth = 2 * (DnsName.MaxEncodedLength - 2);

		private byte[]? _buffer;

		public int Length { readonly get; private set; }

		public readonly ReadOnlySpan<byte> Data => _buffer.AsSpan(0, Length);

		public void Dispose()
		{
			if (_buffer is not null)
			{
				ArrayPool<byte>.Shared.Return(_buffer);
				_buffer = null;
			}
		}

		public bool Name(ref DnsWireReader reader)
		{
			if (!reader.TryReadName(out DnsName name))
			{
				return false;
			}

			name.Encoded.CopyTo(Allocate(name.EncodedLength));
			return true;
		}

		public bool Bytes(ref DnsWireReader reader, int count)
		{
			if (!reader.TryReadBytes(count, out ReadOnlySpan<byte> value))
			{
				return false;
			}

			value.CopyTo(Allocate(count));
			return true;
		}

		// A length byte and that many bytes (RFC 1035, Sec. 3.3).
		public bool CharacterString(ref DnsWireReader reader)
		{
			if (!reader.TryReadBytes(1, out ReadOnlySpan<byte> length))
			{
				return false;
			}

			length.CopyTo(Allocate(1));
			return Bytes(ref reader, length[0]);
		}

		// The bytes up to the end of the RDATA, which may be none.
		public bool Rest(ref DnsWireReader reader)
		{
			ReadOnlySpan<byte> rest = reader.ReadToLimit();
			rest.CopyTo(Allocate(rest.Length));
			return true;
		}

		private Span<byte> Allocate(int length)
		{
			_buffer ??= ArrayPool<byte>.Shared.Rent(remaining + MaxGrowth);
			Span<byte> span = _buffer.AsSpan(Length, length);
			Length += length;
			return span;
		}
	}
}
