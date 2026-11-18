using System.Diagnostics;
using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of a TXT record, a sequence of character strings (RFC 1035, Sec. 3.3.14).
/// </summary>
/// <remarks>Decoding gives the data of a TXT record without a string as <see cref="DnsUnknownData" />.</remarks>
/// <param name="Values">The character strings, at least one, each of up to 255 bytes.</param>
/// <exception cref="ArgumentNullException"><paramref name="Values" /> is <see langword="null" />.</exception>
/// <exception cref="ArgumentException"><paramref name="Values" /> is empty or has a string longer than 255 bytes.</exception>
public sealed record DnsTxtData(IReadOnlyList<ReadOnlyMemory<byte>> Values) : DnsRecordData
{
	/// <summary>
	/// Gets the character strings, at least one, each of up to 255 bytes, in no particular encoding.
	/// </summary>
	/// <remarks>The record holds a copy of the list, but shares the bytes, which must not be changed afterwards.</remarks>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The value set is empty or has a string longer than 255 bytes.</exception>
	public IReadOnlyList<ReadOnlyMemory<byte>> Values { get; init => field = CheckValues(value); } = CheckValues(Values);

	/// <summary>
	/// Gets <see cref="DnsRecordType.Txt" />.
	/// </summary>
	public override DnsRecordType Type => DnsRecordType.Txt;

	/// <summary>
	/// Determines whether <paramref name="other" /> holds the same strings, byte for byte.
	/// </summary>
	/// <param name="other">The data to compare with.</param>
	/// <returns><see langword="true" /> if the strings are equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsTxtData? other)
	{
		if (ReferenceEquals(this, other))
		{
			return true;
		}

		if (other is null || Values.Count != other.Values.Count)
		{
			return false;
		}

		for (int i = 0; i < Values.Count; ++i)
		{
			if (!Values[i].Span.SequenceEqual(other.Values[i].Span))
			{
				return false;
			}
		}

		return true;
	}

	/// <summary>
	/// Returns a hash code consistent with <see cref="Equals(DnsTxtData)" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();

		for (int i = 0; i < Values.Count; ++i)
		{
			ReadOnlySpan<byte> value = Values[i].Span;
			hash.Add(value.Length);
			hash.AddBytes(value);
		}

		return hash.ToHashCode();
	}

	// Quoted strings, with quotes and backslashes escaped and other bytes outside printable ASCII written as \DDD.
	internal override void AppendPresentation(StringBuilder builder)
	{
		for (int i = 0; i < Values.Count; ++i)
		{
			if (i > 0)
			{
				builder.Append(' ');
			}

			builder.Append('"');

			foreach (byte value in Values[i].Span)
			{
				if (value is (byte)'"' or (byte)'\\')
				{
					builder.Append('\\').Append((char)value);
				}
				else if (value is >= 0x20 and <= 0x7E)
				{
					builder.Append((char)value);
				}
				else
				{
					builder.Append($@"\{value:D3}");
				}
			}

			builder.Append('"');
		}
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		for (int i = 0; i < Values.Count; ++i)
		{
			ReadOnlySpan<byte> value = Values[i].Span;
			Debug.Assert(value.Length <= byte.MaxValue);
			writer.WriteUInt8((byte)value.Length);
			writer.WriteBytes(value);
		}
	}

	// Reads character strings up to the end of the RDATA, which the caller has checked is not empty.
	internal static DnsTxtData? Read(ref DnsWireReader reader)
	{
		ReadOnlySpan<byte> data = reader.ReadToLimit();
		Debug.Assert(!data.IsEmpty);
		int count = 0;

		for (int i = 0; i < data.Length; i += data[i] + 1)
		{
			if (data[i] >= data.Length - i)
			{
				reader.Fail("A character string of a TXT record runs past the end of the RDATA.");
				return null;
			}

			++count;
		}

		// One copy of the RDATA holds every string.
		byte[] copy = data.ToArray();
		ReadOnlyMemory<byte>[] values = new ReadOnlyMemory<byte>[count];

		for (int i = 0, j = 0; j < values.Length; i += copy[i] + 1, ++j)
		{
			values[j] = copy.AsMemory(i + 1, copy[i]);
		}

		return new DnsTxtData(values);
	}

	private static ReadOnlyMemory<byte>[] CheckValues(IReadOnlyList<ReadOnlyMemory<byte>> values)
	{
		ArgumentNullException.ThrowIfNull(values, nameof(Values));

		if (values.Count is 0)
		{
			throw new ArgumentException("TXT data needs at least one character string, which may be empty.", nameof(Values));
		}

		ReadOnlyMemory<byte>[] copy = [.. values];

		foreach (ReadOnlyMemory<byte> value in copy)
		{
			if (value.Length > byte.MaxValue)
			{
				throw new ArgumentException("A character string is longer than 255 bytes.", nameof(Values));
			}
		}

		return copy;
	}
}
