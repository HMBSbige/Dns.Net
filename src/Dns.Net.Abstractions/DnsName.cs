using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents an absolute domain name, held in uncompressed wire format (RFC 1035, Sec. 3.1).
/// </summary>
/// <remarks>
/// <para>
/// A label may hold any byte: host name rules (RFC 1123) are not applied. The default value is the root.
/// Equality ignores the case of ASCII letters (RFC 4343, Sec. 3); a name keeps the case that it was created with.
/// </para>
/// <para>
/// The presentation format is that of master files (RFC 1035, Sec. 5.1), where the trailing dot is optional when parsing.
/// Characters must be printable ASCII: convert an internationalized name with <see cref="IdnMapping.GetAscii(string)" /> first.
/// </para>
/// </remarks>
public readonly struct DnsName : IEquatable<DnsName>, ISpanParsable<DnsName>, ISpanFormattable
{
	/// <summary>
	/// The maximum length of a name in wire format, in bytes, the root label included (RFC 1035, Sec. 2.3.4).
	/// </summary>
	public const int MaxEncodedLength = 255;

	/// <summary>
	/// The maximum length of a label, in bytes, its length byte excluded (RFC 1035, Sec. 2.3.4).
	/// </summary>
	public const int MaxLabelLength = 63;

	private const string EmptyName = "The name is empty.";

	private const string EmptyLabel = "The name has an empty label.";

	private const string InvalidEscape = "The name has a backslash that is followed neither by three decimal digits of value at most 255 nor by another ASCII character.";

	private const string InvalidCharacter = "The name has a character that is not printable ASCII; escape it, or convert an internationalized name with IdnMapping.GetAscii first.";

	private const string LabelTooLong = "The name has a label longer than 63 bytes.";

	private const string NameTooLong = "The name is longer than 255 bytes in wire format.";

	// Never changed; null for the root, so that the default value is the root.
	private readonly byte[]? _encoded;

	// Takes ownership of encoded, the valid wire format of a name other than the root.
	internal DnsName(byte[] encoded)
	{
		Debug.Assert(encoded.Length is > 1 and <= MaxEncodedLength && encoded[^1] is 0);
		_encoded = encoded;
	}

	/// <summary>
	/// Gets the root name.
	/// </summary>
	public static DnsName Root => default;

	/// <summary>
	/// Gets a value that indicates whether the name is the root.
	/// </summary>
	public bool IsRoot => _encoded is null;

	/// <summary>
	/// Gets the number of labels, the root label excluded; 0 for the root.
	/// </summary>
	public int LabelCount
	{
		get
		{
			ReadOnlySpan<byte> encoded = Encoded;
			int count = 0;

			for (int i = 0; encoded[i] is not 0; i += encoded[i] + 1)
			{
				++count;
			}

			return count;
		}
	}

	/// <summary>
	/// Gets the length of the name in uncompressed wire format, in bytes.
	/// </summary>
	public int EncodedLength => _encoded?.Length ?? 1;

	// The uncompressed wire format.
	internal ReadOnlySpan<byte> Encoded => _encoded is null ? [0] : _encoded;

	/// <summary>
	/// Parses a name in presentation format.
	/// </summary>
	/// <param name="s">The name in presentation format.</param>
	/// <returns>The name, with the case of its letters kept.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="s" /> is <see langword="null" />.</exception>
	/// <exception cref="FormatException"><paramref name="s" /> is not a valid name.</exception>
	public static DnsName Parse(string s)
	{
		ArgumentNullException.ThrowIfNull(s);

		return Parse(s.AsSpan());
	}

	/// <summary>
	/// Parses a name in presentation format.
	/// </summary>
	/// <param name="s">The name in presentation format.</param>
	/// <returns>The name, with the case of its letters kept.</returns>
	/// <exception cref="FormatException"><paramref name="s" /> is not a valid name.</exception>
	public static DnsName Parse(ReadOnlySpan<char> s)
	{
		string? error = TryParseCore(s, out DnsName result);

		return error is null ? result : ThrowHelper.ThrowFormat<DnsName>(error);
	}

	/// <summary>
	/// Tries to parse a name in presentation format.
	/// </summary>
	/// <param name="s">The name in presentation format.</param>
	/// <param name="result">The name on success; otherwise, the root.</param>
	/// <returns><see langword="true" /> if <paramref name="s" /> is a valid name; otherwise, <see langword="false" />.</returns>
	public static bool TryParse([NotNullWhen(true)] string? s, out DnsName result)
	{
		if (s is null)
		{
			result = default;
			return false;
		}

		return TryParse(s.AsSpan(), out result);
	}

	/// <summary>
	/// Tries to parse a name in presentation format.
	/// </summary>
	/// <param name="s">The name in presentation format.</param>
	/// <param name="result">The name on success; otherwise, the root.</param>
	/// <returns><see langword="true" /> if <paramref name="s" /> is a valid name; otherwise, <see langword="false" />.</returns>
	public static bool TryParse(ReadOnlySpan<char> s, out DnsName result)
	{
		return TryParseCore(s, out result) is null;
	}

	static DnsName IParsable<DnsName>.Parse(string s, IFormatProvider? provider)
	{
		return Parse(s);
	}

	static bool IParsable<DnsName>.TryParse([NotNullWhen(true)] string? s, IFormatProvider? provider, out DnsName result)
	{
		return TryParse(s, out result);
	}

	static DnsName ISpanParsable<DnsName>.Parse(ReadOnlySpan<char> s, IFormatProvider? provider)
	{
		return Parse(s);
	}

	static bool ISpanParsable<DnsName>.TryParse(ReadOnlySpan<char> s, IFormatProvider? provider, out DnsName result)
	{
		return TryParse(s, out result);
	}

	/// <summary>
	/// Determines whether the name is <paramref name="other" /> or a name below it.
	/// </summary>
	/// <param name="other">The name that may be an ancestor.</param>
	/// <returns><see langword="true" /> if the name equals <paramref name="other" /> or ends with all of its labels; otherwise, <see langword="false" />.</returns>
	public bool IsSubdomainOf(DnsName other)
	{
		ReadOnlySpan<byte> name = Encoded;
		ReadOnlySpan<byte> ancestor = other.Encoded;
		int start = 0;

		// The suffix must start at a label boundary; the root label alone is never longer than the ancestor, so the loop stops on a label.
		while (name.Length - start > ancestor.Length)
		{
			start += name[start] + 1;
		}

		return EqualsIgnoreCase(name.Slice(start), ancestor);
	}

	/// <summary>
	/// Tries to read a name in uncompressed wire format from the start of <paramref name="source" />, as <see cref="TryEncode" /> writes it.
	/// </summary>
	/// <remarks>A compression pointer or an extended label type fails. Bytes may follow the name; they are not read.</remarks>
	/// <param name="source">The bytes that start with the name.</param>
	/// <param name="name">The name on success; otherwise, the root.</param>
	/// <param name="bytesConsumed">The number of bytes that the name takes, or 0 on failure.</param>
	/// <returns><see langword="true" /> if <paramref name="source" /> starts with a name; otherwise, <see langword="false" />.</returns>
	public static bool TryDecode(ReadOnlySpan<byte> source, out DnsName name, out int bytesConsumed)
	{
		// The reader rejects a pointer that does not point back, and here there is nothing before the name.
		DnsWireReader reader = new(source);

		if (reader.TryReadName(out name))
		{
			bytesConsumed = source.Length - reader.Remaining;
			return true;
		}

		bytesConsumed = 0;
		return false;
	}

	/// <summary>
	/// Tries to write the name in uncompressed wire format.
	/// </summary>
	/// <param name="destination">The buffer that receives the name.</param>
	/// <param name="bytesWritten">The number of bytes written, or 0 on failure.</param>
	/// <returns><see langword="true" /> if <paramref name="destination" /> is long enough; otherwise, <see langword="false" />, with <paramref name="destination" /> unchanged.</returns>
	public bool TryEncode(Span<byte> destination, out int bytesWritten)
	{
		ReadOnlySpan<byte> encoded = Encoded;

		if (encoded.TryCopyTo(destination))
		{
			bytesWritten = encoded.Length;
			return true;
		}

		bytesWritten = 0;
		return false;
	}

	/// <summary>
	/// Determines whether the name equals <paramref name="other" />, ignoring the case of ASCII letters (RFC 4343, Sec. 3).
	/// </summary>
	/// <param name="other">The name to compare with.</param>
	/// <returns><see langword="true" /> if the names have the same labels, apart from the case of ASCII letters; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsName other)
	{
		return ReferenceEquals(_encoded, other._encoded) || EqualsIgnoreCase(Encoded, other.Encoded);
	}

	/// <summary>
	/// Determines whether <paramref name="obj" /> is a <see cref="DnsName" /> equal to the name.
	/// </summary>
	/// <param name="obj">The object to compare with.</param>
	/// <returns><see langword="true" /> if <paramref name="obj" /> is an equal <see cref="DnsName" />; otherwise, <see langword="false" />.</returns>
	public override bool Equals([NotNullWhen(true)] object? obj)
	{
		return obj is DnsName other && Equals(other);
	}

	/// <summary>
	/// Returns a hash code that ignores the case of ASCII letters, consistent with <see cref="Equals(DnsName)" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		ReadOnlySpan<byte> encoded = Encoded;
		Span<byte> folded = stackalloc byte[MaxEncodedLength];
		folded = folded.Slice(0, encoded.Length);

		for (int i = 0; i < encoded.Length; ++i)
		{
			folded[i] = ToLowerAscii(encoded[i]);
		}

		HashCode hash = new();
		hash.AddBytes(folded);
		return hash.ToHashCode();
	}

	/// <summary>
	/// Returns the name in presentation format, without the trailing dot.
	/// </summary>
	/// <remarks>The root is <c>"."</c>. Special and non-printable bytes are escaped, so that <see cref="Parse(string)" /> returns the same bytes.</remarks>
	/// <returns>The name in presentation format.</returns>
	public override string ToString()
	{
		ReadOnlySpan<byte> encoded = Encoded;

		return string.Create(GetFormattedLength(encoded), encoded, static (destination, encoded) => Format(encoded, destination));
	}

	/// <summary>
	/// Tries to write the name in presentation format, as <see cref="ToString()" /> returns it.
	/// </summary>
	/// <param name="destination">The buffer that receives the characters.</param>
	/// <param name="charsWritten">The number of characters written, or 0 on failure.</param>
	/// <returns><see langword="true" /> if <paramref name="destination" /> is long enough; otherwise, <see langword="false" />.</returns>
	public bool TryFormat(Span<char> destination, out int charsWritten)
	{
		ReadOnlySpan<byte> encoded = Encoded;
		int length = GetFormattedLength(encoded);

		if (destination.Length < length)
		{
			charsWritten = 0;
			return false;
		}

		Format(encoded, destination);
		charsWritten = length;
		return true;
	}

	// The name has a single format, which does not depend on the culture.
	bool ISpanFormattable.TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
	{
		return TryFormat(destination, out charsWritten);
	}

	string IFormattable.ToString(string? format, IFormatProvider? formatProvider)
	{
		return ToString();
	}

	/// <summary>
	/// Determines whether two names are equal, ignoring the case of ASCII letters.
	/// </summary>
	/// <param name="left">The first name.</param>
	/// <param name="right">The second name.</param>
	/// <returns><see langword="true" /> if <paramref name="left" /> equals <paramref name="right" />; otherwise, <see langword="false" />.</returns>
	public static bool operator ==(DnsName left, DnsName right)
	{
		return left.Equals(right);
	}

	/// <summary>
	/// Determines whether two names differ, ignoring the case of ASCII letters.
	/// </summary>
	/// <param name="left">The first name.</param>
	/// <param name="right">The second name.</param>
	/// <returns><see langword="true" /> if <paramref name="left" /> does not equal <paramref name="right" />; otherwise, <see langword="false" />.</returns>
	public static bool operator !=(DnsName left, DnsName right)
	{
		return !left.Equals(right);
	}

	// Appends the name as master files write it, with the trailing dot that makes it absolute.
	internal void AppendAbsolute(StringBuilder builder)
	{
		builder.Append(CultureInfo.InvariantCulture, $"{this}");

		if (!IsRoot)
		{
			builder.Append('.');
		}
	}

	// Compares bytes, ignoring the case of ASCII letters only (RFC 4343, Sec. 3).
	internal static bool EqualsIgnoreCase(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
	{
		if (left.Length != right.Length)
		{
			return false;
		}

		for (int i = 0; i < left.Length; ++i)
		{
			if (left[i] != right[i] && ToLowerAscii(left[i]) != ToLowerAscii(right[i]))
			{
				return false;
			}
		}

		return true;
	}

	internal static byte ToLowerAscii(byte value)
	{
		return (uint)(value - 'A') <= 'Z' - 'A' ? (byte)(value | 0x20) : value;
	}

	// Parses s in a single pass, so that a backslash escapes exactly the one character after it, a dot or a backslash included.
	// Returns null on success, otherwise the reason for failure.
	private static string? TryParseCore(ReadOnlySpan<char> s, out DnsName result)
	{
		result = default;

		if (s.IsEmpty)
		{
			return EmptyName;
		}

		if (s is ".")
		{
			return null;
		}

		Span<byte> buffer = stackalloc byte[MaxEncodedLength];
		int labelStart = 0;
		int length = 1;
		bool labelOpen = true;
		int i = 0;

		while (i < s.Length)
		{
			char c = s[i++];
			byte value;

			if (c is '.')
			{
				int labelLength = length - labelStart - 1;

				if (labelLength is 0)
				{
					return EmptyLabel;
				}

				buffer[labelStart] = (byte)labelLength;
				labelOpen = i < s.Length;

				if (labelOpen)
				{
					labelStart = length++;
				}

				continue;
			}

			if (c is '\\')
			{
				if (i == s.Length)
				{
					return InvalidEscape;
				}

				char escaped = s[i++];

				if (char.IsAsciiDigit(escaped))
				{
					if (s.Length - i < 2 || !char.IsAsciiDigit(s[i]) || !char.IsAsciiDigit(s[i + 1]))
					{
						return InvalidEscape;
					}

					int number = (escaped - '0') * 100 + (s[i] - '0') * 10 + (s[i + 1] - '0');
					i += 2;

					if (number > byte.MaxValue)
					{
						return InvalidEscape;
					}

					value = (byte)number;
				}
				else if (char.IsAscii(escaped))
				{
					value = (byte)escaped;
				}
				else
				{
					return InvalidEscape;
				}
			}
			else if (c is >= '!' and <= '~')
			{
				value = (byte)c;
			}
			else
			{
				return InvalidCharacter;
			}

			if (length - labelStart > MaxLabelLength)
			{
				return LabelTooLong;
			}

			// The byte and the root label that ends the name must both fit.
			if (length >= MaxEncodedLength - 1)
			{
				return NameTooLong;
			}

			buffer[length++] = value;
		}

		// A label that no dot ended is not empty: a dot opens a label only when more characters follow, and each of them adds a byte or fails.
		if (labelOpen)
		{
			buffer[labelStart] = (byte)(length - labelStart - 1);
		}

		buffer[length++] = 0;
		result = new DnsName(buffer.Slice(0, length).ToArray());
		return null;
	}

	// The characters that a label escapes with a backslash: the dot, the backslash, and those that master files give a meaning (RFC 1035, Sec. 5.1).
	private static bool IsSpecial(byte value)
	{
		return value is (byte)'.' or (byte)'\\' or (byte)'"' or (byte)'(' or (byte)')' or (byte)';' or (byte)'@' or (byte)'$';
	}

	private static int GetFormattedLength(ReadOnlySpan<byte> encoded)
	{
		if (encoded.Length is 1)
		{
			return 1;
		}

		// A dot separates each label from the next.
		int length = -1;

		for (int i = 0; encoded[i] is not 0; i += encoded[i] + 1)
		{
			++length;

			foreach (byte value in encoded.Slice(i + 1, encoded[i]))
			{
				length += value switch
				{
					_ when IsSpecial(value) => 2,
					>= 0x21 and <= 0x7E => 1,
					_ => 4
				};
			}
		}

		return length;
	}

	private static void Format(ReadOnlySpan<byte> encoded, Span<char> destination)
	{
		if (encoded.Length is 1)
		{
			destination[0] = '.';
			return;
		}

		int j = 0;

		for (int i = 0; encoded[i] is not 0; i += encoded[i] + 1)
		{
			if (i > 0)
			{
				destination[j++] = '.';
			}

			foreach (byte value in encoded.Slice(i + 1, encoded[i]))
			{
				if (IsSpecial(value))
				{
					destination[j++] = '\\';
					destination[j++] = (char)value;
				}
				else if (value is >= 0x21 and <= 0x7E)
				{
					destination[j++] = (char)value;
				}
				else
				{
					destination[j++] = '\\';
					destination[j++] = (char)('0' + value / 100);
					destination[j++] = (char)('0' + value / 10 % 10);
					destination[j++] = (char)('0' + value % 10);
				}
			}
		}
	}
}
