namespace Dns.Net.Abstractions;

/// <summary>
/// Represents an EDNS option (RFC 6891, Sec. 6.1.2): a code, and data whose format the code defines.
/// </summary>
/// <remarks>Equality compares the bytes of the data, not the memory that holds them.</remarks>
/// <param name="Code">The option code.</param>
/// <param name="Data">The option data in wire format; the option shares the bytes, which must not be changed afterwards.</param>
public readonly record struct DnsEdnsOption(DnsEdnsOptionCode Code, ReadOnlyMemory<byte> Data)
{
	/// <summary>
	/// Determines whether <paramref name="other" /> has the same code and the same bytes of data.
	/// </summary>
	/// <param name="other">The option to compare with.</param>
	/// <returns><see langword="true" /> if the options are equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsEdnsOption other)
	{
		return Code == other.Code && Data.Span.SequenceEqual(other.Data.Span);
	}

	/// <summary>
	/// Returns a hash code consistent with <see cref="Equals(DnsEdnsOption)" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(Code);
		hash.AddBytes(Data.Span);
		return hash.ToHashCode();
	}

	/// <summary>
	/// Returns the option as dig shows it, without the leading semicolon, such as <c>COOKIE: 0102030405060708</c>.
	/// </summary>
	/// <returns>The option in presentation format.</returns>
	public override string ToString()
	{
		return Data.IsEmpty ? $"{Code.Mnemonic}:" : $"{Code.Mnemonic}: {Convert.ToHexString(Data.Span)}";
	}
}
