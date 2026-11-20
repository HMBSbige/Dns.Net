using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the result of a query that an <see cref="IDnsClient" /> makes.
/// </summary>
/// <remarks>
/// The type mirrors <see cref="System.Net.DnsResult{T}" />. Equality compares the records one by one, rather than the lists.
/// </remarks>
/// <typeparam name="T">The type of the records.</typeparam>
/// <param name="ResponseCode">The response code.</param>
/// <param name="Records">The records, which only a <see cref="DnsResponseCode.NoError" /> result can have.</param>
/// <param name="NegativeCacheTtl">How long an NXDOMAIN or NODATA result may be cached (RFC 2308, Sec. 5).</param>
public readonly record struct DnsQueryResult<T>(DnsResponseCode ResponseCode, [AllowNull] IReadOnlyList<T> Records, TimeSpan NegativeCacheTtl)
{
	/// <summary>
	/// Gets the records; empty on an error, on NODATA, and for the default value.
	/// </summary>
	/// <remarks>The result keeps the list it is given, not a copy; a <see langword="null" /> list reads as empty.</remarks>
	[AllowNull]
	public IReadOnlyList<T> Records { get => field ?? []; init; } = Records;

	/// <summary>
	/// Determines whether <paramref name="other" /> has the same response code, negative-cache TTL and records.
	/// </summary>
	/// <param name="other">The result to compare with.</param>
	/// <returns><see langword="true" /> if they are equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsQueryResult<T> other)
	{
		return ResponseCode == other.ResponseCode && NegativeCacheTtl == other.NegativeCacheTtl && ListEquality.SequenceEqual(Records, other.Records);
	}

	/// <summary>
	/// Returns a hash code consistent with <see cref="Equals(DnsQueryResult{T})" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(ResponseCode);
		hash.Add(NegativeCacheTtl);
		ListEquality.AddTo(ref hash, Records);
		return hash.ToHashCode();
	}
}
