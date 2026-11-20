using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents a TXT record (RFC 1035, Sec. 3.3.14): a sequence of character strings, with the TTL of the record.
/// </summary>
/// <remarks>
/// The type mirrors <see cref="System.Net.TxtRecord" />. The client decides how the strings are decoded; <see cref="DnsTxtData.Values" /> keeps the bytes.
/// Equality compares the strings one by one, ordinally, rather than the lists.
/// </remarks>
/// <param name="Values">The character strings of the record.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsTxtRecord([AllowNull] IReadOnlyList<string> Values, TimeSpan Ttl) : IDnsQueryRecord<DnsTxtRecord>
{
	/// <summary>
	/// Gets the character strings of the record.
	/// </summary>
	/// <remarks>The record keeps the list it is given, not a copy; a <see langword="null" /> list reads as empty.</remarks>
	[AllowNull]
	public IReadOnlyList<string> Values { get => field ?? []; init; } = Values;

	/// <summary>
	/// Determines whether <paramref name="other" /> has the same strings and TTL.
	/// </summary>
	/// <param name="other">The record to compare with.</param>
	/// <returns><see langword="true" /> if they are equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsTxtRecord other)
	{
		return Ttl == other.Ttl && ListEquality.SequenceEqual(Values, other.Values);
	}

	/// <summary>
	/// Returns a hash code consistent with <see cref="Equals(DnsTxtRecord)" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(Ttl);
		ListEquality.AddTo(ref hash, Values);
		return hash.ToHashCode();
	}

	static DnsRecordType IDnsQueryRecord<DnsTxtRecord>.Type => DnsRecordType.Txt;

	static DnsTxtRecord[] IDnsQueryRecord<DnsTxtRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create<DnsTxtRecord>(answers, ttl, static (data, recordTtl) => data is DnsTxtData { Values: var values } ? new DnsTxtRecord(Decode(values), recordTtl) : null);

		static string[] Decode(IReadOnlyList<ReadOnlyMemory<byte>> values)
		{
			string[] strings = new string[values.Count];

			for (int i = 0; i < strings.Length; ++i)
			{
				strings[i] = Encoding.UTF8.GetString(values[i].Span);
			}

			return strings;
		}
	}
}
