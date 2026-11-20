namespace Dns.Net.Abstractions;

/// <summary>
/// Defines a record type that <see cref="IDnsClient.ResolveAsync{TRecord}" /> resolves, and how its records are built from a response.
/// </summary>
/// <typeparam name="TSelf">The type that implements the interface.</typeparam>
public interface IDnsQueryRecord<out TSelf> where TSelf : IDnsQueryRecord<TSelf>
{
	/// <summary>
	/// Gets the record type that the query asks for, which must be a data type, not a meta-type such as ANY.
	/// </summary>
	static abstract DnsRecordType Type { get; }

	/// <summary>
	/// Gets the TTL of the record.
	/// </summary>
	TimeSpan Ttl { get; }

	/// <summary>
	/// Creates the records of a result from one RRset of a response.
	/// </summary>
	/// <remarks>The method skips answers it cannot represent. An empty array lets a client that follows a CNAME chain go on from a CNAME record of that owner.</remarks>
	/// <param name="answers">The RRset: the records of type <see cref="Type" /> and class IN of one owner.</param>
	/// <param name="ttl">The least TTL among <paramref name="answers" />, which each record takes, except an RRSIG record (RFC 2181, Sec. 5.2).</param>
	/// <param name="response">The response, for its other sections.</param>
	/// <returns>The records, in order; never <see langword="null" />.</returns>
	static abstract TSelf[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response);
}
