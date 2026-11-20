namespace Dns.Net.Abstractions;

/// <summary>
/// Represents a PTR record (RFC 1035, Sec. 3.3.12).
/// </summary>
/// <remarks>The type mirrors <see cref="System.Net.PtrRecord" />.</remarks>
/// <param name="Name">The name pointed to.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsPtrRecord(string Name, TimeSpan Ttl) : IDnsQueryRecord<DnsPtrRecord>
{
	static DnsRecordType IDnsQueryRecord<DnsPtrRecord>.Type => DnsRecordType.Ptr;

	static DnsPtrRecord[] IDnsQueryRecord<DnsPtrRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create<DnsPtrRecord>(answers, ttl, static (data, recordTtl) => data is DnsPtrData ptr ? new DnsPtrRecord(InternationalNames.ToUnicode(ptr.Name), recordTtl) : null);
	}
}
