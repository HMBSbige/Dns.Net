namespace Dns.Net.Abstractions;

/// <summary>
/// Represents a CNAME record (RFC 1035, Sec. 3.3.1).
/// </summary>
/// <remarks>The type mirrors <see cref="System.Net.CNameRecord" />.</remarks>
/// <param name="CanonicalName">The canonical name.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsCNameRecord(string CanonicalName, TimeSpan Ttl) : IDnsQueryRecord<DnsCNameRecord>
{
	static DnsRecordType IDnsQueryRecord<DnsCNameRecord>.Type => DnsRecordType.CName;

	static DnsCNameRecord[] IDnsQueryRecord<DnsCNameRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create<DnsCNameRecord>(answers, ttl, static (data, recordTtl) => data is DnsCNameData cname ? new DnsCNameRecord(InternationalNames.ToUnicode(cname.CanonicalName), recordTtl) : null);
	}
}
