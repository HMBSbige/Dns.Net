namespace Dns.Net.Abstractions;

/// <summary>
/// Represents an NS record (RFC 1035, Sec. 3.3.11).
/// </summary>
/// <remarks>The type mirrors <see cref="System.Net.NsRecord" />.</remarks>
/// <param name="Name">The name of the name server.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsNsRecord(string Name, TimeSpan Ttl) : IDnsQueryRecord<DnsNsRecord>
{
	static DnsRecordType IDnsQueryRecord<DnsNsRecord>.Type => DnsRecordType.Ns;

	static DnsNsRecord[] IDnsQueryRecord<DnsNsRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create<DnsNsRecord>(answers, ttl, static (data, recordTtl) => data is DnsNsData ns ? new DnsNsRecord(InternationalNames.ToUnicode(ns.Name), recordTtl) : null);
	}
}
