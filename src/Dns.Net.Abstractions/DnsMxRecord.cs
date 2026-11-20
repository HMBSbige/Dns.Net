namespace Dns.Net.Abstractions;

/// <summary>
/// Represents an MX record (RFC 1035, Sec. 3.3.9).
/// </summary>
/// <remarks>The type mirrors <see cref="System.Net.MxRecord" />.</remarks>
/// <param name="Exchange">The name of the mail exchange host.</param>
/// <param name="Preference">The preference of the host; lower is preferred.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsMxRecord(string Exchange, ushort Preference, TimeSpan Ttl) : IDnsQueryRecord<DnsMxRecord>
{
	static DnsRecordType IDnsQueryRecord<DnsMxRecord>.Type => DnsRecordType.Mx;

	static DnsMxRecord[] IDnsQueryRecord<DnsMxRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create<DnsMxRecord>(answers, ttl, static (data, recordTtl) => data is DnsMxData mx ? new DnsMxRecord(InternationalNames.ToUnicode(mx.Exchange), mx.Preference, recordTtl) : null);
	}
}
