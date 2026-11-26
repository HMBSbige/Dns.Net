namespace Dns.Net.Abstractions;

/// <summary>
/// Represents a PTR record (RFC 1035, Sec. 3.3.12).
/// </summary>
/// <remarks>
/// The type mirrors <see cref="System.Net.PtrRecord" />. <see cref="IDnsQueryRecord{TSelf}.CreateRecords" /> keeps the escapes of <see cref="DnsName.ToString" />, except that a name with an <c>xn--</c> label comes back in Unicode, and in lowercase, when <see cref="System.Globalization.IdnMapping" /> converts the whole name, which it does not for a name with an escape, an underscore label or an invalid <c>xn--</c> label.
/// </remarks>
/// <param name="Name">The name pointed to.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsPtrRecord(string Name, TimeSpan Ttl) : IDnsQueryRecord<DnsPtrRecord>
{
	static DnsRecordType IDnsQueryRecord<DnsPtrRecord>.Type => DnsRecordType.Ptr;

	static DnsPtrRecord[] IDnsQueryRecord<DnsPtrRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create(answers, ttl, static (DnsPtrData ptr, TimeSpan recordTtl) => new DnsPtrRecord(InternationalNames.ToUnicode(ptr.Name), recordTtl));
	}
}
