namespace Dns.Net.Abstractions;

/// <summary>
/// Represents an MX record (RFC 1035, Sec. 3.3.9).
/// </summary>
/// <remarks>
/// The type mirrors <see cref="System.Net.MxRecord" />. <see cref="IDnsQueryRecord{TSelf}.CreateRecords" /> keeps the escapes of <see cref="DnsName.ToString" />, except that a name with an <c>xn--</c> label comes back in Unicode, and in lowercase, when <see cref="System.Globalization.IdnMapping" /> converts the whole name, which it does not for a name with an escape, an underscore label or an invalid <c>xn--</c> label.
/// </remarks>
/// <param name="Exchange">The name of the mail exchange host.</param>
/// <param name="Preference">The preference of the host; lower is preferred.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsMxRecord(string Exchange, ushort Preference, TimeSpan Ttl) : IDnsQueryRecord<DnsMxRecord>
{
	static DnsRecordType IDnsQueryRecord<DnsMxRecord>.Type => DnsRecordType.Mx;

	static DnsMxRecord[] IDnsQueryRecord<DnsMxRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create(answers, ttl, static (DnsMxData mx, TimeSpan recordTtl) => new DnsMxRecord(InternationalNames.ToUnicode(mx.Exchange), mx.Preference, recordTtl));
	}
}
