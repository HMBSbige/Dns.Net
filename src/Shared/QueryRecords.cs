using Dns.Net.Abstractions;

namespace Dns.Net;

// Shared by the record types and DnsClient, which builds its address records with it.
internal static class QueryRecords
{
	// Skips the answers for which create gives null.
	public static T[] Create<T>(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, Func<DnsRecordData, TimeSpan, T?> create) where T : struct
	{
		T[] records = new T[answers.Length];
		int count = 0;

		foreach (DnsResourceRecord answer in answers)
		{
			if (create(answer.Data, ttl) is { } record)
			{
				records[count++] = record;
			}
		}

		return count == records.Length ? records : records.AsSpan(0, count).ToArray();
	}
}
