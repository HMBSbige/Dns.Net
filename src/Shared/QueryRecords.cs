using Dns.Net.Abstractions;

namespace Dns.Net;

// Shared by the record types and DnsClient, which builds its address records with it.
internal static class QueryRecords
{
	// Skips the answers whose data is not TData.
	public static T[] Create<TData, T>(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, Func<TData, TimeSpan, T> create) where TData : DnsRecordData
	{
		T[] records = new T[answers.Length];
		int count = 0;

		foreach (DnsResourceRecord answer in answers)
		{
			if (answer.Data is TData data)
			{
				records[count++] = create(data, ttl);
			}
		}

		return count == records.Length ? records : records.AsSpan(0, count).ToArray();
	}
}
