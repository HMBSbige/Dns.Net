using Dns.Net.Abstractions;
using System.Net;

namespace Dns.Net;

// Takes results already limited by NegativeCaching.
internal static class AddressResults
{
	public static DnsQueryResult<DnsAddressRecord> Merge(DnsQueryResult<DnsAddressRecord> a, DnsQueryResult<DnsAddressRecord> aaaa)
	{
		if (a.Records.Count is not 0 || aaaa.Records.Count is not 0)
		{
			return new DnsQueryResult<DnsAddressRecord>(DnsResponseCode.NoError, [.. a.Records, .. aaaa.Records], TimeSpan.Zero);
		}

		DnsResponseCode responseCode = a.ResponseCode is DnsResponseCode.NxDomain || aaaa.ResponseCode is DnsResponseCode.NxDomain
			? DnsResponseCode.NxDomain
			: a.ResponseCode is not DnsResponseCode.NoError ? a.ResponseCode : aaaa.ResponseCode;

		// A failure of one query takes no negative-cache TTL from a negative answer to the other.
		return new DnsQueryResult<DnsAddressRecord>(responseCode, [], NegativeCaching.Limit(responseCode, recordCount: 0, MinNonZero(a.NegativeCacheTtl, aaaa.NegativeCacheTtl)));

		static TimeSpan MinNonZero(TimeSpan x, TimeSpan y)
		{
			if (x <= TimeSpan.Zero)
			{
				return y > TimeSpan.Zero ? y : TimeSpan.Zero;
			}

			return y <= TimeSpan.Zero || x < y ? x : y;
		}
	}
}
