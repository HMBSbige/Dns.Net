using System.Net;

namespace Dns.Net;

internal static class NegativeCaching
{
	// Only NXDOMAIN and NODATA are negative answers (RFC 2308, Sec. 5); a failure such as SERVFAIL is not.
	public static TimeSpan Limit(DnsResponseCode responseCode, int recordCount, TimeSpan ttl)
	{
		return recordCount is 0 && responseCode is DnsResponseCode.NoError or DnsResponseCode.NxDomain ? ttl : TimeSpan.Zero;
	}
}
