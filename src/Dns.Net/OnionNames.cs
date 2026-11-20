using Dns.Net.Abstractions;
using System.Net;

namespace Dns.Net;

// RFC 7686, Sec. 2.
internal static class OnionNames
{
	// A canceled token cancels this answer too, so that the name makes no difference to the caller.
	public static ValueTask<DnsQueryResult<T>> NxDomain<T>(CancellationToken cancellationToken)
	{
		return cancellationToken.IsCancellationRequested
			? ValueTask.FromCanceled<DnsQueryResult<T>>(cancellationToken)
			: ValueTask.FromResult(new DnsQueryResult<T>(DnsResponseCode.NxDomain, [], TimeSpan.Zero));
	}
}
