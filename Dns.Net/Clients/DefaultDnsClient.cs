using Dns.Net.Abstractions;
using System.Net;

namespace Dns.Net.Clients;

public class DefaultDnsClient : IDnsClient
{
	public async ValueTask<IPAddress> QueryAsync(string hostname, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(hostname);

		IPAddress[] res = await System.Net.Dns.GetHostAddressesAsync(hostname, cancellationToken);

		if (res.LongLength <= 0)
		{
			DnsException.Throw();
		}

		return res[0];
	}

	public IPAddress Query(string hostname)
	{
		ArgumentNullException.ThrowIfNull(hostname);

		IPAddress[] res = System.Net.Dns.GetHostAddresses(hostname);

		if (res.LongLength <= 0)
		{
			DnsException.Throw();
		}

		return res[0];
	}
}
