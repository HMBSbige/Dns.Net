using Dns.Net.Abstractions;
using Microsoft;
using System.Net;
using System.Net.Sockets;

namespace Dns.Net.Clients;

public class DefaultAClient : IDnsClient
{
	public async ValueTask<IPAddress> QueryAsync(string hostname, CancellationToken cancellationToken = default)
	{
		Requires.NotNull(hostname, nameof(hostname));

		IPAddress[] res = await System.Net.Dns.GetHostAddressesAsync(hostname, AddressFamily.InterNetwork, cancellationToken);

		if (res.LongLength <= 0)
		{
			DnsException.Throw();
		}

		return res[0];
	}

	public IPAddress Query(string hostname)
	{
		Requires.NotNull(hostname, nameof(hostname));

		IPAddress[] res = System.Net.Dns.GetHostAddresses(hostname, AddressFamily.InterNetwork);

		if (res.LongLength <= 0)
		{
			DnsException.Throw();
		}

		return res[0];
	}
}
