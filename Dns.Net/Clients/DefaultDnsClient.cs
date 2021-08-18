using Dns.Net.Abstractions;
using Microsoft;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Dns.Net.Clients
{
	public class DefaultDnsClient : IDnsClient
	{
		public async ValueTask<IPAddress> QueryAsync(string hostname, CancellationToken cancellationToken = default)
		{
			Requires.NotNull(hostname, nameof(hostname));

			var resTask = System.Net.Dns.GetHostAddressesAsync(hostname);

			if (cancellationToken.CanBeCanceled)
			{
				var t = Task.Delay(-1, cancellationToken);

				var task = await Task.WhenAny(resTask, t);

				if (task == t)
				{
					throw new OperationCanceledException();
				}
			}

			var res = await resTask;

			if (res.LongLength <= 0)
			{
				DnsException.Throw();
			}

			return res[0];
		}

		public IPAddress Query(string hostname)
		{
			Requires.NotNull(hostname, nameof(hostname));

			var res = System.Net.Dns.GetHostAddresses(hostname);

			if (res.LongLength <= 0)
			{
				DnsException.Throw();
			}

			return res[0];
		}
	}
}
