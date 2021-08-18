using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Dns.Net.Abstractions
{
	public interface IDnsClient
	{
		ValueTask<IPAddress> QueryAsync(string hostname, CancellationToken cancellationToken = default);
		IPAddress Query(string hostname);
	}
}
