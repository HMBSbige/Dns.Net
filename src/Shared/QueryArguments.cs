using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace Dns.Net;

// The address families of IDnsClient.ResolveAddressesAsync; shared so that the clients and DnsClientExtensions reject the same ones.
internal static class QueryArguments
{
	public static void CheckAddressFamily(AddressFamily addressFamily, [CallerArgumentExpression(nameof(addressFamily))] string? paramName = null)
	{
		if (addressFamily is not (AddressFamily.Unspecified or AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
		{
			throw new ArgumentOutOfRangeException(paramName, addressFamily, "The address family is neither Unspecified, InterNetwork nor InterNetworkV6.");
		}
	}
}
