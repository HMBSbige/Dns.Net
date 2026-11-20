using System.Net.Sockets;

namespace Dns.Net;

// The checks that every IDnsClient makes before it returns the value task.
internal static class QueryArguments
{
	public static void CheckName(string name)
	{
		ArgumentException.ThrowIfNullOrEmpty(name);
	}

	public static void CheckAddressFamily(AddressFamily addressFamily)
	{
		if (addressFamily is not (AddressFamily.Unspecified or AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
		{
			throw new ArgumentOutOfRangeException(nameof(addressFamily), addressFamily, "The address family is neither Unspecified, InterNetwork nor InterNetworkV6.");
		}
	}
}
