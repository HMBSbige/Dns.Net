using System.Net;
using System.Net.Sockets;

namespace Dns.Net;

// IPAddress is mutable (ScopeId on IPv6, the obsolete Address setter on IPv4), so each owner keeps a copy of its own.
internal static class IPAddressCopy
{
	public static IPAddress Of(IPAddress address)
	{
		Span<byte> bytes = stackalloc byte[16];
		_ = address.TryWriteBytes(bytes, out int length);

		return address.AddressFamily is AddressFamily.InterNetworkV6 ? new IPAddress(bytes, address.ScopeId) : new IPAddress(bytes.Slice(0, length));
	}
}
