using System.Net.Sockets;

namespace Dns.Net.Abstractions;

// RFC 2181, Sec. 5.2.
internal static class RRsetTtl
{
	// The A records and the AAAA records of one owner are separate RRsets.
	public static void TakeLeastByFamily(Span<DnsAddressRecord> addresses)
	{
		TimeSpan v4 = TimeSpan.MaxValue;
		TimeSpan v6 = TimeSpan.MaxValue;

		foreach (DnsAddressRecord address in addresses)
		{
			ref TimeSpan least = ref address.Address.AddressFamily is AddressFamily.InterNetwork ? ref v4 : ref v6;

			if (address.Ttl < least)
			{
				least = address.Ttl;
			}
		}

		foreach (ref DnsAddressRecord address in addresses)
		{
			address = address with { Ttl = address.Address.AddressFamily is AddressFamily.InterNetwork ? v4 : v6 };
		}
	}
}
