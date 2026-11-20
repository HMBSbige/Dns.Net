using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Dns.Net.Abstractions;

/// <summary>
/// Provides a query for both address families, reverse lookups by address, and host name resolution like that of <see cref="System.Net.Dns" />, for any <see cref="IDnsClient" />.
/// </summary>
public static class DnsClientExtensions
{
	private const int MaxHostNameLength = 255;

	/// <param name="client">The client that makes the queries.</param>
	extension(IDnsClient client)
	{
		/// <summary>
		/// Asynchronously resolves both the IPv4 addresses (A records) and the IPv6 addresses (AAAA records) of a host.
		/// </summary>
		/// <param name="name">The host name.</param>
		/// <param name="cancellationToken">The token used to cancel the queries.</param>
		/// <returns>A value task whose result holds the A records, then the AAAA records.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="client" /> or <paramref name="name" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="name" /> is empty, or not a valid name for the client.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask<DnsQueryResult<DnsAddressRecord>> ResolveAddressesAsync(string name, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(client);

			return client.ResolveAddressesAsync(name, AddressFamily.Unspecified, cancellationToken);
		}

		/// <summary>
		/// Asynchronously resolves the PTR records of an address, the reverse lookup.
		/// </summary>
		/// <remarks>The query goes to <c>in-addr.arpa</c> or <c>ip6.arpa</c> (RFC 1035, Sec. 3.5; RFC 3596, Sec. 2.5); an IPv4-mapped IPv6 address counts as an IPv6 address.</remarks>
		/// <param name="address">The address.</param>
		/// <param name="cancellationToken">The token used to cancel the query.</param>
		/// <returns>A value task whose result holds the PTR records, in the order of the response.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="client" /> or <paramref name="address" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="address" /> is neither an IPv4 nor an IPv6 address.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask<DnsQueryResult<DnsPtrRecord>> ResolvePtrAsync(IPAddress address, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(client);
			ArgumentNullException.ThrowIfNull(address);

			return client.ResolveAsync<DnsPtrRecord>(BuildReverseLookupName(address), cancellationToken);
		}

		/// <summary>
		/// Asynchronously resolves the IPv4 and IPv6 addresses of a host, as <see cref="System.Net.Dns.GetHostAddressesAsync(string, CancellationToken)" /> does, but through the client.
		/// </summary>
		/// <remarks>The rules are those of <see cref="GetHostAddressesAsync(IDnsClient, string, AddressFamily, CancellationToken)" />.</remarks>
		/// <param name="hostNameOrAddress">The host name, or an IP address in text.</param>
		/// <param name="cancellationToken">The token used to cancel the queries.</param>
		/// <returns>A value task whose result is the addresses, the IPv4 addresses first, except ::1 before 127.0.0.1 for a name in <c>localhost</c>.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="client" /> or <paramref name="hostNameOrAddress" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException">
		/// <paramref name="hostNameOrAddress" /> is the address 0.0.0.0 or ::; or it is not an IP address, and is empty, has a null character or is not a valid name for the client.
		/// </exception>
		/// <exception cref="ArgumentOutOfRangeException"><paramref name="hostNameOrAddress" /> is not an IP address, and is longer than 255 characters, or exactly 255 without a trailing dot.</exception>
		/// <exception cref="SocketException">The host has no address: <see cref="SocketException.SocketErrorCode" /> tells why.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress, CancellationToken cancellationToken = default)
		{
			return client.GetHostAddressesAsync(hostNameOrAddress, AddressFamily.Unspecified, cancellationToken);
		}

		/// <summary>
		/// Asynchronously resolves the addresses of a family of a host, as <see cref="System.Net.Dns.GetHostAddressesAsync(string, AddressFamily, CancellationToken)" /> does, but through the client.
		/// </summary>
		/// <remarks>
		/// <para>
		/// An IP address resolves to itself, and the special-use names <c>localhost</c>, <c>invalid</c> and <c>onion</c> and the names below them resolve or fail without a query (RFC 6761, Sec. 6.3 and 6.4; RFC 7686, Sec. 2).
		/// Unlike in <see cref="System.Net.Dns" />, an empty name throws rather than standing for the local host, and no hosts file or search domain is used.
		/// If the operating system does not support IPv6, <see cref="AddressFamily.InterNetworkV6" /> gives an empty result and <see cref="AddressFamily.Unspecified" /> asks only for IPv4.
		/// </para>
		/// <para>
		/// Invalid arguments throw at once; a <see cref="SocketException" /> comes through the task, and an exception of the client comes through as it is.
		/// NODATA maps to <see cref="SocketError.NoData" />, NXDOMAIN to <see cref="SocketError.HostNotFound" />, SERVFAIL to <see cref="SocketError.TryAgain" />, and any other response code to <see cref="SocketError.NoRecovery" />.
		/// </para>
		/// </remarks>
		/// <param name="hostNameOrAddress">The host name, or an IP address in text.</param>
		/// <param name="family"><see cref="AddressFamily.InterNetwork" /> for IPv4 addresses, <see cref="AddressFamily.InterNetworkV6" /> for IPv6 addresses, or <see cref="AddressFamily.Unspecified" /> for both.</param>
		/// <param name="cancellationToken">The token used to cancel the queries.</param>
		/// <returns>A value task whose result is the addresses, as new instances that the caller may change.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="client" /> or <paramref name="hostNameOrAddress" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException">
		/// <paramref name="hostNameOrAddress" /> is the address 0.0.0.0 or ::; or it is not an IP address, and is empty, has a null character or is not a valid name for the client.
		/// </exception>
		/// <exception cref="ArgumentOutOfRangeException">
		/// <paramref name="family" /> is not <see cref="AddressFamily.Unspecified" />, <see cref="AddressFamily.InterNetwork" /> or <see cref="AddressFamily.InterNetworkV6" />;
		/// or <paramref name="hostNameOrAddress" /> is not an IP address, and is longer than 255 characters, or exactly 255 without a trailing dot.
		/// </exception>
		/// <exception cref="SocketException">The host has no address: <see cref="SocketException.SocketErrorCode" /> tells why.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress, AddressFamily family, CancellationToken cancellationToken = default)
		{
			return GetHostAddressesCoreAsync(client, hostNameOrAddress, family, OperatingSystem.IsBrowser() || Socket.OSSupportsIPv6, cancellationToken);
		}
	}

	// The IPv6 support of the operating system is a parameter so that tests can vary it.
	internal static ValueTask<IPAddress[]> GetHostAddressesCoreAsync(IDnsClient client, string hostNameOrAddress, AddressFamily family, bool osSupportsIPv6, CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(client);
		ArgumentNullException.ThrowIfNull(hostNameOrAddress);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<IPAddress[]>(cancellationToken);
		}

		if (family is not (AddressFamily.Unspecified or AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
		{
			throw new ArgumentOutOfRangeException(nameof(family), family, "The address family is neither Unspecified, InterNetwork nor InterNetworkV6.");
		}

		if (!osSupportsIPv6)
		{
			if (family is AddressFamily.InterNetworkV6)
			{
				return ValueTask.FromResult<IPAddress[]>([]);
			}

			family = AddressFamily.InterNetwork;
		}

		if (IPAddress.TryParse(hostNameOrAddress, out IPAddress? address))
		{
			if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
			{
				throw new ArgumentException("The address 0.0.0.0 or :: is not the address of a host.", nameof(hostNameOrAddress));
			}

			return ValueTask.FromResult<IPAddress[]>(family is AddressFamily.Unspecified || address.AddressFamily == family ? [address] : []);
		}

		if (hostNameOrAddress.Length > MaxHostNameLength || hostNameOrAddress.Length == MaxHostNameLength && hostNameOrAddress[^1] is not '.')
		{
			throw new ArgumentOutOfRangeException(nameof(hostNameOrAddress), "The host name is longer than 255 characters, or 255 characters long without a trailing dot.");
		}

		if (hostNameOrAddress.Contains('\0'))
		{
			throw new ArgumentException("The host name has a null character.", nameof(hostNameOrAddress));
		}

		if (hostNameOrAddress.Length is 0)
		{
			throw new ArgumentException("The host name is empty; without a resolver of the operating system, it does not stand for the local host.", nameof(hostNameOrAddress));
		}

		if (SpecialUseNames.IsInvalid(hostNameOrAddress))
		{
			return ValueTask.FromException<IPAddress[]>(CreateSocketException(SocketError.HostNotFound, $"The host name '{hostNameOrAddress}' is in the special-use domain invalid, which never resolves (RFC 6761, Sec. 6.4)."));
		}

		if (SpecialUseNames.IsOnion(hostNameOrAddress))
		{
			return ValueTask.FromException<IPAddress[]>(CreateSocketException(SocketError.HostNotFound, $"The host name '{hostNameOrAddress}' is in the special-use domain onion, which only Tor resolves; no query is sent for it (RFC 7686)."));
		}

		if (SpecialUseNames.IsLocalhost(hostNameOrAddress))
		{
			return ValueTask.FromResult(GetLoopbackAddresses(family));
		}

		return GetAddressesAsync(client.ResolveAddressesAsync(hostNameOrAddress, family, cancellationToken), hostNameOrAddress);
	}

	private static string BuildReverseLookupName(IPAddress address)
	{
		Span<byte> bytes = stackalloc byte[16];

		switch (address.AddressFamily)
		{
			case AddressFamily.InterNetwork:
			{
				_ = address.TryWriteBytes(bytes, out _);
				return string.Create(CultureInfo.InvariantCulture, $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa");
			}
			case AddressFamily.InterNetworkV6:
			{
				_ = address.TryWriteBytes(bytes, out _);
				Span<char> nibbles = stackalloc char[bytes.Length * 4];

				for (int i = 0; i < bytes.Length; ++i)
				{
					byte value = bytes[bytes.Length - 1 - i];
					nibbles[i * 4] = ToHexDigit(value & 0xF);
					nibbles[i * 4 + 1] = '.';
					nibbles[i * 4 + 2] = ToHexDigit(value >> 4);
					nibbles[i * 4 + 3] = '.';
				}

				return string.Concat(nibbles, "ip6.arpa");
			}
			default:
			{
				throw new ArgumentException("The address is neither an IPv4 nor an IPv6 address.", nameof(address));
			}
		}

		static char ToHexDigit(int value)
		{
			return (char)(value < 10 ? '0' + value : 'a' + value - 10);
		}
	}

	private static IPAddress[] GetLoopbackAddresses(AddressFamily family)
	{
		// New instances, so that the caller may change them, as the scope of an IPv6 address.
		IPAddress ipv4 = new(IPAddress.Loopback.GetAddressBytes());
		IPAddress ipv6 = new(IPAddress.IPv6Loopback.GetAddressBytes());

		return family switch
		{
			AddressFamily.InterNetwork => [ipv4],
			AddressFamily.InterNetworkV6 => [ipv6],
			_ => [ipv6, ipv4]
		};
	}

	private static async ValueTask<IPAddress[]> GetAddressesAsync(ValueTask<DnsQueryResult<DnsAddressRecord>> query, string hostName)
	{
		DnsQueryResult<DnsAddressRecord> result = await query.ConfigureAwait(false);
		IReadOnlyList<DnsAddressRecord> records = result.Records;

		if (records.Count is not 0)
		{
			IPAddress[] addresses = new IPAddress[records.Count];

			for (int i = 0; i < addresses.Length; ++i)
			{
				// The client may return the same records again, as from a cache; each caller gets addresses of its own.
				addresses[i] = IPAddressCopy.Of(records[i].Address);
			}

			return addresses;
		}

		throw result.ResponseCode switch
		{
			DnsResponseCode.NoError => CreateSocketException(SocketError.NoData, $"The host '{hostName}' has no address of the requested family (NODATA)."),
			DnsResponseCode.NxDomain => CreateSocketException(SocketError.HostNotFound, $"The host '{hostName}' does not exist (NXDOMAIN)."),
			DnsResponseCode.ServerFailure => CreateSocketException(SocketError.TryAgain, $"The server failed to resolve the host '{hostName}' (SERVFAIL); a later attempt may succeed."),
			_ => CreateSocketException(SocketError.NoRecovery, $"The server could not resolve the host '{hostName}' (response code {result.ResponseCode}).")
		};
	}

	private static SocketException CreateSocketException(SocketError error, string message)
	{
		return new SocketException((int)error, message);
	}
}
