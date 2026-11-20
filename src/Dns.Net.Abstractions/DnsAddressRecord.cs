using System.Net;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents an address that an A or AAAA record holds, with the TTL of that record.
/// </summary>
/// <remarks>The type mirrors <see cref="System.Net.AddressRecord" />.</remarks>
/// <param name="Address">The IPv4 address of an A record, or the IPv6 address of an AAAA record.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsAddressRecord(IPAddress Address, TimeSpan Ttl);
