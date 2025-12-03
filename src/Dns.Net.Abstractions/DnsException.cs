namespace Dns.Net.Abstractions;

public class DnsException(string? message) : Exception(message)
{
	public static void Throw(string? message = default)
	{
		throw new DnsException(message);
	}
}
