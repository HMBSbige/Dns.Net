namespace Dns.Net.Abstractions;

public class DnsException : Exception
{
	public DnsException() { }
	public DnsException(string? message) : base(message) { }

	public static void Throw(string? message = null)
	{
		if (string.IsNullOrEmpty(message))
		{
			throw new DnsException(message);
		}

		throw new DnsException();
	}
}
