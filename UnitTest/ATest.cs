using Dns.Net.Abstractions;
using Dns.Net.Clients;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;

namespace UnitTest;

[TestClass]
public class ATest
{
	[TestMethod]
	public void TestDefault()
	{
		IDnsClient client = new DefaultAClient();
		IPAddress localhost = client.Query(@"localhost");
		Assert.AreEqual(IPAddress.Loopback, localhost);

		const string ipStr = @"131.107.255.255";
		IPAddress expected = IPAddress.Parse(ipStr);

		IPAddress ip = client.Query(ipStr);
		Assert.AreEqual(expected, ip);

		ip = client.Query(@"dns.msftncsi.com");
		Assert.AreEqual(expected, ip);
	}

	[TestMethod]
	public async Task TestDefaultAsync()
	{
		IDnsClient client = new DefaultAClient();
		IPAddress localhost = await client.QueryAsync(@"localhost");
		Assert.AreEqual(IPAddress.Loopback, localhost);

		const string ipStr = @"131.107.255.255";
		IPAddress expected = IPAddress.Parse(ipStr);

		IPAddress ip = await client.QueryAsync(ipStr);
		Assert.AreEqual(expected, ip);

		ip = await client.QueryAsync(@"dns.msftncsi.com");
		Assert.AreEqual(expected, ip);
	}
}
