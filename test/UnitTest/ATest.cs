using Dns.Net.Abstractions;
using Dns.Net.Clients;
using System.Net;

namespace UnitTest;

[TestClass]
public class ATest
{
	public TestContext TestContext { get; set; }

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
		IPAddress localhost = await client.QueryAsync(@"localhost", TestContext.CancellationToken);
		Assert.AreEqual(IPAddress.Loopback, localhost);

		const string ipStr = @"131.107.255.255";
		IPAddress expected = IPAddress.Parse(ipStr);

		IPAddress ip = await client.QueryAsync(ipStr, TestContext.CancellationToken);
		Assert.AreEqual(expected, ip);

		ip = await client.QueryAsync(@"dns.msftncsi.com", TestContext.CancellationToken);
		Assert.AreEqual(expected, ip);
	}
}
