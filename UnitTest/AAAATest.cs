using Dns.Net.Abstractions;
using Dns.Net.Clients;
using System.Net;

namespace UnitTest;

[TestClass]
public class AAAATest
{
	public TestContext TestContext { get; set; }

	[TestMethod]
	public void TestDefault()
	{
		IDnsClient client = new DefaultAAAAClient();
		IPAddress localhost = client.Query(@"localhost");
		Assert.AreEqual(IPAddress.IPv6Loopback, localhost);

		const string ipStr = @"fd3e:4f5a:5b81::1";
		IPAddress expected = IPAddress.Parse(ipStr);

		IPAddress ip = client.Query(ipStr);
		Assert.AreEqual(expected, ip);
	}

	[TestMethod]
	public async Task TestDefaultAsync()
	{
		IDnsClient client = new DefaultAAAAClient();
		IPAddress localhost = await client.QueryAsync(@"localhost", TestContext.CancellationToken);
		Assert.AreEqual(IPAddress.IPv6Loopback, localhost);

		const string ipStr = @"fd3e:4f5a:5b81::1";
		IPAddress expected = IPAddress.Parse(ipStr);

		IPAddress ip = await client.QueryAsync(ipStr, TestContext.CancellationToken);
		Assert.AreEqual(expected, ip);
	}
}
