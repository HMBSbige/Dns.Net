using Dns.Net.Abstractions;
using Dns.Net.Clients;
using System.Net;

namespace UnitTest;

[TestClass]
public class UnitTest
{
	public TestContext TestContext { get; set; }

	[TestMethod]
	public void TestDefault()
	{
		IDnsClient client = new DefaultDnsClient();
		IPAddress localhost = client.Query(@"localhost");
		Assert.IsTrue(Equals(localhost, IPAddress.Loopback) || Equals(localhost, IPAddress.IPv6Loopback));

		const string ipStr = @"1.1.1.1";
		IPAddress ip = client.Query(ipStr);
		Assert.AreEqual(IPAddress.Parse(ipStr), ip);

		client.Query(@"github.com");
	}

	[TestMethod]
	public async Task TestDefaultAsync()
	{
		IDnsClient client = new DefaultDnsClient();
		IPAddress localhost = await client.QueryAsync(@"localhost", TestContext.CancellationToken);
		Assert.IsTrue(Equals(localhost, IPAddress.Loopback) || Equals(localhost, IPAddress.IPv6Loopback));

		const string ipStr = @"1.1.1.1";
		IPAddress ip = await client.QueryAsync(ipStr, TestContext.CancellationToken);
		Assert.AreEqual(IPAddress.Parse(ipStr), ip);

		await client.QueryAsync(@"github.com", TestContext.CancellationToken);
	}
}
