using Dns.Net.Abstractions;
using Dns.Net.Clients;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;

namespace UnitTest;

[TestClass]
public class UnitTest
{
	[TestMethod]
	public void TestDefault()
	{
		IDnsClient client = new DefaultDnsClient();
		IPAddress localhost = client.Query(@"localhost");
		Assert.IsTrue(Equals(localhost, IPAddress.Loopback) || Equals(localhost, IPAddress.IPv6Loopback));

		const string ipStr = @"1.1.1.1";
		IPAddress ip = client.Query(ipStr);
		Assert.IsTrue(ip.Equals(IPAddress.Parse(ipStr)));

		client.Query(@"stun.syncthing.net");
	}

	[TestMethod]
	public async Task TestDefaultAsync()
	{
		IDnsClient client = new DefaultDnsClient();
		IPAddress localhost = await client.QueryAsync(@"localhost");
		Assert.IsTrue(Equals(localhost, IPAddress.Loopback) || Equals(localhost, IPAddress.IPv6Loopback));

		const string ipStr = @"1.1.1.1";
		IPAddress ip = await client.QueryAsync(ipStr);
		Assert.IsTrue(ip.Equals(IPAddress.Parse(ipStr)));

		await client.QueryAsync(@"stun.syncthing.net");
	}
}
