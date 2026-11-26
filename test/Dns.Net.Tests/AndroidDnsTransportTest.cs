using System.Diagnostics.CodeAnalysis;

namespace Dns.Net.Tests;

public class AndroidDnsTransportTest
{
	[Test]
	[SuppressMessage("Interoperability", "CA1416", Justification = "Checks the platforms that the analyzer warns about.")]
	public async Task ConstructionFailsOutsideAndroid()
	{
		await Assert.That(() => new AndroidDnsTransport()).ThrowsExactly<PlatformNotSupportedException>();
	}
}
