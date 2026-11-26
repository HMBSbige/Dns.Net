using Dns.Net.Abstractions;
using System.Net;
using static Dns.Net.Tests.Equality;

namespace Dns.Net.Tests;

public class DnsQueryResultTest
{
	private static readonly DnsAddressRecord First = new(IPAddress.Parse("192.0.2.1"), TimeSpan.FromSeconds(60));

	private static readonly DnsAddressRecord Second = new(IPAddress.Parse("2001:db8::1"), TimeSpan.FromSeconds(30));

	[Test]
	public async Task ListsAreNeverNull()
	{
		await Assert.That(default(DnsQueryResult<DnsMxRecord>).Records).IsEmpty();
		await Assert.That(new DnsQueryResult<DnsMxRecord>(DnsResponseCode.NoError, null, TimeSpan.Zero).Records).IsEmpty();
		await Assert.That((new DnsQueryResult<DnsMxRecord>(DnsResponseCode.NoError, [], TimeSpan.Zero) with { Records = null }).Records).IsEmpty();

		await Assert.That(default(DnsSrvRecord).Addresses).IsEmpty();
		await Assert.That(new DnsSrvRecord("sip.example.com", 5060, 10, 5, TimeSpan.Zero, null).Addresses).IsEmpty();
		await Assert.That((new DnsSrvRecord("sip.example.com", 5060, 10, 5, TimeSpan.Zero, [First]) with { Addresses = null }).Addresses).IsEmpty();

		await Assert.That(default(DnsTxtRecord).Values).IsEmpty();
		await Assert.That(new DnsTxtRecord(null, TimeSpan.Zero).Values).IsEmpty();
		await Assert.That((new DnsTxtRecord(["v=spf1 -all"], TimeSpan.Zero) with { Values = null }).Values).IsEmpty();
	}

	[Test]
	public async Task AResultKeepsTheListItIsGiven()
	{
		List<DnsAddressRecord> records = [First];

		await Assert.That(new DnsQueryResult<DnsAddressRecord>(DnsResponseCode.NoError, records, TimeSpan.Zero).Records).IsSameReferenceAs(records);
	}

	[Test]
	public async Task ResultsCompareTheirRecordsInOrder()
	{
		DnsQueryResult<DnsAddressRecord> result = new(DnsResponseCode.NoError, new List<DnsAddressRecord> { First, Second }, TimeSpan.Zero);
		DnsQueryResult<DnsAddressRecord> same = new(DnsResponseCode.NoError, [First, Second], TimeSpan.Zero);

		await AssertEqual(result, same);

		await Assert.That(result).IsNotEqualTo(same with { Records = [Second, First] });
		await Assert.That(result).IsNotEqualTo(same with { Records = [First] });
		await Assert.That(result).IsNotEqualTo(same with { ResponseCode = DnsResponseCode.ServerFailure });
		await Assert.That(result).IsNotEqualTo(same with { NegativeCacheTtl = TimeSpan.FromSeconds(1) });

		// A null list reads as empty, so it equals an empty one.
		DnsQueryResult<DnsAddressRecord> none = new(DnsResponseCode.NxDomain, null, TimeSpan.FromSeconds(5));
		DnsQueryResult<DnsAddressRecord> empty = new(DnsResponseCode.NxDomain, [], TimeSpan.FromSeconds(5));
		await AssertEqual(none, empty);
		await Assert.That(default(DnsQueryResult<DnsAddressRecord>)).IsEqualTo(new DnsQueryResult<DnsAddressRecord>(DnsResponseCode.NoError, [], TimeSpan.Zero));
	}

	[Test]
	public async Task SrvRecordsCompareTheirAddressesInOrder()
	{
		DnsSrvRecord record = new("sip.example.com", 5060, 10, 5, TimeSpan.FromSeconds(300), new List<DnsAddressRecord> { First, Second });
		DnsSrvRecord same = new("sip.example.com", 5060, 10, 5, TimeSpan.FromSeconds(300), [First, Second]);

		await AssertEqual(record, same);
		await Assert.That(record).IsNotEqualTo(same with { Addresses = [Second, First] });
		await Assert.That(record).IsNotEqualTo(same with { Target = "SIP.example.com" });
		await Assert.That(record).IsNotEqualTo(same with { Port = 5061 });
		await Assert.That(record).IsNotEqualTo(same with { Priority = 11 });
		await Assert.That(record).IsNotEqualTo(same with { Weight = 6 });
		await Assert.That(record).IsNotEqualTo(same with { Ttl = TimeSpan.FromSeconds(301) });

		// Results compare their records with the equality of the records.
		DnsQueryResult<DnsSrvRecord> result = new(DnsResponseCode.NoError, [record], TimeSpan.Zero);
		await AssertEqual(result, new DnsQueryResult<DnsSrvRecord>(DnsResponseCode.NoError, [same], TimeSpan.Zero));
	}

	[Test]
	public async Task TxtRecordsCompareTheirStringsInOrder()
	{
		DnsTxtRecord record = new(new List<string> { "a", "b" }, TimeSpan.FromSeconds(60));
		DnsTxtRecord same = new(["a", "b"], TimeSpan.FromSeconds(60));

		await AssertEqual(record, same);
		await Assert.That(record).IsNotEqualTo(same with { Values = ["b", "a"] });
		await Assert.That(record).IsNotEqualTo(same with { Values = ["a", "B"] });
		await Assert.That(record).IsNotEqualTo(same with { Ttl = TimeSpan.FromSeconds(61) });
	}
}
