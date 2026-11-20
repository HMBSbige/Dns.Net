using Dns.Net.Abstractions;
using System.Net;

namespace Dns.Net.Tests;

public class DnsQueryResultTest
{
	private static readonly DnsAddressRecord First = new(IPAddress.Parse("192.0.2.1"), TimeSpan.FromSeconds(60));

	private static readonly DnsAddressRecord Second = new(IPAddress.Parse("2001:db8::1"), TimeSpan.FromSeconds(30));

	[Test]
	public async Task ListsAreNeverNull()
	{
		await Assert.That(default(DnsQueryResult<DnsMxRecord>).Records).IsNotNull().And.IsEmpty();
		await Assert.That(new DnsQueryResult<DnsMxRecord>(DnsResponseCode.NoError, null, TimeSpan.Zero).Records).IsNotNull().And.IsEmpty();
		await Assert.That((new DnsQueryResult<DnsMxRecord>(DnsResponseCode.NoError, [], TimeSpan.Zero) with { Records = null }).Records).IsNotNull().And.IsEmpty();

		await Assert.That(default(DnsSrvRecord).Addresses).IsNotNull().And.IsEmpty();
		await Assert.That(new DnsSrvRecord("sip.example.com", 5060, 10, 5, TimeSpan.Zero, null).Addresses).IsNotNull().And.IsEmpty();
		await Assert.That((new DnsSrvRecord("sip.example.com", 5060, 10, 5, TimeSpan.Zero, [First]) with { Addresses = null }).Addresses).IsNotNull().And.IsEmpty();

		await Assert.That(default(DnsTxtRecord).Values).IsNotNull().And.IsEmpty();
		await Assert.That(new DnsTxtRecord(null, TimeSpan.Zero).Values).IsNotNull().And.IsEmpty();
		await Assert.That((new DnsTxtRecord(["v=spf1 -all"], TimeSpan.Zero) with { Values = null }).Values).IsNotNull().And.IsEmpty();
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

		await Assert.That(result).IsEqualTo(same);
		await Assert.That(result == same).IsTrue();
		await Assert.That(result.GetHashCode()).IsEqualTo(same.GetHashCode());

		await Assert.That(result).IsNotEqualTo(same with { Records = [Second, First] });
		await Assert.That(result).IsNotEqualTo(same with { Records = [First] });
		await Assert.That(result).IsNotEqualTo(same with { ResponseCode = DnsResponseCode.ServerFailure });
		await Assert.That(result).IsNotEqualTo(same with { NegativeCacheTtl = TimeSpan.FromSeconds(1) });

		// A null list reads as empty, so it equals an empty one.
		DnsQueryResult<DnsAddressRecord> none = new(DnsResponseCode.NxDomain, null, TimeSpan.FromSeconds(5));
		DnsQueryResult<DnsAddressRecord> empty = new(DnsResponseCode.NxDomain, [], TimeSpan.FromSeconds(5));
		await Assert.That(none).IsEqualTo(empty);
		await Assert.That(none.GetHashCode()).IsEqualTo(empty.GetHashCode());
		await Assert.That(default(DnsQueryResult<DnsAddressRecord>)).IsEqualTo(new DnsQueryResult<DnsAddressRecord>(DnsResponseCode.NoError, [], TimeSpan.Zero));
	}

	[Test]
	public async Task SrvRecordsCompareTheirAddressesInOrder()
	{
		DnsSrvRecord record = new("sip.example.com", 5060, 10, 5, TimeSpan.FromSeconds(300), new List<DnsAddressRecord> { First, Second });
		DnsSrvRecord same = new("sip.example.com", 5060, 10, 5, TimeSpan.FromSeconds(300), [First, Second]);

		await Assert.That(record).IsEqualTo(same);
		await Assert.That(record.GetHashCode()).IsEqualTo(same.GetHashCode());
		await Assert.That(record).IsNotEqualTo(same with { Addresses = [Second, First] });
		await Assert.That(record).IsNotEqualTo(same with { Target = "SIP.example.com" });
		await Assert.That(record).IsNotEqualTo(same with { Port = 5061 });
		await Assert.That(record).IsNotEqualTo(same with { Priority = 11 });
		await Assert.That(record).IsNotEqualTo(same with { Weight = 6 });
		await Assert.That(record).IsNotEqualTo(same with { Ttl = TimeSpan.FromSeconds(301) });

		// Results compare their records with the equality of the records.
		DnsQueryResult<DnsSrvRecord> result = new(DnsResponseCode.NoError, [record], TimeSpan.Zero);
		await Assert.That(result).IsEqualTo(new DnsQueryResult<DnsSrvRecord>(DnsResponseCode.NoError, [same], TimeSpan.Zero));
		await Assert.That(result.GetHashCode()).IsEqualTo(new DnsQueryResult<DnsSrvRecord>(DnsResponseCode.NoError, [same], TimeSpan.Zero).GetHashCode());
	}

	[Test]
	public async Task TxtRecordsCompareTheirStringsInOrder()
	{
		DnsTxtRecord record = new(new List<string> { "a", "b" }, TimeSpan.FromSeconds(60));
		DnsTxtRecord same = new(["a", "b"], TimeSpan.FromSeconds(60));

		await Assert.That(record).IsEqualTo(same);
		await Assert.That(record.GetHashCode()).IsEqualTo(same.GetHashCode());
		await Assert.That(record).IsNotEqualTo(same with { Values = ["b", "a"] });
		await Assert.That(record).IsNotEqualTo(same with { Values = ["a", "B"] });
		await Assert.That(record).IsNotEqualTo(same with { Ttl = TimeSpan.FromSeconds(61) });
	}

	[Test]
	public async Task RecordsWithoutListsCompareByValue()
	{
		await Assert.That(new DnsMxRecord("mail.example.com", 10, TimeSpan.FromSeconds(60))).IsEqualTo(new DnsMxRecord("mail.example.com", 10, TimeSpan.FromSeconds(60)));
		await Assert.That(new DnsAddressRecord(IPAddress.Parse("192.0.2.1"), TimeSpan.FromSeconds(60))).IsEqualTo(First);
		await Assert.That(new DnsCNameRecord("example.com", TimeSpan.FromSeconds(1))).IsNotEqualTo(new DnsCNameRecord("example.net", TimeSpan.FromSeconds(1)));
	}
}
