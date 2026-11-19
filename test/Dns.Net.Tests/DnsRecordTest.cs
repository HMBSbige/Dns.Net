using Dns.Net.Abstractions;
using System.Net;

namespace Dns.Net.Tests;

public class DnsRecordTest
{
	private static readonly DnsName Example = DnsName.Parse("example.com");

	private static readonly TimeSpan Hour = TimeSpan.FromHours(1);

	[Test]
	public async Task ToStringWritesALineOfAMasterFile()
	{
		await AssertLine(new DnsResourceRecord(Example, TimeSpan.FromSeconds(300), new DnsAddressData(IPAddress.Parse("192.0.2.1"))), "example.com. 300 IN A 192.0.2.1");
		await AssertLine(new DnsResourceRecord(Example, TimeSpan.FromSeconds(300.9), new DnsAddressData(IPAddress.Parse("2001:db8::1"))), "example.com. 300 IN AAAA 2001:db8::1");
		await AssertLine(new DnsResourceRecord(DnsName.Parse("www.example.com"), Hour, new DnsCNameData(Example)), "www.example.com. 3600 IN CNAME example.com.");
		await AssertLine(new DnsResourceRecord(Example, Hour, new DnsMxData(10, DnsName.Parse("mail.example.com"))), "example.com. 3600 IN MX 10 mail.example.com.");
		await AssertLine(new DnsResourceRecord(DnsName.Root, Hour, new DnsNsData(DnsName.Parse("a.root-servers.net"))), ". 3600 IN NS a.root-servers.net.");
		await AssertLine(new DnsResourceRecord(DnsName.Parse("1.2.0.192.in-addr.arpa"), Hour, new DnsPtrData(Example)), "1.2.0.192.in-addr.arpa. 3600 IN PTR example.com.");
		await AssertLine(new DnsResourceRecord(DnsName.Parse("_sip._tcp.example.com"), Hour, new DnsSrvData(10, 60, 5060, DnsName.Root)), "_sip._tcp.example.com. 3600 IN SRV 10 60 5060 .");
		await AssertLine(new DnsResourceRecord(Example, Hour, new DnsSoaData(DnsName.Parse("ns1.example.com"), DnsName.Parse("hostmaster.example.com"), 2024010101, TimeSpan.FromHours(2), Hour, TimeSpan.FromDays(14), TimeSpan.FromMinutes(5))), "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300");
		await AssertLine(new DnsResourceRecord(Example, Hour, new DnsTxtData(["v=spf1 -all"u8.ToArray(), (byte[])[(byte)'"', (byte)'\\', 9, 255, (byte)' '], ReadOnlyMemory<byte>.Empty])), @"example.com. 3600 IN TXT ""v=spf1 -all"" ""\""\\\009\255 "" """"");
		await AssertLine(new DnsResourceRecord(Example, Hour, new DnsUnknownData(DnsRecordType.Txt, ReadOnlyMemory<byte>.Empty)), @"example.com. 3600 IN TXT \# 0");
		await AssertLine(new DnsResourceRecord(Example, Hour, new DnsUnknownData((DnsRecordType)65280, (byte[])[0xDE, 0xAD, 0xBE, 0xEF])), @"example.com. 3600 IN TYPE65280 \# 4 DEADBEEF");
		await AssertLine(new DnsResourceRecord(Example, Hour, new DnsUnknownData(DnsRecordType.Caa, ReadOnlyMemory<byte>.Empty)) { Class = DnsClass.Any }, @"example.com. 3600 ANY CAA \# 0");
		await AssertLine(new DnsResourceRecord(DnsName.Parse("version.bind"), TimeSpan.Zero, new DnsTxtData(["9"u8.ToArray()])) { Class = DnsClass.Chaos }, @"version.bind. 0 CH TXT ""9""");
		await AssertLine(new DnsResourceRecord(DnsName.Parse(@"a\.b"), TimeSpan.Zero, new DnsCNameData(Example)) { Class = (DnsClass)99 }, @"a\.b. 0 CLASS99 CNAME example.com.");
		await AssertLine(new DnsResourceRecord(DnsName.Parse(@"acct\;prod.example"), TimeSpan.Zero, new DnsAddressData(IPAddress.Parse("192.0.2.1"))), @"acct\;prod.example. 0 IN A 192.0.2.1");
	}

	[Test]
	public async Task QuestionToStringWritesNameClassAndType()
	{
		await Assert.That(new DnsQuestion(Example, DnsRecordType.Https).ToString()).IsEqualTo("example.com. IN HTTPS");
		await Assert.That(new DnsQuestion(DnsName.Root, DnsRecordType.Ns).ToString()).IsEqualTo(". IN NS");
		await Assert.That(new DnsQuestion(Example, (DnsRecordType)65280, DnsClass.Chaos).ToString()).IsEqualTo("example.com. CH TYPE65280");
	}

	[Test]
	public async Task AQuestionBuiltWithAnObjectInitializerIsOfClassIn()
	{
		DnsQuestion question = new() { Name = Example, Type = DnsRecordType.A };
		byte[] encoded = new DnsMessage { Questions = [question] }.Encode();

		// QTYPE and QCLASS end the message.
		await Assert.That(Convert.ToHexString(encoded.AsSpan(encoded.Length - 4))).IsEqualTo("00010001");
		await Assert.That(question).IsEqualTo(new DnsQuestion(Example, DnsRecordType.A));
	}

	[Test]
	public async Task TheDefaultQuestionIsOfClassZero()
	{
		await Assert.That(default(DnsQuestion).Class).IsEqualTo((DnsClass)0);
		DnsQuestion[] questions = new DnsQuestion[1];

		await Assert.That(questions[0].ToString()).IsEqualTo(". CLASS0 TYPE0");
	}

	[Test]
	public async Task OptionAndEdnsToStringShowCodesAndHex()
	{
		await Assert.That(new DnsEdnsOption(DnsEdnsOptionCode.Nsid, "ns1"u8.ToArray()).ToString()).IsEqualTo("NSID: 6E7331");
		await Assert.That(new DnsEdnsOption((DnsEdnsOptionCode)65001, ReadOnlyMemory<byte>.Empty).ToString()).IsEqualTo("OPT=65001:");
		await Assert.That(new DnsEdns().ToString()).IsEqualTo("; EDNS: version: 0, flags:; udp: 1232");
	}

	[Test]
	public async Task TtlMustBeWithin32Bits()
	{
		TimeSpan max = TimeSpan.FromSeconds(uint.MaxValue);
		TimeSpan topBit = TimeSpan.FromSeconds(2147483648L);
		DnsAddressData data = new(IPAddress.Loopback);

		await Assert.That(new DnsResourceRecord(Example, max, data).Ttl).IsEqualTo(max);
		await Assert.That(new DnsResourceRecord(Example, topBit, data).Ttl).IsEqualTo(topBit);
		await Assert.That(new DnsResourceRecord(Example, TimeSpan.Zero, data).Ttl).IsEqualTo(TimeSpan.Zero);
		await Assert.That(() => new DnsResourceRecord(Example, max + TimeSpan.FromTicks(1), data)).Throws<ArgumentOutOfRangeException>().WithParameterName("Ttl");
		await Assert.That(() => new DnsResourceRecord(Example, TimeSpan.FromTicks(-1), data)).Throws<ArgumentOutOfRangeException>().WithParameterName("Ttl");

		DnsResourceRecord record = new(Example, TimeSpan.Zero, data);
		await Assert.That((record with { Ttl = max }).Ttl).IsEqualTo(max);
		await Assert.That((record with { Ttl = topBit }).Ttl).IsEqualTo(topBit);
		await Assert.That(() => record with { Ttl = TimeSpan.FromTicks(-1) }).Throws<ArgumentOutOfRangeException>().WithParameterName("Ttl");
		await Assert.That(() => record with { Ttl = max + TimeSpan.FromTicks(1) }).Throws<ArgumentOutOfRangeException>().WithParameterName("Ttl");
	}

	[Test]
	public async Task RecordsRequireData()
	{
		DnsResourceRecord record = new(Example, TimeSpan.Zero, new DnsAddressData(IPAddress.Loopback));

		await Assert.That(() => new DnsResourceRecord(Example, TimeSpan.Zero, null!)).Throws<ArgumentNullException>().WithParameterName("Data");
		await Assert.That(() => record with { Data = null! }).Throws<ArgumentNullException>();
		await Assert.That(() => new DnsRequestContext(null!, DnsProtocol.Udp)).Throws<ArgumentNullException>().WithParameterName("Request");
	}

	[Test]
	public async Task AddressDataTakesItsTypeFromTheAddressFamily()
	{
		await Assert.That(new DnsAddressData(IPAddress.Parse("192.0.2.1")).Type).IsEqualTo(DnsRecordType.A);
		await Assert.That(new DnsAddressData(IPAddress.Parse("2001:db8::1")).Type).IsEqualTo(DnsRecordType.Aaaa);
		await Assert.That(new DnsAddressData(IPAddress.Parse("::ffff:192.0.2.1")).Type).IsEqualTo(DnsRecordType.Aaaa);
		await Assert.That(new DnsResourceRecord(Example, TimeSpan.Zero, new DnsAddressData(IPAddress.IPv6Loopback)).Type).IsEqualTo(DnsRecordType.Aaaa);
		await Assert.That(() => new DnsAddressData(null!)).Throws<ArgumentNullException>().WithParameterName("Address");
		await Assert.That(() => new DnsAddressData(IPAddress.Loopback) with { Address = null! }).Throws<ArgumentNullException>();
	}

	[Test]
	public async Task AddressDataKeepsACopyOfTheAddress()
	{
		// IPAddress is mutable.
		IPAddress address = IPAddress.Parse("fe80::1%3");
		DnsAddressData data = new(address);
		DnsMessage message = new() { Answers = [new DnsResourceRecord(Example, Hour, data)] };
		int hash = message.GetHashCode();

		address.ScopeId = 7;

		await Assert.That(data.Address.ToString()).IsEqualTo("fe80::1%3");
		await Assert.That(message.GetHashCode()).IsEqualTo(hash);

		IPAddress other = IPAddress.Parse("fe80::2%4");
		DnsAddressData changed = data with { Address = other };
		other.ScopeId = 8;

		await Assert.That(changed.Address.ToString()).IsEqualTo("fe80::2%4");
		await Assert.That(new DnsAddressData(IPAddress.Parse("192.0.2.1")).Address).IsEqualTo(IPAddress.Parse("192.0.2.1"));
	}

	[Test]
	public async Task TheLineOfAnAaaaRecordLeavesOutTheScopeOfTheAddress()
	{
		// Neither the text form (RFC 3596, Sec. 2.4) nor the wire format holds a zone index.
		DnsAddressData data = new(IPAddress.Parse("fe80::1%7"));
		DnsResourceRecord record = new(DnsName.Parse("host.example"), TimeSpan.FromSeconds(60), data);
		DnsMessage decoded = DnsMessage.Decode(new DnsMessage { Answers = [record] }.Encode());

		await Assert.That(record.ToString()).IsEqualTo("host.example. 60 IN AAAA fe80::1");
		await Assert.That(decoded.Answers[0].ToString()).IsEqualTo(record.ToString());
		await Assert.That(data.Address.ScopeId).IsEqualTo(7L);
	}

	[Test]
	public async Task TxtStringsHoldAtMost255Bytes()
	{
		await Assert.That(new DnsTxtData([new byte[255]]).Values[0].Length).IsEqualTo(255);
		await Assert.That(() => new DnsTxtData([new byte[1], new byte[256]])).Throws<ArgumentException>().WithParameterName("Values");
		await Assert.That(() => new DnsTxtData(null!)).Throws<ArgumentNullException>().WithParameterName("Values");
		await Assert.That(() => new DnsTxtData([ReadOnlyMemory<byte>.Empty]) with { Values = [new byte[256]] }).Throws<ArgumentException>();
	}

	[Test]
	public async Task TxtDataHoldsAtLeastOneString()
	{
		// RFC 1035, Sec. 3.3.14: at least one string, which may be empty.
		await Assert.That(() => new DnsTxtData([])).ThrowsExactly<ArgumentException>().WithParameterName("Values");
		await Assert.That(() => new DnsTxtData([ReadOnlyMemory<byte>.Empty]) with { Values = [] }).ThrowsExactly<ArgumentException>().WithParameterName("Values");
		await Assert.That(new DnsTxtData([ReadOnlyMemory<byte>.Empty]).Values.Count).IsEqualTo(1);
	}

	[Test]
	public async Task TxtDataCopiesTheListThatItIsGiven()
	{
		// Were the list shared, a string added later would escape the 255-byte check.
		List<ReadOnlyMemory<byte>> values = ["a"u8.ToArray()];
		DnsTxtData data = new(values);
		values.Add(new byte[256]);

		await Assert.That(data.Values.Count).IsEqualTo(1);
	}

	[Test]
	public async Task UnknownDataCannotBeOpt()
	{
		await Assert.That(() => new DnsUnknownData(DnsRecordType.Opt, ReadOnlyMemory<byte>.Empty)).Throws<ArgumentException>().WithParameterName("Type");
		await Assert.That(new DnsUnknownData(DnsRecordType.Caa, ReadOnlyMemory<byte>.Empty).Type).IsEqualTo(DnsRecordType.Caa);
	}

	[Test]
	public async Task SoaIntervalsMustBeWithin32Bits()
	{
		TimeSpan max = TimeSpan.FromSeconds(uint.MaxValue);
		TimeSpan over = max + TimeSpan.FromTicks(1);
		DnsSoaData soa = new(Example, Example, 0, max, max, max, max);

		await Assert.That(soa.Minimum).IsEqualTo(max);
		await Assert.That(() => new DnsSoaData(Example, Example, 0, over, max, max, max)).Throws<ArgumentOutOfRangeException>().WithParameterName("Refresh");
		await Assert.That(() => new DnsSoaData(Example, Example, 0, max, over, max, max)).Throws<ArgumentOutOfRangeException>().WithParameterName("Retry");
		await Assert.That(() => new DnsSoaData(Example, Example, 0, max, max, over, max)).Throws<ArgumentOutOfRangeException>().WithParameterName("Expire");
		await Assert.That(() => new DnsSoaData(Example, Example, 0, max, max, max, over)).Throws<ArgumentOutOfRangeException>().WithParameterName("Minimum");
		await Assert.That(() => new DnsSoaData(Example, Example, 0, TimeSpan.FromTicks(-1), max, max, max)).Throws<ArgumentOutOfRangeException>();
		await Assert.That(() => soa with { Minimum = TimeSpan.FromSeconds(-1) }).Throws<ArgumentOutOfRangeException>();

		// The intervals go on the wire as 32-bit seconds.
		DnsMessage message = new() { Answers = [new DnsResourceRecord(DnsName.Root, TimeSpan.Zero, soa)] };
		await Assert.That(Convert.ToHexString(message.Encode().AsSpan(message.Encode().Length - 16))).IsEqualTo("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
	}

	[Test]
	public async Task DataWithBytesComparesTheBytes()
	{
		DnsTxtData txt = new(["ab"u8.ToArray(), "c"u8.ToArray()]);
		DnsUnknownData unknown = new(DnsRecordType.Caa, (byte[])[1, 2, 3]);
		DnsEdnsOption option = new(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3]);

		await AssertEqual(txt, new DnsTxtData([new ReadOnlyMemory<byte>([0, (byte)'a', (byte)'b'], 1, 2), "c"u8.ToArray()]));
		await Assert.That(txt).IsNotEqualTo(new DnsTxtData(["a"u8.ToArray(), "bc"u8.ToArray()]));
		await Assert.That(txt).IsNotEqualTo(new DnsTxtData(["ab"u8.ToArray()]));
		await Assert.That((DnsRecordData)txt).IsNotEqualTo(new DnsUnknownData(DnsRecordType.Txt, (byte[])[2, (byte)'a', (byte)'b', 1, (byte)'c']));

		await AssertEqual(unknown, new DnsUnknownData(DnsRecordType.Caa, (byte[])[1, 2, 3]));
		await Assert.That(unknown).IsNotEqualTo(new DnsUnknownData(DnsRecordType.Caa, (byte[])[1, 2, 4]));
		await Assert.That(unknown).IsNotEqualTo(new DnsUnknownData(DnsRecordType.Tlsa, (byte[])[1, 2, 3]));

		await AssertEqual(option, new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3]));
		await Assert.That(option == new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3])).IsTrue();
		await Assert.That(option).IsNotEqualTo(new DnsEdnsOption(DnsEdnsOptionCode.Padding, (byte[])[1, 2, 3]));
		await Assert.That(option).IsNotEqualTo(new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2]));

		await AssertEqual(new DnsEdns { Options = [option] }, new DnsEdns { Options = [new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3])] });
		await Assert.That(new DnsEdns { Options = [option] }).IsNotEqualTo(new DnsEdns());
		await Assert.That(new DnsEdns()).IsNotEqualTo(new DnsEdns { DnssecOk = true });
	}

	[Test]
	public async Task RecordsCompareOwnerNamesRegardlessOfCase()
	{
		DnsAddressData data = new(IPAddress.Parse("192.0.2.1"));

		await AssertEqual(new DnsResourceRecord(Example, Hour, data), new DnsResourceRecord(DnsName.Parse("EXAMPLE.Com"), Hour, new DnsAddressData(IPAddress.Parse("192.0.2.1"))));
		await Assert.That(new DnsResourceRecord(Example, Hour, data)).IsNotEqualTo(new DnsResourceRecord(Example, Hour, data) { Class = DnsClass.Chaos });
		await AssertEqual(new DnsQuestion(Example, DnsRecordType.A), new DnsQuestion(DnsName.Parse("Example.COM"), DnsRecordType.A));
	}

	[Test]
	public async Task RecordsThatDifferOnlyInTtlAreNotEqual()
	{
		DnsResourceRecord record = new(Example, Hour, new DnsAddressData(IPAddress.Parse("192.0.2.1")));
		DnsResourceRecord longer = record with { Ttl = 2 * Hour };

		await Assert.That(longer).IsNotEqualTo(record);

		// Dynamic update compares records without their TTLs (RFC 2136, Sec. 1.1.1).
		await Assert.That(longer == record with { Ttl = longer.Ttl }).IsTrue();
	}

	[Test]
	public async Task NamesInDataCompareRegardlessOfCaseOnlyInTypedData()
	{
		DnsResourceRecord cname = new(Example, Hour, new DnsCNameData(DnsName.Parse("www.example.com")));
		DnsResourceRecord minfo = new(Example, Hour, new DnsUnknownData((DnsRecordType)14, MInfo("admin.example.com", "errors.example.com")));

		await AssertEqual(cname, cname with { Data = new DnsCNameData(DnsName.Parse("WWW.Example.com")) });

		// DnsUnknownData compares bytes exactly, not names as RFC 2136, Sec. 1.1.2, does.
		await Assert.That(minfo).IsNotEqualTo(minfo with { Data = new DnsUnknownData((DnsRecordType)14, MInfo("Admin.example.com", "errors.example.com")) });
		await AssertEqual(minfo, minfo with { Data = new DnsUnknownData((DnsRecordType)14, MInfo("admin.example.com", "errors.example.com")) });

		static byte[] MInfo(string responsible, string errors)
		{
			byte[] data = new byte[2 * DnsName.MaxEncodedLength];
			_ = DnsName.Parse(responsible).TryEncode(data, out int first);
			_ = DnsName.Parse(errors).TryEncode(data.AsSpan(first), out int second);
			return data.AsSpan(0, first + second).ToArray();
		}
	}

	private static async Task AssertLine(DnsResourceRecord record, string expected)
	{
		await Assert.That(record.ToString()).IsEqualTo(expected);
	}

	private static async Task AssertEqual<T>(T left, T right) where T : notnull
	{
		await Assert.That(left).IsEqualTo(right);
		await Assert.That(left.GetHashCode()).IsEqualTo(right.GetHashCode());
	}
}
