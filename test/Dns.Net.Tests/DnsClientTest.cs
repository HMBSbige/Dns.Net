using Dns.Net.Abstractions;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using TUnit.Assertions.Enums;

namespace Dns.Net.Tests;

public class DnsClientTest
{
	private const string Name = "www.example.com";

	[Test]
	public async Task TheConstructorKeepsTheTransport()
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());

		await Assert.That(new DnsClient(transport).Transport).IsSameReferenceAs(transport);
		await Assert.That(() => new DnsClient(null!)).Throws<ArgumentNullException>().WithParameterName("transport");
	}

	[Test]
	public async Task EachMethodSendsOneQueryOfItsType(CancellationToken cancellationToken)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());
		DnsClient client = new(transport);

		_ = await client.ResolveAddressesAsync("Example.COM.", AddressFamily.InterNetwork, cancellationToken);
		_ = await client.ResolveAddressesAsync("Example.COM.", AddressFamily.InterNetworkV6, cancellationToken);
		_ = await client.ResolveAsync<DnsSrvRecord>("Example.COM.", cancellationToken);
		_ = await client.ResolveAsync<DnsMxRecord>("Example.COM.", cancellationToken);
		_ = await client.ResolveAsync<DnsTxtRecord>("Example.COM.", cancellationToken);
		_ = await client.ResolveAsync<DnsCNameRecord>("Example.COM.", cancellationToken);
		_ = await client.ResolveAsync<DnsPtrRecord>("Example.COM.", cancellationToken);
		_ = await client.ResolveAsync<DnsNsRecord>("Example.COM.", cancellationToken);

		await Assert.That(transport.Queries.Select(static query => query.Questions[0].Type))
			.IsEquivalentTo([DnsRecordType.A, DnsRecordType.Aaaa, DnsRecordType.Srv, DnsRecordType.Mx, DnsRecordType.Txt, DnsRecordType.CName, DnsRecordType.Ptr, DnsRecordType.Ns], CollectionOrdering.Matching);
		await Assert.That(transport.Tokens).All(token => token == cancellationToken);

		foreach (DnsMessage query in transport.Queries)
		{
			await Assert.That(query.Id).IsEqualTo((ushort)0);
			await Assert.That(query.IsResponse).IsFalse();
			await Assert.That(query.Opcode).IsEqualTo(DnsOpcode.Query);
			await Assert.That(query.IsRecursionDesired).IsTrue();
			await Assert.That(query.IsCheckingDisabled).IsFalse();
			DnsQuestion question = await Assert.That(query.Questions).HasSingleItem();
			await Assert.That(question.Name.ToString()).IsEqualTo("Example.COM");
			await Assert.That(question.Class).IsEqualTo(DnsClass.Internet);
			DnsEdns edns = await Assert.That(query.Edns).IsNotNull();
			await Assert.That(edns.UdpPayloadSize).IsEqualTo((ushort)1232);
			await Assert.That(edns.DnssecOk).IsFalse();
			await Assert.That(edns.Options).IsEmpty();
			await Assert.That(query.Answers.Count + query.Authorities.Count + query.Additionals.Count).IsEqualTo(0);
		}

		// The MX query on the wire: identifier 0, RD, one question, and an OPT record for 1232 bytes.
		byte[] expected = Wire.Concat(Wire.Header(0, 0x0100, 1, 0, 0, 1), Wire.Name("Example", "COM"), Wire.U16(15), Wire.U16(1), [0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
		await Assert.That(Convert.ToHexString(transport.Queries[3].Encode())).IsEqualTo(Convert.ToHexString(expected));
	}

	[Test]
	public async Task BothFamiliesSendTheAQueryFirst(CancellationToken cancellationToken)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());

		_ = await new DnsClient(transport).ResolveAddressesAsync(Name, AddressFamily.Unspecified, cancellationToken);

		await Assert.That(transport.Queries.Select(static query => query.Questions[0])).IsEquivalentTo([new DnsQuestion(DnsName.Parse(Name), DnsRecordType.A), new DnsQuestion(DnsName.Parse(Name), DnsRecordType.Aaaa)], EqualityComparer<DnsQuestion>.Default, CollectionOrdering.Matching);
		await Assert.That(transport.Tokens).IsEquivalentTo([cancellationToken, cancellationToken]);
	}

	[Test]
	public async Task RecordsMapToTheQueryLayerTypes(CancellationToken cancellationToken)
	{
		DnsClient client = new(new ScriptedTransport(static query => query.CreateResponse() with
		{
			Answers = query.Questions[0].Type switch
			{
				DnsRecordType.A => [A(Name, "192.0.2.1", 300), A(Name, "192.0.2.2", 30)],
				DnsRecordType.Aaaa => [A(Name, "2001:db8::1", 120)],
				DnsRecordType.Mx => [Rr(Name, 3600, new DnsMxData(10, N("mail.example.com"))), Rr(Name, 60, new DnsMxData(20, N("Backup.Example.net.")))],
				DnsRecordType.Txt => [Rr(Name, 60, new DnsTxtData(["v=spf1"u8.ToArray(), "-all"u8.ToArray()]))],
				DnsRecordType.CName => [CName(Name, "example.com", 90)],
				DnsRecordType.Ptr => [Rr(Name, 45, new DnsPtrData(N("host.example.com")))],
				DnsRecordType.Ns => [Rr(Name, 172800, new DnsNsData(N("a.iana-servers.net"))), Rr(Name, 172800, new DnsNsData(N("b.iana-servers.net")))],
				DnsRecordType.Srv => [Rr(Name, 15, new DnsSrvData(1, 2, 5060, N("sip.example.com")))],
				_ => []
			}
		}));

		// Each RRset takes its least TTL (RFC 2181, Sec. 5.2); A and AAAA are separate RRsets.
		await Assert.That(await client.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.1", 30), Address("192.0.2.2", 30)));
		await Assert.That(await client.ResolveAddressesAsync(Name, AddressFamily.InterNetworkV6, cancellationToken)).IsEqualTo(Positive(Address("2001:db8::1", 120)));
		await Assert.That(await client.ResolveAddressesAsync(Name, AddressFamily.Unspecified, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.1", 30), Address("192.0.2.2", 30), Address("2001:db8::1", 120)));
		await Assert.That(await client.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsMxRecord("mail.example.com", 10, Seconds(60)), new DnsMxRecord("Backup.Example.net", 20, Seconds(60))));
		await Assert.That(await client.ResolveAsync<DnsTxtRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsTxtRecord(["v=spf1", "-all"], Seconds(60))));
		await Assert.That(await client.ResolveAsync<DnsCNameRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsCNameRecord("example.com", Seconds(90))));
		await Assert.That(await client.ResolveAsync<DnsPtrRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsPtrRecord("host.example.com", Seconds(45))));
		await Assert.That(await client.ResolveAsync<DnsNsRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsNsRecord("a.iana-servers.net", Seconds(172800)), new DnsNsRecord("b.iana-servers.net", Seconds(172800))));
		await Assert.That(await client.ResolveAsync<DnsSrvRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsSrvRecord("sip.example.com", 5060, 1, 2, Seconds(15), [])));
	}

	[Test]
	public async Task AChainOfCNamesLeadsToTheRecords(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(
			CName(Name, "a.example.net", 3600),
			CName("a.example.net", "b.example.org", 10),
			A("b.example.org", "192.0.2.7", 30),
			A("b.example.org", "192.0.2.8", 20));

		DnsQueryResult<DnsAddressRecord> result = await client.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken);

		// The records take the least TTL of their RRset, not the least along the chain.
		await Assert.That(result).IsEqualTo(Positive(Address("192.0.2.7", 20), Address("192.0.2.8", 20)));
	}

	[Test]
	public async Task RecordsOffTheChainDoNotLowerTheTtl(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(
			A("unrelated.example.com", "192.0.2.9", 1),
			CName(Name, "target.example.com", 5),
			A("example.com", "192.0.2.10", 2),
			A("target.example.com", "192.0.2.1", 300),
			A("target.example.com", "192.0.2.2", 100),
			A("target.example.com", "192.0.2.3", 3) with { Class = DnsClass.Chaos },
			A("target.example.com", "2001:db8::1", 4),
			A("sub.target.example.com", "192.0.2.11", 1));

		await Assert.That(await client.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.1", 100), Address("192.0.2.2", 100)));
	}

	[Test]
	public async Task RecordsOfTheTypeTakePrecedenceOverACName(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(CName(Name, "other.example.com"), A("other.example.com", "192.0.2.2"), A(Name, "192.0.2.1"));

		await Assert.That(await client.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.1", 60)));
	}

	[Test]
	public async Task OnlyTheFirstCNameOfANameIsFollowed(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(CName(Name, "first.example.com"), CName(Name, "second.example.com"), A("second.example.com", "192.0.2.2"), A("first.example.com", "192.0.2.1"));

		await Assert.That(await client.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.1", 60)));
	}

	[Test]
	public async Task NamesCompareRegardlessOfCase(CancellationToken cancellationToken)
	{
		// Without the wire format, whose compression would change the case of the owners.
		DnsClient client = new(new ScriptedTransport(static query => query.CreateResponse() with
		{
			Answers = [CName("WWW.Example.COM", "Target.Example.com"), A("tArGeT.eXaMpLe.CoM", "192.0.2.1")]
		}, roundTrip: false));

		await Assert.That(await client.ResolveAddressesAsync("www.example.com", AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.1", 60)));
	}

	[Test]
	public async Task RecordsOfOtherClassesDoNotCount(CancellationToken cancellationToken)
	{
		DnsClient chaosAnswer = Answering(A(Name, "192.0.2.1") with { Class = DnsClass.Chaos }, A(Name, "192.0.2.2"));
		DnsClient chaosAlias = Answering(CName(Name, "target.example.com") with { Class = DnsClass.Chaos }, A("target.example.com", "192.0.2.3"));

		await Assert.That(await chaosAnswer.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.2", 60)));
		await Assert.That(await chaosAlias.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Empty<DnsAddressRecord>(DnsResponseCode.NoError));
	}

	[Test]
	public async Task ABrokenChainIsNoData(CancellationToken cancellationToken)
	{
		DnsClient client = Answering([CName(Name, "a.example.net"), CName("a.example.net", "b.example.org"), Rr("b.example.org", 60, new DnsTxtData(["v=spf1 -all"u8.ToArray()]))], [Soa("example.org", 3600, 300)]);

		await Assert.That(await client.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Empty<DnsAddressRecord>(DnsResponseCode.NoError, 300));
	}

	[Test]
	[Arguments(16, true)]
	[Arguments(17, false)]
	public async Task AChainMayHaveSixteenCNames(int length, bool resolves, CancellationToken cancellationToken)
	{
		List<DnsResourceRecord> answers = [];

		for (int i = 0; i < length; ++i)
		{
			answers.Add(CName(i is 0 ? Name : $"c{i}.example.com", $"c{i + 1}.example.com"));
		}

		answers.Add(A($"c{length}.example.com", "192.0.2.1"));

		// Shuffled, as order does not matter in a chain.
		answers.Reverse();
		DnsClient client = Answering([.. answers], [Soa("example.com", 60, 60)]);

		DnsQueryResult<DnsAddressRecord> result = await client.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken);

		// A failure gets no negative-cache TTL from the SOA record.
		await Assert.That(result).IsEqualTo(resolves ? Positive(Address("192.0.2.1", 60)) : Empty<DnsAddressRecord>(DnsResponseCode.ServerFailure));
	}

	[Test]
	public async Task ALoopIsAServerFailure(CancellationToken cancellationToken)
	{
		DnsClient loop = Answering(CName(Name, "a.example.com"), CName("a.example.com", "b.example.com"), CName("b.example.com", "A.example.com"));
		DnsClient self = Answering(CName(Name, Name));
		DnsClient loopWithSoa = Answering([CName(Name, "a.example.com"), CName("a.example.com", Name)], [Soa("example.com", 3600, 3600)]);

		await Assert.That(await loop.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Empty<DnsAddressRecord>(DnsResponseCode.ServerFailure));
		await Assert.That(await self.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsMxRecord>(DnsResponseCode.ServerFailure));
		await Assert.That(await loopWithSoa.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsMxRecord>(DnsResponseCode.ServerFailure));
	}

	[Test]
	[Arguments(3600, 300, 300)]
	[Arguments(60, 300, 60)]
	[Arguments(0, 300, 0)]
	public async Task TheNegativeCacheTtlIsTheLesserOfTheSoaTtlAndMinimum(int ttl, int minimum, int expected, CancellationToken cancellationToken)
	{
		DnsClient client = Answering([], [Rr("example.com", 60, new DnsNsData(N("ns.example.com"))), Soa("example.com", ttl, minimum), Soa("example.com", 1, 1)]);

		await Assert.That(await client.ResolveAsync<DnsTxtRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsTxtRecord>(DnsResponseCode.NoError, expected));
	}

	[Test]
	public async Task TheNegativeCacheTtlComesFromTheFirstSoaOfClassIn(CancellationToken cancellationToken)
	{
		DnsClient chaosFirst = Answering([], [Soa("example.com", 10, 10) with { Class = DnsClass.Chaos }, Soa("example.com", 20, 20)]);
		DnsClient soaInAnswers = Answering([Soa(Name, 30, 30)], []);

		await Assert.That(await chaosFirst.ResolveAsync<DnsTxtRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsTxtRecord>(DnsResponseCode.NoError, 20));
		await Assert.That(await soaInAnswers.ResolveAsync<DnsTxtRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsTxtRecord>(DnsResponseCode.NoError));
	}

	[Test]
	public async Task AReferralIsNoDataWithoutANegativeCacheTtl(CancellationToken cancellationToken)
	{
		// A referral: NS records and no SOA record in the authority section (RFC 2308, Sec. 2.2).
		ScriptedTransport transport = new(static query => query.CreateResponse() with
		{
			Authorities = [Rr("example.com", 172800, new DnsNsData(N("ns1.example.com")))],
			Additionals = [A("ns1.example.com", "192.0.2.53", 172800)]
		});

		DnsQueryResult<DnsAddressRecord> result = await new DnsClient(transport).ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken);

		await Assert.That(result).IsEqualTo(Empty<DnsAddressRecord>(DnsResponseCode.NoError));
		await Assert.That(transport.Queries).HasSingleItem();
	}

	[Test]
	[Arguments(DnsResponseCode.NxDomain, 120)]
	[Arguments(DnsResponseCode.ServerFailure, 0)]
	[Arguments(DnsResponseCode.Refused, 0)]
	[Arguments((DnsResponseCode)16, 0)]
	public async Task ErrorsComeBackWithoutRecordsAndOnlyNxDomainTakesTheSoaTtl(DnsResponseCode responseCode, int negativeCacheTtl, CancellationToken cancellationToken)
	{
		DnsClient client = new(new ScriptedTransport(query => query.CreateResponse() with
		{
			ResponseCode = responseCode,
			Answers = [CName(Name, "gone.example.net"), Rr(Name, 60, new DnsMxData(10, N("mail.example.com")))],
			Authorities = [Soa("example.com", 600, 120)]
		}));

		await Assert.That(await client.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsMxRecord>(responseCode, negativeCacheTtl));
	}

	[Test]
	public async Task RecordsLeaveTheNegativeCacheTtlZero(CancellationToken cancellationToken)
	{
		DnsClient client = Answering([Rr(Name, 60, new DnsMxData(10, N("mail.example.com")))], [Soa("example.com", 600, 120)]);

		await Assert.That(await client.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsMxRecord("mail.example.com", 10, Seconds(60))));
	}

	[Test]
	public async Task SrvTargetsTakeTheirAddressesFromTheAdditionalSection(CancellationToken cancellationToken)
	{
		const string service = "_sip._udp.example.com";

		// Without the wire format, so that the owners keep their case.
		DnsClient client = new(new ScriptedTransport(static query => query.CreateResponse() with
		{
			Answers =
			[
				Rr(service, 300, new DnsSrvData(10, 60, 5060, N("sip.example.com"))),
				Rr(service, 300, new DnsSrvData(20, 0, 5060, N("backup.example.com"))),
				Rr(service, 300, new DnsSrvData(30, 0, 5060, DnsName.Root)),
				Rr(service, 300, new DnsSrvData(40, 0, 5061, N("SIP.example.COM")))
			],
			Additionals =
			[
				A("sip.example.com", "192.0.2.1", 10),
				A("other.example.com", "192.0.2.2"),
				A("SIP.EXAMPLE.COM", "2001:db8::1", 20),
				A("sip.example.com", "192.0.2.3") with { Class = DnsClass.Chaos },
				Rr("sip.example.com", 60, new DnsTxtData(["v=spf1 -all"u8.ToArray()])),
				A(".", "192.0.2.4"),
				A("www.sip.example.com", "192.0.2.5")
			]
		}, roundTrip: false));

		DnsAddressRecord[] sip = [Address("192.0.2.1", 10), Address("2001:db8::1", 20)];

		DnsQueryResult<DnsSrvRecord> result = await client.ResolveAsync<DnsSrvRecord>(service, cancellationToken);

		await Assert.That(result).IsEqualTo(Positive(
			new DnsSrvRecord("sip.example.com", 5060, 10, 60, Seconds(300), sip),
			new DnsSrvRecord("backup.example.com", 5060, 20, 0, Seconds(300), []),
			new DnsSrvRecord(".", 5060, 30, 0, Seconds(300), []),
			new DnsSrvRecord("SIP.example.COM", 5061, 40, 0, Seconds(300), sip)));

		// Records with the same target share one list.
		await Assert.That(result.Records[3].Addresses).IsSameReferenceAs(result.Records[0].Addresses);
	}

	[Test]
	public async Task SrvRecordsAndTheAddressesOfEachTargetAndFamilyTakeTheirLeastTtl(CancellationToken cancellationToken)
	{
		const string service = "_sip._udp.example.com";
		DnsClient client = new(new ScriptedTransport(static query => query.CreateResponse() with
		{
			Answers = [Rr(service, 300, new DnsSrvData(10, 0, 5060, N("sip.example.com"))), Rr(service, 100, new DnsSrvData(20, 0, 5060, N("backup.example.com")))],
			Additionals =
			[
				A("sip.example.com", "192.0.2.1", 20),
				A("sip.example.com", "2001:db8::1", 30),
				A("sip.example.com", "192.0.2.2", 10),
				A("backup.example.com", "192.0.2.3", 5)
			]
		}));

		await Assert.That(await client.ResolveAsync<DnsSrvRecord>(service, cancellationToken)).IsEqualTo(Positive(
			new DnsSrvRecord("sip.example.com", 5060, 10, 0, Seconds(100), [Address("192.0.2.1", 10), Address("2001:db8::1", 30), Address("192.0.2.2", 10)]),
			new DnsSrvRecord("backup.example.com", 5060, 20, 0, Seconds(100), [Address("192.0.2.3", 5)])));
	}

	[Test]
	public async Task CallersThatChangeAReturnedAddressChangeNothingElse(CancellationToken cancellationToken)
	{
		// The transport returns one response to every query, as a cache would; IPAddress is mutable.
		DnsMessage aaaa = DnsMessage.CreateQuery(new DnsQuestion(N(Name), DnsRecordType.Aaaa)).CreateResponse() with { Answers = [A(Name, "fe80::5")] };
		DnsMessage srv = DnsMessage.CreateQuery(new DnsQuestion(N(Name), DnsRecordType.Srv)).CreateResponse() with
		{
			Answers = [Rr(Name, 60, new DnsSrvData(1, 1, 5060, N("sip.example.com")))],
			Additionals = [A("sip.example.com", "fe80::6")]
		};
		DnsClient client = new(new ScriptedTransport(query => query.Questions[0].Type is DnsRecordType.Srv ? srv : aaaa, roundTrip: false));
		int aaaaHash = aaaa.GetHashCode();
		int srvHash = srv.GetHashCode();

		DnsQueryResult<DnsAddressRecord> first = await client.ResolveAddressesAsync(Name, AddressFamily.InterNetworkV6, cancellationToken);
		first.Records[0].Address.ScopeId = 7;
		DnsQueryResult<DnsSrvRecord> firstSrv = await client.ResolveAsync<DnsSrvRecord>(Name, cancellationToken);
		firstSrv.Records[0].Addresses[0].Address.ScopeId = 9;

		DnsQueryResult<DnsAddressRecord> second = await client.ResolveAddressesAsync(Name, AddressFamily.InterNetworkV6, cancellationToken);
		DnsQueryResult<DnsSrvRecord> secondSrv = await client.ResolveAsync<DnsSrvRecord>(Name, cancellationToken);

		await Assert.That(second.Records[0].Address.ToString()).IsEqualTo("fe80::5");
		await Assert.That(secondSrv.Records[0].Addresses[0].Address.ToString()).IsEqualTo("fe80::6");
		await Assert.That(aaaa.GetHashCode()).IsEqualTo(aaaaHash);
		await Assert.That(srv.GetHashCode()).IsEqualTo(srvHash);
	}

	[Test]
	public async Task NoDataForSrvLeavesTheAdditionalSectionUnread()
	{
		// NODATA with many additional addresses that no SRV record refers to.
		const string service = "_sip._udp.example.com";
		DnsMessage bare = DnsMessage.CreateQuery(new DnsQuestion(N(service), DnsRecordType.Srv)).CreateResponse() with { Authorities = [Soa("example.com", 600, 120)] };
		DnsMessage withAdditionals = bare with { Additionals = [.. Enumerable.Range(1, 16).Select(static i => A($"ns{i}.example.com", $"192.0.2.{i}"))] };
		DnsClient bareClient = new(new FixedTransport(bare));
		DnsClient additionalsClient = new(new FixedTransport(withAdditionals));

		// The transport completes at once, so each call runs to its end on this thread.
		DnsQueryResult<DnsSrvRecord> bareResult = ResolveAtOnce(bareClient, service);
		DnsQueryResult<DnsSrvRecord> additionalsResult = ResolveAtOnce(additionalsClient, service);
		long bareBytes = BytesPerCall(bareClient, service);
		long additionalsBytes = BytesPerCall(additionalsClient, service);

		await Assert.That(bareResult).IsEqualTo(Empty<DnsSrvRecord>(DnsResponseCode.NoError, 120));
		await Assert.That(additionalsResult).IsEqualTo(bareResult);
		await Assert.That(additionalsBytes - bareBytes).IsLessThan(512);

		static DnsQueryResult<DnsSrvRecord> ResolveAtOnce(DnsClient client, string name)
		{
			ValueTask<DnsQueryResult<DnsSrvRecord>> task = client.ResolveAsync<DnsSrvRecord>(name);
			return task.IsCompletedSuccessfully ? task.Result : throw new InvalidOperationException("The call did not complete at once.");
		}

		static long BytesPerCall(DnsClient client, string name)
		{
			const int calls = 100;
			long before = GC.GetAllocatedBytesForCurrentThread();

			for (int i = 0; i < calls; ++i)
			{
				_ = ResolveAtOnce(client, name);
			}

			return (GC.GetAllocatedBytesForCurrentThread() - before) / calls;
		}
	}

	[Test]
	public async Task TxtStringsDecodeAsUtf8(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(
			Rr(Name, 60, new DnsTxtData([new byte[] { 0x61, 0xFF, 0x62 }, new byte[] { 0xC3, 0xA9 }, new byte[] { 0xE4, 0xBD }, Array.Empty<byte>()])),
			Rr(Name, 30, new DnsUnknownData(DnsRecordType.Txt, ReadOnlyMemory<byte>.Empty)),
			Rr(Name, 20, new DnsTxtData(["v=spf1 -all"u8.ToArray()])));

		await Assert.That(await client.ResolveAsync<DnsTxtRecord>(Name, cancellationToken)).IsEqualTo(Positive(
			new DnsTxtRecord(["a\uFFFDb", "\u00E9", "\uFFFD", ""], Seconds(20)),
			new DnsTxtRecord(["v=spf1 -all"], Seconds(20))));
	}

	[Test]
	public async Task TxtRecordsWithoutStringsLeaveNoData(CancellationToken cancellationToken)
	{
		DnsClient client = Answering([Rr(Name, 30, new DnsUnknownData(DnsRecordType.Txt, ReadOnlyMemory<byte>.Empty))], [Soa("example.com", 100, 50)]);

		await Assert.That(await client.ResolveAsync<DnsTxtRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsTxtRecord>(DnsResponseCode.NoError, 50));
	}

	[Test]
	public async Task RecordsWhoseDataDoesNotMatchTheirTypeDoNotCount(CancellationToken cancellationToken)
	{
		// Only a message built in code can hold such a record; decoding would read it as DnsAddressData.
		DnsClient client = new(new ScriptedTransport(static query => query.CreateResponse() with
		{
			Answers = [Rr(Name, 60, new DnsUnknownData(DnsRecordType.A, new byte[] { 192, 0, 2, 1 })), A(Name, "192.0.2.2")]
		}, roundTrip: false));

		await Assert.That(await client.ResolveAddressesAsync(Name, AddressFamily.InterNetwork, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.2", 60)));
	}

	[Test]
	public async Task ACNameQueryReturnsTheCNamesOfTheNameWithoutFollowingThem(CancellationToken cancellationToken)
	{
		DnsClient alias = Answering(CName("a.example.com", "c.example.com"), CName(Name, "a.example.com", 300), CName("a.example.com", "b.example.com"));
		DnsClient noAlias = Answering([CName("a.example.com", "b.example.com")], [Soa("example.com", 70, 80)]);

		await Assert.That(await alias.ResolveAsync<DnsCNameRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsCNameRecord("a.example.com", Seconds(300))));
		await Assert.That(await noAlias.ResolveAsync<DnsCNameRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsCNameRecord>(DnsResponseCode.NoError, 70));
	}

	[Test]
	public async Task PtrRecordsFollowClasslessDelegation(CancellationToken cancellationToken)
	{
		// RFC 2317, Sec. 4.
		DnsClient client = Answering(CName("1.2.0.192.in-addr.arpa", "1.0/25.2.0.192.in-addr.arpa"), Rr("1.0/25.2.0.192.in-addr.arpa", 300, new DnsPtrData(N("host.example.com"))));

		await Assert.That(await client.ResolveAsync<DnsPtrRecord>("1.2.0.192.in-addr.arpa", cancellationToken)).IsEqualTo(Positive(new DnsPtrRecord("host.example.com", Seconds(300))));
	}

	[Test]
	public async Task ARecordTypeOfTheCallerBuildsTheAnswer(CancellationToken cancellationToken)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse() with
		{
			Answers = [Rr(Name, 300, HinfoRecord.Data("x86-64", "Linux")), Rr(Name, 30, HinfoRecord.Malformed), Rr(Name, 120, HinfoRecord.Data("ARM", "BSD"))]
		});

		DnsQueryResult<HinfoRecord> result = await new DnsClient(transport).ResolveAsync<HinfoRecord>(Name, cancellationToken);

		// The least TTL covers the whole RRset, the skipped record included.
		await Assert.That(transport.Queries.Single().Questions[0].Type).IsEqualTo(DnsRecordType.HInfo);
		await Assert.That(result).IsEqualTo(Positive(new HinfoRecord("x86-64", "Linux", Seconds(30)), new HinfoRecord("ARM", "BSD", Seconds(30))));
	}

	[Test]
	public async Task ARecordTypeThatBuildsNullFails(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(Rr(Name, 60, new DnsMxData(10, N("mail.example.com"))));

		ValueTask<DnsQueryResult<NullRecord>> task = client.ResolveAsync<NullRecord>(Name, cancellationToken);

		await Assert.That(async () => await task).ThrowsExactly<InvalidOperationException>();
	}

	[Test]
	public async Task TheQueryAsksForTheTypeThatPassedTheCheck(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(Rr(Name, 60, new DnsMxData(10, N("mail.example.com"))));
		ScriptedTransport transport = (ScriptedTransport)client.Transport;

		// Only this test uses the type.
		FlippingRecord.Reads = 0;
		DnsQueryResult<FlippingRecord> result = await client.ResolveAsync<FlippingRecord>(Name, cancellationToken);

		await Assert.That(transport.Queries.Single().Questions[0].Type).IsEqualTo(DnsRecordType.Mx);
		await Assert.That(result.Records).HasSingleItem();
	}

	[Test]
	[Arguments("example.com")]
	[Arguments("service.onion")]
	public async Task QTypesAndMetaTypesThrowAtOnce(string name)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());
		DnsClient client = new(transport);

		await Assert.That(() => { _ = client.ResolveAsync<AnyRecord>(name); }).ThrowsExactly<NotSupportedException>();
		await Assert.That(() => { _ = client.ResolveAsync<OptRecord>(name); }).ThrowsExactly<NotSupportedException>();
		await Assert.That(() => { _ = client.ResolveAsync<Type128Record>(name); }).ThrowsExactly<NotSupportedException>();
		await Assert.That(transport.Queries).IsEmpty();
	}

	[Test]
	public async Task TheDataTypesNextToTheQTypesAndMetaTypesAreQueried(CancellationToken cancellationToken)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());
		DnsClient client = new(transport);

		await client.ResolveAsync<Type127Record>(Name, cancellationToken);
		await client.ResolveAsync<Type256Record>(Name, cancellationToken);

		await Assert.That(transport.Queries.Select(static query => query.Questions[0].Type)).IsEquivalentTo([(DnsRecordType)127, (DnsRecordType)256], CollectionOrdering.Matching);
	}

	[Test]
	public async Task TheNameIsCheckedBeforeTheType()
	{
		DnsClient client = new(new ScriptedTransport(static query => query.CreateResponse()));

		await Assert.That(() => { _ = client.ResolveAsync<AnyRecord>("a..b"); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAsync<AnyRecord>(null!); }).ThrowsExactly<ArgumentNullException>().WithParameterName("name");
	}

	[Test]
	public async Task ARecordTypeOfTheCallerFollowsTheCNameChain(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(CName(Name, "a.example.net", 3600), CName("a.example.net", "b.example.org", 30), Rr("b.example.org", 90, HinfoRecord.Data("x86-64", "Linux")));

		await Assert.That(await client.ResolveAsync<HinfoRecord>(Name, cancellationToken)).IsEqualTo(Positive(new HinfoRecord("x86-64", "Linux", Seconds(90))));
	}

	[Test]
	public async Task ARecordThatTheTypeOfTheCallerSkipsDoesNotStopTheCNameChain(CancellationToken cancellationToken)
	{
		DnsClient client = Answering(Rr(Name, 30, HinfoRecord.Malformed), CName(Name, "a.example.net"), Rr("a.example.net", 60, HinfoRecord.Data("x86-64", "Linux")));

		await Assert.That(await client.ResolveAsync<HinfoRecord>(Name, cancellationToken)).IsEqualTo(Positive(new HinfoRecord("x86-64", "Linux", Seconds(60))));
	}

	[Test]
	public async Task ARecordTypeOfTheCallerWithoutAnAnswerIsNoData(CancellationToken cancellationToken)
	{
		DnsClient otherType = Answering([CName(Name, "a.example.net"), Rr("a.example.net", 60, new DnsTxtData(["x"u8.ToArray()]))], [Soa("example.net", 600, 120)]);
		DnsClient skipped = Answering([CName(Name, "a.example.net"), Rr("a.example.net", 60, HinfoRecord.Malformed)], [Soa("example.net", 600, 120)]);

		await Assert.That(await otherType.ResolveAsync<HinfoRecord>(Name, cancellationToken)).IsEqualTo(Empty<HinfoRecord>(DnsResponseCode.NoError, 120));
		await Assert.That(await skipped.ResolveAsync<HinfoRecord>(Name, cancellationToken)).IsEqualTo(Empty<HinfoRecord>(DnsResponseCode.NoError, 120));
	}

	[Test]
	public async Task EachOwnerOfALoopGoesToTheRecordTypeOnce()
	{
		// Each owner in the loop has a record that the type skips, so the client keeps going round.
		DnsClient client = new(new ScriptedTransport(static query => query.CreateResponse() with
		{
			Answers = [Rr(Name, 60, HinfoRecord.Malformed), CName(Name, "a.example.net"), Rr("a.example.net", 60, HinfoRecord.Malformed), CName("a.example.net", Name)]
		}));

		// The transport completes at once, so only this thread uses the type.
		CountingRecord.Owners.Clear();
		ValueTask<DnsQueryResult<CountingRecord>> task = client.ResolveAsync<CountingRecord>(Name);

		await Assert.That(task.IsCompletedSuccessfully).IsTrue();
		await Assert.That(task.Result).IsEqualTo(Empty<CountingRecord>(DnsResponseCode.ServerFailure));
		await Assert.That(CountingRecord.Owners).IsEquivalentTo([N(Name), N("a.example.net")], CollectionOrdering.Matching);
	}

	[Test]
	[Arguments("例子.com", "xn--fsqu00a.com")]
	[Arguments("例子.测试.", "xn--fsqu00a.xn--0zwm56d")]
	[Arguments("Bücher.example", "xn--bcher-kva.example")]
	[Arguments("xn--bcher-kva.example", "xn--bcher-kva.example")]
	[Arguments("_sip._tcp.example.com", "_sip._tcp.example.com")]
	[Arguments(@"a\.b.example", @"a\.b.example")]
	[Arguments(".", ".")]
	public async Task NamesBecomeAsciiBeforeTheQuery(string name, string expected, CancellationToken cancellationToken)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());

		_ = await new DnsClient(transport).ResolveAsync<DnsNsRecord>(name, cancellationToken);

		DnsMessage query = await Assert.That(transport.Queries).HasSingleItem();
		await Assert.That(query.Questions[0].Name.ToString()).IsEqualTo(expected);
	}

	[Test]
	[Arguments("_sip.例子.com")]
	[Arguments("例子..com")]
	[Arguments("a b.例子")]
	[Arguments("a..b")]
	[Arguments("exa mple.com")]
	[Arguments(@"bad\")]
	[Arguments("..")]
	public async Task InvalidNamesThrowAtOnce(string name)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());
		DnsClient client = new(transport);

		await Assert.That(() => { _ = client.ResolveAsync<DnsMxRecord>(name); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAddressesAsync(name, AddressFamily.Unspecified); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(transport.Queries).IsEmpty();
	}

	[Test]
	public async Task ArgumentsAreCheckedAtOnce()
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());
		DnsClient client = new(transport);

		await Assert.That(() => { _ = client.ResolveAddressesAsync(null!, AddressFamily.Unix); }).ThrowsExactly<ArgumentNullException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAddressesAsync("", AddressFamily.InterNetwork); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAddressesAsync("", AddressFamily.Unix); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAddressesAsync("a..b", AddressFamily.Unix); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("addressFamily");
		await Assert.That(() => { _ = client.ResolveAddressesAsync(Name, (AddressFamily)12345); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("addressFamily");

		await Assert.That(() => { _ = client.ResolveAsync<DnsMxRecord>(null!); }).ThrowsExactly<ArgumentNullException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAsync<DnsMxRecord>(""); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(transport.Queries).IsEmpty();
	}

	[Test]
	[Arguments("service.onion")]
	[Arguments("SERVICE.ONION.")]
	[Arguments("onion")]
	[Arguments(@"service.\111nion")]
	[Arguments("service\u3002onion")]
	public async Task NamesInOnionGetNxDomainWithoutAQuery(string name, CancellationToken cancellationToken)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());
		DnsClient client = new(transport);

		await Assert.That(client.QueriesOnionNames).IsFalse();

		foreach (AddressFamily family in (AddressFamily[])[AddressFamily.Unspecified, AddressFamily.InterNetwork, AddressFamily.InterNetworkV6])
		{
			await AssertNxDomainAtOnce(client.ResolveAddressesAsync(name, family, cancellationToken));
		}

		await AssertNxDomainAtOnce(client.ResolveAsync<DnsMxRecord>(name, cancellationToken));
		await Assert.That(transport.Queries).IsEmpty();
	}

	[Test]
	public async Task NamesInOnionGetACanceledTaskForACanceledToken()
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());
		DnsClient client = new(transport);
		CancellationToken canceled = new(true);

		foreach (AddressFamily family in (AddressFamily[])[AddressFamily.Unspecified, AddressFamily.InterNetwork, AddressFamily.InterNetworkV6])
		{
			await AssertCanceledAtOnce(client.ResolveAddressesAsync("service.onion", family, canceled));
		}

		await AssertCanceledAtOnce(client.ResolveAsync<DnsMxRecord>("service.onion", canceled));
		await Assert.That(transport.Queries).IsEmpty();
	}

	[Test]
	[Arguments("onion.example")]
	[Arguments("xonion")]
	public async Task NamesOutsideOnionAreQueried(string name, CancellationToken cancellationToken)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());

		await CallEachMethodAsync(new DnsClient(transport), name, cancellationToken);

		// Unspecified sends two queries.
		await Assert.That(transport.Queries.Count).IsEqualTo(5);
	}

	[Test]
	public async Task AClientThatQueriesOnionNamesSendsTheirQueries(CancellationToken cancellationToken)
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());

		await CallEachMethodAsync(new DnsClient(transport) { QueriesOnionNames = true }, "service.onion", cancellationToken);

		await Assert.That(transport.Queries.Count).IsEqualTo(5);
		await Assert.That(transport.Queries).All(static query => query.Questions[0].Name == DnsName.Parse("service.onion"));
	}

	[Test]
	public async Task ArgumentsOfOnionNamesAreCheckedToo()
	{
		ScriptedTransport transport = new(static query => query.CreateResponse());
		DnsClient client = new(transport);

		await Assert.That(() => { _ = client.ResolveAddressesAsync("service.onion", AddressFamily.Unix); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("addressFamily");
		await Assert.That(() => { _ = client.ResolveAddressesAsync("exa mple.onion", AddressFamily.InterNetwork); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAsync<DnsMxRecord>("exa mple.onion"); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(transport.Queries).IsEmpty();
	}

	[Test]
	[Arguments("xn--fsqu00a.com", "例子.com")]
	[Arguments("XN--FSQU00A.example", "例子.example")]
	[Arguments("Mail.xn--bcher-kva.example", "mail.bücher.example")]
	[Arguments("xn--zz.example", "xn--zz.example")]
	[Arguments("xn--bcher-kva._tcp.example", "xn--bcher-kva._tcp.example")]
	[Arguments(@"a\.xn--bcher-kva.example", @"a\.xn--bcher-kva.example")]
	[Arguments("axn--bcher-kva.example", "axn--bcher-kva.example")]
	[Arguments("Mail.Example.COM", "Mail.Example.COM")]
	[Arguments(".", ".")]
	public async Task NamesInAsciiCompatibleEncodingComeBackInUnicode(DnsName exchange, string expected, CancellationToken cancellationToken)
	{
		// Without the wire format, whose compression may change the case of a shared suffix.
		DnsClient client = new(new ScriptedTransport(query => query.CreateResponse() with { Answers = [Rr(Name, 60, new DnsMxData(10, exchange))] }, roundTrip: false));

		await Assert.That(await client.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).IsEqualTo(Positive(new DnsMxRecord(expected, 10, Seconds(60))));
	}

	[Test]
	[Arguments(DnsResponseCode.NoError, 0, DnsResponseCode.NoError, 0, true, true, DnsResponseCode.NoError, 0)]
	[Arguments(DnsResponseCode.NoError, 0, DnsResponseCode.NoError, 0, false, true, DnsResponseCode.NoError, 0)]
	[Arguments(DnsResponseCode.NoError, 0, DnsResponseCode.NxDomain, 0, true, false, DnsResponseCode.NoError, 0)]
	[Arguments(DnsResponseCode.ServerFailure, 0, DnsResponseCode.NoError, 0, false, true, DnsResponseCode.NoError, 0)]
	[Arguments(DnsResponseCode.NoError, 300, DnsResponseCode.NoError, 100, false, false, DnsResponseCode.NoError, 100)]
	[Arguments(DnsResponseCode.NoError, 0, DnsResponseCode.NoError, 100, false, false, DnsResponseCode.NoError, 100)]
	[Arguments(DnsResponseCode.NoError, 50, DnsResponseCode.NoError, 0, false, false, DnsResponseCode.NoError, 50)]
	[Arguments(DnsResponseCode.NoError, 0, DnsResponseCode.NoError, 0, false, false, DnsResponseCode.NoError, 0)]
	[Arguments(DnsResponseCode.NxDomain, 30, DnsResponseCode.NoError, 0, false, false, DnsResponseCode.NxDomain, 30)]
	[Arguments(DnsResponseCode.NoError, 0, DnsResponseCode.NxDomain, 40, false, false, DnsResponseCode.NxDomain, 40)]
	[Arguments(DnsResponseCode.ServerFailure, 0, DnsResponseCode.NxDomain, 0, false, false, DnsResponseCode.NxDomain, 0)]
	[Arguments(DnsResponseCode.ServerFailure, 0, DnsResponseCode.Refused, 0, false, false, DnsResponseCode.ServerFailure, 0)]
	[Arguments(DnsResponseCode.NoError, 0, DnsResponseCode.Refused, 0, false, false, DnsResponseCode.Refused, 0)]
	[Arguments(DnsResponseCode.Refused, 70, DnsResponseCode.NoError, 60, false, false, DnsResponseCode.Refused, 0)]
	public async Task BothFamiliesMergeAsTheResolverOfDotNetDoes(DnsResponseCode aCode, int aSoaTtl, DnsResponseCode aaaaCode, int aaaaSoaTtl, bool aRecords, bool aaaaRecords, DnsResponseCode expectedCode, int expectedTtl, CancellationToken cancellationToken)
	{
		DnsClient client = new(new ScriptedTransport(query =>
		{
			bool isA = query.Questions[0].Type is DnsRecordType.A;
			DnsResponseCode code = isA ? aCode : aaaaCode;
			int soaTtl = isA ? aSoaTtl : aaaaSoaTtl;
			bool records = isA ? aRecords : aaaaRecords;

			return query.CreateResponse() with
			{
				ResponseCode = code,
				Answers = records ? [A(Name, isA ? "192.0.2.1" : "2001:db8::1", 5)] : [],
				Authorities = soaTtl is 0 ? [] : [Soa("example.com", soaTtl, soaTtl)]
			};
		}));

		DnsQueryResult<DnsAddressRecord> result = await client.ResolveAddressesAsync(Name, AddressFamily.Unspecified, cancellationToken);

		List<DnsAddressRecord> expectedRecords = [];

		if (aRecords && aCode is DnsResponseCode.NoError)
		{
			expectedRecords.Add(Address("192.0.2.1", 5));
		}

		if (aaaaRecords && aaaaCode is DnsResponseCode.NoError)
		{
			expectedRecords.Add(Address("2001:db8::1", 5));
		}

		await Assert.That(result).IsEqualTo(new DnsQueryResult<DnsAddressRecord>(expectedCode, expectedRecords, Seconds(expectedTtl)));
	}

	[Test]
	[Arguments(DnsRecordType.A)]
	[Arguments(DnsRecordType.Aaaa)]
	public async Task EitherQueryFailingFailsTheWhole(DnsRecordType failing, CancellationToken cancellationToken)
	{
		IOException failure = new("The transport failed.");
		DnsClient client = new(new AsyncTransport(async (query, _) =>
		{
			await Task.Yield();
			return query.Questions[0].Type == failing ? throw failure : query.CreateResponse() with { Answers = [A(Name, failing is DnsRecordType.A ? "2001:db8::1" : "192.0.2.1")] };
		}));

		IOException? thrown = await Assert.That(async () => await client.ResolveAddressesAsync(Name, AddressFamily.Unspecified, cancellationToken)).ThrowsExactly<IOException>();

		await Assert.That(thrown).IsSameReferenceAs(failure);
	}

	[Test]
	public async Task ExceptionsOfTheTransportComeThroughAsTheyAre(CancellationToken cancellationToken)
	{
		TimeoutException failure = new("No server answered.");
		DnsClient client = new(new AsyncTransport((_, _) => throw failure));

		TimeoutException? thrown = await Assert.That(async () => await client.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).ThrowsExactly<TimeoutException>();

		await Assert.That(thrown).IsSameReferenceAs(failure);
	}

	[Test]
	public async Task CancellationReachesTheTransport()
	{
		using CancellationTokenSource source = new();
		TaskCompletionSource sent = new(TaskCreationOptions.RunContinuationsAsynchronously);

		DnsClient client = new(new AsyncTransport(async (query, token) =>
		{
			sent.TrySetResult();
			// Bounded, so that a token that does not arrive fails the test rather than hangs it.
			await Task.Delay(TimeSpan.FromSeconds(30), token);
			return query.CreateResponse();
		}));

		ValueTask<DnsQueryResult<DnsAddressRecord>> pending = client.ResolveAddressesAsync(Name, AddressFamily.Unspecified, source.Token);
		await sent.Task.WaitAsync(TimeSpan.FromSeconds(30));
		await source.CancelAsync();

		await Assert.That(async () => await pending).Throws<OperationCanceledException>();
	}

	[Test]
	public async Task AResponseThatDoesNotAnswerTheQueryThrows(CancellationToken cancellationToken)
	{
		Func<DnsMessage, DnsMessage>[] mismatches =
		[
			static query => query.CreateResponse() with { Id = 1 },
			static query => query.CreateResponse() with { Questions = [query.Questions[0] with { Type = DnsRecordType.A }] },
			static query => query.CreateResponse() with { ResponseCode = DnsResponseCode.NxDomain, Questions = [] }
		];

		foreach (Func<DnsMessage, DnsMessage> mismatch in mismatches)
		{
			DnsClient client = new(new ScriptedTransport(mismatch));

			await Assert.That(async () => await client.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).ThrowsExactly<InvalidDataException>();
		}

		// Only FORMERR and NOTIMP may leave the question out.
		DnsClient formErr = new(new ScriptedTransport(static query => query.CreateResponse() with { ResponseCode = DnsResponseCode.FormatError, Questions = [] }));
		await Assert.That(await formErr.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).IsEqualTo(Empty<DnsMxRecord>(DnsResponseCode.FormatError));
	}

	[Test]
	public async Task ATruncatedResponseThrows(CancellationToken cancellationToken)
	{
		DnsClient client = new(new ScriptedTransport(static query => query.CreateResponse() with { IsTruncated = true, Answers = [Rr(Name, 60, new DnsMxData(10, N("mail.example.com")))] }));
		DnsClient truncatedError = new(new ScriptedTransport(static query => query.CreateResponse() with { IsTruncated = true, ResponseCode = DnsResponseCode.NxDomain }));

		await Assert.That(async () => await client.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).ThrowsExactly<InvalidDataException>();
		await Assert.That(async () => await truncatedError.ResolveAsync<DnsMxRecord>(Name, cancellationToken)).ThrowsExactly<InvalidDataException>();
	}

	[Test]
	public async Task AHandlerCanServeTheClientInProcess(CancellationToken cancellationToken)
	{
		DnsClient client = new(new InProcessTransport(new ZoneHandler()));

		await Assert.That(await client.ResolveAddressesAsync("WWW.example.com", AddressFamily.Unspecified, cancellationToken)).IsEqualTo(Positive(Address("192.0.2.80", 300), Address("2001:db8::80", 300)));
		await Assert.That(await client.ResolveAsync<DnsMxRecord>("example.com", cancellationToken)).IsEqualTo(Positive(new DnsMxRecord("mail.example.com", 10, Seconds(3600))));
		await Assert.That(await client.ResolveAsync<DnsTxtRecord>("nothing.example.com", cancellationToken)).IsEqualTo(Empty<DnsTxtRecord>(DnsResponseCode.NxDomain, 300));
	}

	[Test]
	public async Task ConcurrentCallsShareOneClient(CancellationToken cancellationToken)
	{
		const int callCount = 64;
		GatedTransport transport = new();
		DnsClient client = new(transport);

		// Every query waits in the transport, so all are in flight at once, the A and AAAA queries of each call together.
		Task<DnsQueryResult<DnsAddressRecord>>[] calls = [.. Enumerable.Range(1, callCount).Select(i => client.ResolveAddressesAsync($"host{i}.example.com", AddressFamily.Unspecified, cancellationToken).AsTask())];

		await Assert.That(transport.MaxInFlight).IsEqualTo(2 * callCount);

		// Answered in the reverse order of the queries, each with addresses of its own.
		foreach ((DnsMessage query, TaskCompletionSource<DnsMessage> response) in Enumerable.Reverse(transport.Pending))
		{
			DnsQuestion question = query.Questions[0];
			string name = question.Name.ToString();
			int host = int.Parse(name.AsSpan(4, name.IndexOf('.', StringComparison.Ordinal) - 4), CultureInfo.InvariantCulture);
			string address = question.Type is DnsRecordType.A ? $"192.0.2.{host}" : $"2001:db8::{host:x}";

			response.SetResult(DnsMessage.Decode((query.CreateResponse() with { Answers = [A(name, address, host)] }).Encode()));
		}

		DnsQueryResult<DnsAddressRecord>[] results = await Task.WhenAll(calls);

		for (int i = 1; i <= callCount; ++i)
		{
			await Assert.That(results[i - 1]).IsEqualTo(Positive(Address($"192.0.2.{i}", i), Address($"2001:db8::{i:x}", i)));
		}
	}

	private static DnsName N(string name)
	{
		return DnsName.Parse(name);
	}

	private static TimeSpan Seconds(int seconds)
	{
		return TimeSpan.FromSeconds(seconds);
	}

	private static DnsResourceRecord Rr(string owner, int ttl, DnsRecordData data)
	{
		return new DnsResourceRecord(N(owner), Seconds(ttl), data);
	}

	private static DnsResourceRecord A(string owner, string address, int ttl = 60)
	{
		return Rr(owner, ttl, new DnsAddressData(IPAddress.Parse(address)));
	}

	private static DnsResourceRecord CName(string owner, string target, int ttl = 60)
	{
		return Rr(owner, ttl, new DnsCNameData(N(target)));
	}

	private static DnsResourceRecord Soa(string zone, int ttl, int minimum)
	{
		return Rr(zone, ttl, new DnsSoaData(N($"ns1.{zone}"), N($"hostmaster.{zone}"), 2026111901, Seconds(7200), Seconds(900), Seconds(1209600), Seconds(minimum)));
	}

	private static DnsAddressRecord Address(string address, int ttl)
	{
		return new DnsAddressRecord(IPAddress.Parse(address), Seconds(ttl));
	}

	private static DnsQueryResult<T> Positive<T>(params T[] records)
	{
		return new DnsQueryResult<T>(DnsResponseCode.NoError, records, TimeSpan.Zero);
	}

	private static DnsQueryResult<T> Empty<T>(DnsResponseCode responseCode, int negativeCacheTtl = 0)
	{
		return new DnsQueryResult<T>(responseCode, [], Seconds(negativeCacheTtl));
	}

	// A client whose transport answers every query with NOERROR and the given sections.
	private static DnsClient Answering(params DnsResourceRecord[] answers)
	{
		return Answering(answers, []);
	}

	private static DnsClient Answering(DnsResourceRecord[] answers, DnsResourceRecord[] authorities)
	{
		return new DnsClient(new ScriptedTransport(query => query.CreateResponse() with { Answers = answers, Authorities = authorities }));
	}

	private static async Task AssertNxDomainAtOnce<T>(ValueTask<DnsQueryResult<T>> task)
	{
		await Assert.That(task.IsCompletedSuccessfully).IsTrue();
		await Assert.That(await task).IsEqualTo(new DnsQueryResult<T>(DnsResponseCode.NxDomain, [], TimeSpan.Zero));
	}

	private static async Task AssertCanceledAtOnce<T>(ValueTask<DnsQueryResult<T>> task)
	{
		await Assert.That(task.IsCanceled).IsTrue();
		await Assert.That(async () => await task).Throws<OperationCanceledException>();
	}

	private static async Task CallEachMethodAsync(DnsClient client, string name, CancellationToken cancellationToken)
	{
		foreach (AddressFamily family in (AddressFamily[])[AddressFamily.Unspecified, AddressFamily.InterNetwork, AddressFamily.InterNetworkV6])
		{
			_ = await client.ResolveAddressesAsync(name, family, cancellationToken);
		}

		_ = await client.ResolveAsync<DnsMxRecord>(name, cancellationToken);
	}

	// A record type that builds no record and keeps the owner of each RRset that it gets.
	private readonly record struct CountingRecord(TimeSpan Ttl) : IDnsQueryRecord<CountingRecord>
	{
		public static List<DnsName> Owners { get; } = [];

		public static DnsRecordType Type => DnsRecordType.HInfo;

		public static CountingRecord[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
		{
			Owners.Add(answers[0].Name);
			return [];
		}
	}

	// A record type of MX records whose CreateRecords breaks its contract by returning null.
	private readonly record struct NullRecord(TimeSpan Ttl) : IDnsQueryRecord<NullRecord>
	{
		public static DnsRecordType Type => DnsRecordType.Mx;

		public static NullRecord[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
		{
			return null!;
		}
	}

	// A record type whose Type is MX on the first read and ANY after it.
	private readonly record struct FlippingRecord(TimeSpan Ttl) : IDnsQueryRecord<FlippingRecord>
	{
		public static int Reads { get; set; }

		public static DnsRecordType Type => Reads++ == 0 ? DnsRecordType.Mx : DnsRecordType.Any;

		public static FlippingRecord[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
		{
			return [new FlippingRecord(ttl)];
		}
	}

	// Record types whose Type is a meta-type or a QTYPE.
	private readonly record struct AnyRecord(TimeSpan Ttl) : IDnsQueryRecord<AnyRecord>
	{
		public static DnsRecordType Type => DnsRecordType.Any;

		public static AnyRecord[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
		{
			return [];
		}
	}

	private readonly record struct OptRecord(TimeSpan Ttl) : IDnsQueryRecord<OptRecord>
	{
		public static DnsRecordType Type => DnsRecordType.Opt;

		public static OptRecord[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
		{
			return [];
		}
	}

	private readonly record struct Type128Record(TimeSpan Ttl) : IDnsQueryRecord<Type128Record>
	{
		public static DnsRecordType Type => (DnsRecordType)128;

		public static Type128Record[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
		{
			return [];
		}
	}

	// Record types of the data types next to the range of QTYPEs and meta-types.
	private readonly record struct Type127Record(TimeSpan Ttl) : IDnsQueryRecord<Type127Record>
	{
		public static DnsRecordType Type => (DnsRecordType)127;

		public static Type127Record[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
		{
			return [];
		}
	}

	private readonly record struct Type256Record(TimeSpan Ttl) : IDnsQueryRecord<Type256Record>
	{
		public static DnsRecordType Type => (DnsRecordType)256;

		public static Type256Record[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
		{
			return [];
		}
	}

	// Answers each query with respond, through the wire format by default.
	private sealed class ScriptedTransport(Func<DnsMessage, DnsMessage> respond, bool roundTrip = true) : IDnsTransport
	{
		private readonly Lock _lock = new();

		public List<DnsMessage> Queries { get; } = [];

		public List<CancellationToken> Tokens { get; } = [];

		public ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
		{
			lock (_lock)
			{
				Queries.Add(query);
				Tokens.Add(cancellationToken);
			}

			DnsMessage response = respond(query);
			return ValueTask.FromResult(roundTrip ? DnsMessage.Decode(response.Encode()) : response);
		}
	}

	// Answers every query with the same response, already complete.
	private sealed class FixedTransport(DnsMessage response) : IDnsTransport
	{
		public ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
		{
			return ValueTask.FromResult(response);
		}
	}

	private sealed class AsyncTransport(Func<DnsMessage, CancellationToken, Task<DnsMessage>> respond) : IDnsTransport
	{
		public ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
		{
			return new ValueTask<DnsMessage>(respond(query, cancellationToken));
		}
	}

	// Holds each query until the test completes its response, and counts the queries in flight at once.
	private sealed class GatedTransport : IDnsTransport
	{
		private readonly Lock _lock = new();

		private int _inFlight;

		public List<(DnsMessage Query, TaskCompletionSource<DnsMessage> Response)> Pending { get; } = [];

		public int MaxInFlight { get; private set; }

		public async ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
		{
			TaskCompletionSource<DnsMessage> response = new(TaskCreationOptions.RunContinuationsAsynchronously);

			lock (_lock)
			{
				Pending.Add((query, response));
				MaxInFlight = Math.Max(MaxInFlight, ++_inFlight);
			}

			try
			{
				return await response.Task.WaitAsync(cancellationToken);
			}
			finally
			{
				lock (_lock)
				{
					--_inFlight;
				}
			}
		}
	}

	// Hands each query to a handler in the same process, through the wire format.
	private sealed class InProcessTransport(IDnsRequestHandler handler) : IDnsTransport
	{
		public async ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
		{
			DnsMessage request = DnsMessage.Decode(query.Encode());
			DnsMessage? response = await handler.HandleAsync(new DnsRequestContext(request, DnsProtocol.Udp), cancellationToken);
			return response is null ? throw new TimeoutException("The handler sent no response.") : DnsMessage.Decode(response.Encode());
		}
	}

	// Serves a small zone: www.example.com is an alias of web.example.com, which has an A and an AAAA record, and example.com has an MX record.
	private sealed class ZoneHandler : IDnsRequestHandler
	{
		private static readonly DnsResourceRecord[] Zone =
		[
			CName("www.example.com", "web.example.com", 300),
			A("web.example.com", "192.0.2.80", 300),
			A("web.example.com", "2001:db8::80", 300),
			Rr("example.com", 3600, new DnsMxData(10, N("mail.example.com"))),
			A("mail.example.com", "192.0.2.25", 300)
		];

		public ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
		{
			DnsQuestion question = context.Request.Questions[0];
			List<DnsResourceRecord> answers = [];
			DnsName name = question.Name;

			// Follow aliases within the zone (RFC 1034, Sec. 4.3.2).
			while (Zone.FirstOrDefault(record => record.Name == name && record.Type is DnsRecordType.CName && question.Type is not DnsRecordType.CName) is { Data: DnsCNameData alias } cname)
			{
				answers.Add(cname);
				name = alias.CanonicalName;
			}

			answers.AddRange(Zone.Where(record => record.Name == name && record.Type == question.Type));
			bool exists = Zone.Any(record => record.Name == name);

			DnsMessage response = context.Request.CreateResponse() with
			{
				IsAuthoritativeAnswer = true,
				ResponseCode = exists ? DnsResponseCode.NoError : DnsResponseCode.NxDomain,
				Answers = answers,
				Authorities = answers.Count is 0 ? [Soa("example.com", 3600, 300)] : []
			};

			return ValueTask.FromResult<DnsMessage?>(response);
		}
	}
}
