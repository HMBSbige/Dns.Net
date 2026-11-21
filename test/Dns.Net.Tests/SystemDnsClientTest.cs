using Dns.Net.Abstractions;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.Versioning;
using TUnit.Core.Enums;

namespace Dns.Net.Tests;

public class SystemDnsClientTest
{
	// A connectivity-check name with a fixed A record.
	private const string StableName = "dns.msftncsi.com";

	private const string StableAddress = "131.107.255.255";

	[Test]
	public async Task TheOptionsMustNotBeNull()
	{
		await Assert.That(() => new SystemDnsClient(null!)).ThrowsExactly<ArgumentNullException>().WithParameterName("options");
	}

	[Test]
	public async Task ExceptionsOfTheResolverConstructorComeThrough()
	{
		DnsResolverOptions options = new() { Servers = [null!] };

		// DnsResolver uses this parameter name on every platform.
		await Assert.That(() => new SystemDnsClient(options)).ThrowsExactly<ArgumentException>().WithParameterName("options.Servers");
	}

	[Test]
	public async Task PlatformAnnotationsFollowThoseOfTheResolverOfDotNet()
	{
		// Neither resolver supports browsers or WASI; System.Net.Dns, used without options, does not support Android.
		await Assert.That(UnsupportedPlatforms(typeof(SystemDnsClient))).IsEquivalentTo(["browser", "wasi"]);
		await Assert.That(UnsupportedPlatforms(typeof(SystemDnsClient).GetConstructor(Type.EmptyTypes))).IsEquivalentTo(["android"]);
		await Assert.That(UnsupportedPlatforms(typeof(SystemDnsClient).GetConstructor([typeof(DnsResolverOptions)]))).IsEmpty();
	}

	[Test]
	[MatrixDataSource]
	public async Task ArgumentsAreCheckedAtOnce([Matrix] bool withOptions)
	{
		using SystemDnsClient client = Create(withOptions);

		await Assert.That(() => { _ = client.ResolveAddressesAsync(null!, AddressFamily.Unix); }).ThrowsExactly<ArgumentNullException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAddressesAsync("", AddressFamily.InterNetwork); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAddressesAsync("", AddressFamily.Unix); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAddressesAsync(StableName, AddressFamily.Unix); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("addressFamily");
		await Assert.That(() => { _ = client.ResolveAddressesAsync(StableName, (AddressFamily)12345); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("addressFamily");

		foreach (Func<string, CancellationToken, Task> method in Methods(client))
		{
			await Assert.That(() => { _ = method(null!, CancellationToken.None); }).ThrowsExactly<ArgumentNullException>().WithParameterName("name");
			await Assert.That(() => { _ = method("", CancellationToken.None); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ADisposedClientThrows([Matrix] bool withOptions, [Matrix] bool disposeAsync)
	{
		SystemDnsClient client = Create(withOptions);

		// Disposing twice does nothing more.
		for (int i = 0; i < 2; ++i)
		{
			if (disposeAsync)
			{
				await client.DisposeAsync();
			}
			else
			{
				client.Dispose();
			}
		}

		await Assert.That(() => { _ = client.ResolveAddressesAsync(StableName, AddressFamily.Unspecified); }).ThrowsExactly<ObjectDisposedException>();

		foreach (Func<string, CancellationToken, Task> method in Methods(client))
		{
			await Assert.That(() => { _ = method(StableName, CancellationToken.None); }).ThrowsExactly<ObjectDisposedException>();
		}

		// The arguments come first.
		await Assert.That(() => { _ = client.ResolveAsync<DnsMxRecord>(null!); }).ThrowsExactly<ArgumentNullException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAddressesAsync(StableName, AddressFamily.Unix); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("addressFamily");
	}

	[Test]
	[MatrixDataSource]
	public async Task ANameWithANullCharacterThrowsAtOnce([Matrix] bool withOptions, [Matrix] bool disposed)
	{
		// The resolver of Windows would query only the part before the null character.
		const string name = "localhost\0.example.invalid";
		using SystemDnsClient client = Create(withOptions);

		if (disposed)
		{
			// ReSharper disable once DisposeOnUsingVariable
			client.Dispose();
		}

		// The name comes before the client being disposed, and after the address family.
		foreach (AddressFamily family in (AddressFamily[])[AddressFamily.Unspecified, AddressFamily.InterNetwork, AddressFamily.InterNetworkV6])
		{
			await Assert.That(() => { _ = client.ResolveAddressesAsync(name, family); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		}

		await Assert.That(() => { _ = client.ResolveAddressesAsync(name, AddressFamily.Unix); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("addressFamily");

		foreach (Func<string, CancellationToken, Task> method in Methods(client))
		{
			await Assert.That(() => { _ = method(name, CancellationToken.None); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ARecordTypeOutsideTheResolverThrowsAtOnceAfterTheOtherChecks([Matrix] bool withOptions)
	{
		SystemDnsClient client = Create(withOptions);
		IDnsClient contract = client;

		await Assert.That(() => { _ = client.ResolveAsync<HinfoRecord>(StableName); }).ThrowsExactly<NotSupportedException>();
		await Assert.That(() => { _ = contract.ResolveAsync<HinfoRecord>(StableName); }).ThrowsExactly<NotSupportedException>();

		// The name and then the client being disposed come first.
		await Assert.That(() => { _ = client.ResolveAsync<HinfoRecord>(null!); }).ThrowsExactly<ArgumentNullException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAsync<HinfoRecord>(""); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAsync<HinfoRecord>("a\0.example.com"); }).ThrowsExactly<ArgumentException>().WithParameterName("name");

		client.Dispose();

		await Assert.That(() => { _ = client.ResolveAsync<HinfoRecord>("a\0.example.com"); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(() => { _ = client.ResolveAsync<HinfoRecord>(StableName); }).ThrowsExactly<ObjectDisposedException>();
	}

	[Test]
	public async Task NamesInOnionGoToTheResolver()
	{
		// The resolver checks the token before it sends a query.
		using LookupRecorder lookups = new();
		using SystemDnsClient client = CreateUnroutable();
		CancellationToken canceled = new(true);

		foreach (AddressFamily family in (AddressFamily[])[AddressFamily.Unspecified, AddressFamily.InterNetwork, AddressFamily.InterNetworkV6])
		{
			await AssertLookupThenCanceled(lookups, name => client.ResolveAddressesAsync(name, family, canceled));
		}

		await AssertLookupThenCanceled(lookups, name => client.ResolveAsync<DnsSrvRecord>(name, canceled));
		await AssertLookupThenCanceled(lookups, name => client.ResolveAsync<DnsMxRecord>(name, canceled));
		await AssertLookupThenCanceled(lookups, name => client.ResolveAsync<DnsTxtRecord>(name, canceled));
		await AssertLookupThenCanceled(lookups, name => client.ResolveAsync<DnsCNameRecord>(name, canceled));
		await AssertLookupThenCanceled(lookups, name => client.ResolveAsync<DnsPtrRecord>(name, canceled));
		await AssertLookupThenCanceled(lookups, name => client.ResolveAsync<DnsNsRecord>(name, canceled));
	}

	[Test]
	[MatrixDataSource]
	public async Task TheNegativeCacheTtlIsThatOfTheResolver([Matrix(DnsResponseCode.NoError, DnsResponseCode.NxDomain, DnsResponseCode.FormatError, DnsResponseCode.ServerFailure, DnsResponseCode.Refused, (DnsResponseCode)16)] DnsResponseCode responseCode, [Matrix] bool hasRecords)
	{
		// Some platforms report an SOA TTL for any response code, Windows even with records.
		AddressRecord[] records = hasRecords ? [BclAddress("192.0.2.1", 60)] : [];

		DnsQueryResult<DnsAddressRecord> result = SystemDnsClient.ToQueryResult(Bcl.NewResult(responseCode, records, Seconds(300)));

		DnsAddressRecord[] expectedRecords = hasRecords ? [Address("192.0.2.1", 60)] : [];
		await Assert.That(result).IsEqualTo(new DnsQueryResult<DnsAddressRecord>(responseCode, expectedRecords, Seconds(300)));
	}

	[Test]
	public async Task ResultsMapFieldByField()
	{
		TimeSpan ttl = Seconds(60);

		await Assert.That(SystemDnsClient.ToQueryResult(BclPositive(BclAddress("2001:db8::1", 60)))).IsEqualTo(Positive(Address("2001:db8::1", 60)));
		await Assert.That(SystemDnsClient.ToQueryResult(BclPositive(Bcl.NewMxRecord("mail.example.com", 10, ttl), Bcl.NewMxRecord("backup.example.com", 20, ttl * 2))))
			.IsEqualTo(Positive(new DnsMxRecord("mail.example.com", 10, ttl), new DnsMxRecord("backup.example.com", 20, ttl * 2)));
		await Assert.That(SystemDnsClient.ToQueryResult(BclPositive(Bcl.NewTxtRecord(["v=spf1", "-all"], ttl)))).IsEqualTo(Positive(new DnsTxtRecord(["v=spf1", "-all"], ttl)));
		await Assert.That(SystemDnsClient.ToQueryResult(BclPositive(Bcl.NewCNameRecord("example.com", ttl)))).IsEqualTo(Positive(new DnsCNameRecord("example.com", ttl)));
		await Assert.That(SystemDnsClient.ToQueryResult(BclPositive(Bcl.NewPtrRecord("host.example.com", ttl)))).IsEqualTo(Positive(new DnsPtrRecord("host.example.com", ttl)));
		await Assert.That(SystemDnsClient.ToQueryResult(BclPositive(Bcl.NewNsRecord("a.iana-servers.net", ttl)))).IsEqualTo(Positive(new DnsNsRecord("a.iana-servers.net", ttl)));

		// The resolver gives names without escapes, and the client passes them on.
		await Assert.That(SystemDnsClient.ToQueryResult(BclPositive(Bcl.NewPtrRecord("a.b.example", ttl))).Records[0].Name).IsEqualTo("a.b.example");
	}

	[Test]
	public async Task RecordsKeepTheTtlsOfTheResolver()
	{
		DnsQueryResult<DnsAddressRecord> a = SystemDnsClient.ToQueryResult(BclPositive(BclAddress("192.0.2.1", 300), BclAddress("192.0.2.2", 30)));
		DnsQueryResult<DnsAddressRecord> mixed = SystemDnsClient.ToQueryResult(BclPositive(BclAddress("192.0.2.1", 300), BclAddress("2001:db8::1", 120), BclAddress("192.0.2.2", 30), BclAddress("2001:db8::2", 90)));
		DnsQueryResult<DnsTxtRecord> txt = SystemDnsClient.ToQueryResult(BclPositive(Bcl.NewTxtRecord(["a"], Seconds(50)), Bcl.NewTxtRecord(["b"], Seconds(40))));

		// The resolver gives each CNAME of a chain without its owner.
		DnsQueryResult<DnsCNameRecord> chain = SystemDnsClient.ToQueryResult(BclPositive(Bcl.NewCNameRecord("a.example.net", Seconds(30)), Bcl.NewCNameRecord("b.example.org", Seconds(300))));

		await Assert.That(chain).IsEqualTo(Positive(new DnsCNameRecord("a.example.net", Seconds(30)), new DnsCNameRecord("b.example.org", Seconds(300))));
		await Assert.That(a).IsEqualTo(Positive(Address("192.0.2.1", 300), Address("192.0.2.2", 30)));
		await Assert.That(mixed).IsEqualTo(Positive(Address("192.0.2.1", 300), Address("2001:db8::1", 120), Address("192.0.2.2", 30), Address("2001:db8::2", 90)));
		await Assert.That(txt).IsEqualTo(Positive(new DnsTxtRecord(["a"], Seconds(50)), new DnsTxtRecord(["b"], Seconds(40))));
	}

	[Test]
	public async Task SrvRecordsAndTheirAddressesKeepTheTtlsOfTheResolver()
	{
		List<AddressRecord> sip = [BclAddress("192.0.2.1", 20), BclAddress("2001:db8::1", 30), BclAddress("192.0.2.2", 10)];
		List<AddressRecord> backup = [BclAddress("192.0.2.3", 5)];
		DnsResult<SrvRecord> result = BclPositive(
			Bcl.NewSrvRecord("sip.example.com", 5060, 10, 0, Seconds(300), sip),
			Bcl.NewSrvRecord("backup.example.com", 5060, 20, 0, Seconds(100), backup));

		await Assert.That(SystemDnsClient.ToQueryResult(result)).IsEqualTo(Positive(
			new DnsSrvRecord("sip.example.com", 5060, 10, 0, Seconds(300), [Address("192.0.2.1", 20), Address("2001:db8::1", 30), Address("192.0.2.2", 10)]),
			new DnsSrvRecord("backup.example.com", 5060, 20, 0, Seconds(100), [Address("192.0.2.3", 5)])));
	}

	[Test]
	public async Task EachSrvRecordMapsItsAddresses()
	{
		// DnsResolver gives SRV records with the same target the same list.
		TimeSpan ttl = Seconds(300);
		List<AddressRecord> sip = [BclAddress("192.0.2.1", 10), BclAddress("2001:db8::1", 20)];
		List<AddressRecord> backup = [BclAddress("192.0.2.2", 30)];
		DnsResult<SrvRecord> result = BclPositive(
			Bcl.NewSrvRecord("sip.example.com", 5060, 10, 60, ttl, sip),
			Bcl.NewSrvRecord("backup.example.com", 5060, 20, 0, ttl, backup),
			Bcl.NewSrvRecord("SIP.example.com", 5061, 30, 0, ttl, sip),
			Bcl.NewSrvRecord("other.example.com", 5062, 40, 0, ttl, null));

		DnsAddressRecord[] sipAddresses = [Address("192.0.2.1", 10), Address("2001:db8::1", 20)];
		await Assert.That(SystemDnsClient.ToQueryResult(result)).IsEqualTo(Positive(
			new DnsSrvRecord("sip.example.com", 5060, 10, 60, ttl, sipAddresses),
			new DnsSrvRecord("backup.example.com", 5060, 20, 0, ttl, [Address("192.0.2.2", 30)]),
			new DnsSrvRecord("SIP.example.com", 5061, 30, 0, ttl, sipAddresses),
			new DnsSrvRecord("other.example.com", 5062, 40, 0, ttl, [])));
	}

	[Test]
	public async Task SrvRecordsThatShareAnAddressListShareItsMapping()
	{
		TimeSpan ttl = Seconds(300);
		List<AddressRecord> sip = [BclAddress("192.0.2.1", 10)];
		List<AddressRecord> backup = [BclAddress("192.0.2.1", 10)];
		DnsResult<SrvRecord> result = BclPositive(
			Bcl.NewSrvRecord("sip.example.com", 5060, 10, 0, ttl, sip),
			Bcl.NewSrvRecord("backup.example.com", 5060, 20, 0, ttl, backup),
			Bcl.NewSrvRecord("SIP.example.com", 5061, 30, 0, ttl, sip),
			Bcl.NewSrvRecord("other.example.com", 5062, 40, 0, ttl, sip));

		IReadOnlyList<DnsSrvRecord> records = SystemDnsClient.ToQueryResult(result).Records;

		// Sharing follows the lists of the resolver, not their contents.
		await Assert.That(records[2].Addresses).IsSameReferenceAs(records[0].Addresses);
		await Assert.That(records[3].Addresses).IsSameReferenceAs(records[0].Addresses);
		await Assert.That(records[1].Addresses).IsNotSameReferenceAs(records[0].Addresses);
	}

	[Test]
	[MatrixDataSource]
	[Retry(2)]
	[Category("Network")]
	public async Task ResolvesAStableNameOverTheNetwork([Matrix] bool withOptions, CancellationToken cancellationToken)
	{
		await using SystemDnsClient client = Create(withOptions);

		DnsQueryResult<DnsAddressRecord> result = await client.ResolveAddressesAsync(StableName, AddressFamily.InterNetwork, cancellationToken);

		await Assert.That(result.ResponseCode).IsEqualTo(DnsResponseCode.NoError);
		await Assert.That(result.Records.Select(static record => record.Address.ToString())).Contains(StableAddress);
	}

	// Only off Windows can DnsResolver query a free loopback port; there each call sends one query, without search domains.
	[Test]
	[ExcludeOn(OS.Windows)]
	[Arguments(DnsRecordType.A)]
	[Arguments(DnsRecordType.Aaaa)]
	[Arguments(DnsRecordType.Srv)]
	[Arguments(DnsRecordType.Mx)]
	[Arguments(DnsRecordType.Txt)]
	[Arguments(DnsRecordType.CName)]
	[Arguments(DnsRecordType.Ptr)]
	[Arguments(DnsRecordType.Ns)]
	public async Task AClientWithOptionsQueriesTheServersOfTheOptions(DnsRecordType type, CancellationToken cancellationToken)
	{
		using Socket server = BindResponder();
		await using SystemDnsClient client = new(new DnsResolverOptions { Servers = [(IPEndPoint)server.LocalEndPoint!] });
		using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		string name = $"{Guid.NewGuid():N}.test";

		try
		{
			Task<DnsResponseCode> resolve = ResolveAsync(client, type, name, stop.Token);

			await Assert.That(await AnswerWithNxDomainAsync(server, name, cancellationToken)).IsEqualTo(type);
			await Assert.That(await resolve).IsEqualTo(DnsResponseCode.NxDomain);
		}
		finally
		{
			await stop.CancelAsync();
		}
	}

	[Test]
	[ExcludeOn(OS.Windows)]
	public async Task AClientWithOptionsQueriesTheServersOfTheOptionsForBothAddressFamilies(CancellationToken cancellationToken)
	{
		using Socket server = BindResponder();
		await using SystemDnsClient client = new(new DnsResolverOptions { Servers = [(IPEndPoint)server.LocalEndPoint!] });
		using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		string name = $"{Guid.NewGuid():N}.test";

		try
		{
			Task<DnsQueryResult<DnsAddressRecord>> resolve = client.ResolveAddressesAsync(name, AddressFamily.Unspecified, stop.Token).AsTask();

			DnsRecordType first = await AnswerWithNxDomainAsync(server, name, cancellationToken);
			DnsRecordType second = await AnswerWithNxDomainAsync(server, name, cancellationToken);

			await Assert.That([first, second]).IsEquivalentTo([DnsRecordType.A, DnsRecordType.Aaaa]);
			await Assert.That((await resolve).ResponseCode).IsEqualTo(DnsResponseCode.NxDomain);
		}
		finally
		{
			await stop.CancelAsync();
		}
	}

	[Test]
	[Retry(2)]
	[Category("Network")]
	public async Task GetHostAddressesWorksOverTheSystemClient(CancellationToken cancellationToken)
	{
		await using SystemDnsClient client = new();

		IPAddress[] addresses = await client.GetHostAddressesAsync(StableName, AddressFamily.InterNetwork, cancellationToken);

		await Assert.That(addresses.Select(static address => address.ToString())).Contains(StableAddress);
	}

	private static TimeSpan Seconds(int seconds)
	{
		return TimeSpan.FromSeconds(seconds);
	}

	private static AddressRecord BclAddress(string address, int ttl)
	{
		return Bcl.NewAddressRecord(IPAddress.Parse(address), Seconds(ttl));
	}

	private static DnsAddressRecord Address(string address, int ttl)
	{
		return new DnsAddressRecord(IPAddress.Parse(address), Seconds(ttl));
	}

	// A NOERROR result of the resolver, without a negative-cache TTL.
	private static DnsResult<T> BclPositive<T>(params T[] records)
	{
		return Bcl.NewResult(DnsResponseCode.NoError, records, TimeSpan.Zero);
	}

	private static DnsQueryResult<T> Positive<T>(params T[] records)
	{
		return new DnsQueryResult<T>(DnsResponseCode.NoError, records, TimeSpan.Zero);
	}

	private static string[] UnsupportedPlatforms(MemberInfo? member)
	{
		ArgumentNullException.ThrowIfNull(member);
		return [.. member.GetCustomAttributes<UnsupportedOSPlatformAttribute>(inherit: false).Select(static attribute => attribute.PlatformName)];
	}

	private static SystemDnsClient Create(bool withOptions)
	{
		// Empty servers stand for those that the system is configured with.
		return withOptions ? new SystemDnsClient(new DnsResolverOptions()) : new SystemDnsClient();
	}

	// Asks only a documentation address (RFC 5737) that never answers, so no name reaches the system's servers.
	private static SystemDnsClient CreateUnroutable()
	{
		return new SystemDnsClient(new DnsResolverOptions { Servers = [new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53)] });
	}

	// A UDP socket on a free loopback port, to answer the queries that reach it.
	private static Socket BindResponder()
	{
		Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

		try
		{
			socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
			return socket;
		}
		catch
		{
			socket.Dispose();
			throw;
		}
	}

	// Answers one single-question query about name with NXDOMAIN, and returns its type.
	private static async Task<DnsRecordType> AnswerWithNxDomainAsync(Socket server, string name, CancellationToken cancellationToken)
	{
		using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		timeout.CancelAfter(TimeSpan.FromSeconds(10));
		byte[] buffer = new byte[DnsMessage.MaxEncodedLength];

		SocketReceiveFromResult received = await server.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), timeout.Token);
		DnsMessage query = DnsMessage.Decode(buffer.AsSpan(0, received.ReceivedBytes));

		await Assert.That(query.Questions.Count).IsEqualTo(1);
		await Assert.That(query.Questions[0].Name).IsEqualTo(DnsName.Parse(name));

		byte[] response = (query.CreateResponse() with { ResponseCode = DnsResponseCode.NxDomain }).Encode();
		await server.SendToAsync(response, SocketFlags.None, received.RemoteEndPoint, timeout.Token);
		return query.Questions[0].Type;
	}

	// Calls the client method for type and returns the response code.
	private static async Task<DnsResponseCode> ResolveAsync(SystemDnsClient client, DnsRecordType type, string name, CancellationToken cancellationToken)
	{
		return type switch
		{
			DnsRecordType.A => (await client.ResolveAddressesAsync(name, AddressFamily.InterNetwork, cancellationToken)).ResponseCode,
			DnsRecordType.Aaaa => (await client.ResolveAddressesAsync(name, AddressFamily.InterNetworkV6, cancellationToken)).ResponseCode,
			DnsRecordType.Srv => (await client.ResolveAsync<DnsSrvRecord>(name, cancellationToken)).ResponseCode,
			DnsRecordType.Mx => (await client.ResolveAsync<DnsMxRecord>(name, cancellationToken)).ResponseCode,
			DnsRecordType.Txt => (await client.ResolveAsync<DnsTxtRecord>(name, cancellationToken)).ResponseCode,
			DnsRecordType.CName => (await client.ResolveAsync<DnsCNameRecord>(name, cancellationToken)).ResponseCode,
			DnsRecordType.Ptr => (await client.ResolveAsync<DnsPtrRecord>(name, cancellationToken)).ResponseCode,
			DnsRecordType.Ns => (await client.ResolveAsync<DnsNsRecord>(name, cancellationToken)).ResponseCode,
			_ => throw new ArgumentOutOfRangeException(nameof(type), type, "The client has no method for the type.")
		};
	}

	// Calls resolve with a new onion name and a canceled token; checks that a lookup started and that the call fails for the token.
	private static async Task AssertLookupThenCanceled<T>(LookupRecorder lookups, Func<string, ValueTask<DnsQueryResult<T>>> resolve)
	{
		string label = Guid.NewGuid().ToString("N");
		ValueTask<DnsQueryResult<T>> task = resolve(label + ".onion");

		await Assert.That(lookups.HasStarted(label)).IsTrue();
		await Assert.That(async () => await task).Throws<OperationCanceledException>();
	}

	private static Func<string, CancellationToken, Task>[] Methods(SystemDnsClient client)
	{
		return
		[
			(name, cancellationToken) => client.ResolveAsync<DnsSrvRecord>(name, cancellationToken).AsTask(),
			(name, cancellationToken) => client.ResolveAsync<DnsMxRecord>(name, cancellationToken).AsTask(),
			(name, cancellationToken) => client.ResolveAsync<DnsTxtRecord>(name, cancellationToken).AsTask(),
			(name, cancellationToken) => client.ResolveAsync<DnsCNameRecord>(name, cancellationToken).AsTask(),
			(name, cancellationToken) => client.ResolveAsync<DnsPtrRecord>(name, cancellationToken).AsTask(),
			(name, cancellationToken) => client.ResolveAsync<DnsNsRecord>(name, cancellationToken).AsTask()
		];
	}

	// Records the DnsLookup activities that DnsResolver starts, synchronously, on the "Experimental.System.Net.NameResolution" ActivitySource.
	// The listener is process-wide; the unique label in each name tells the tests apart.
	private sealed class LookupRecorder : IDisposable
	{
		private readonly ConcurrentQueue<Activity> _activities = new();

		private readonly ActivityListener _listener;

		public LookupRecorder()
		{
			_listener = new ActivityListener
			{
				ShouldListenTo = static source => source.Name == "Experimental.System.Net.NameResolution",
				Sample = static (ref _) => ActivitySamplingResult.AllData,
				ActivityStarted = _activities.Enqueue
			};

			ActivitySource.AddActivityListener(_listener);
		}

		// Whether a lookup of a name holding label has started. The tag is set after the activity starts, so it is read only here.
		public bool HasStarted(string label)
		{
			return _activities.Any(activity => activity.GetTagItem("dns.question.name") is string name && name.Contains(label, StringComparison.Ordinal));
		}

		public void Dispose()
		{
			_listener.Dispose();
		}
	}
}
