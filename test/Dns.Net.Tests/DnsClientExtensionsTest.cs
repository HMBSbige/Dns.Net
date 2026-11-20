using Dns.Net.Abstractions;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using TUnit.Assertions.Enums;

namespace Dns.Net.Tests;

public class DnsClientExtensionsTest
{
	private static readonly DnsQueryResult<DnsAddressRecord> TwoAddresses = new(
		DnsResponseCode.NoError,
		[new DnsAddressRecord(IPAddress.Parse("192.0.2.1"), TimeSpan.FromSeconds(60)), new DnsAddressRecord(IPAddress.Parse("2001:db8::1"), TimeSpan.FromSeconds(30))],
		TimeSpan.Zero);

	[Test]
	public async Task ResolveAddressesAsksForBothFamilies(CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		DnsQueryResult<DnsAddressRecord> result = await client.ResolveAddressesAsync("example.com", cancellationToken);

		await Assert.That(result).IsEqualTo(TwoAddresses);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", "example.com", AddressFamily.Unspecified)], CollectionOrdering.Matching);
		await Assert.That(client.Tokens).IsEquivalentTo([cancellationToken]);
	}

	[Test]
	[Arguments("192.0.2.1", "1.2.0.192.in-addr.arpa")]
	[Arguments("255.0.10.1", "1.10.0.255.in-addr.arpa")]
	[Arguments("4321:0:1:2:3:4:567:89AB", "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa")]
	[Arguments("::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa")]
	[Arguments("::ffff:192.0.2.1", "1.0.2.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa")]
	[Arguments("fe80::1%3", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa")]
	public async Task ResolvePtrAsksForTheReverseLookupName(string address, string expected, CancellationToken cancellationToken)
	{
		DnsQueryResult<DnsPtrRecord> canned = new(DnsResponseCode.NoError, [new DnsPtrRecord("host.example.com", TimeSpan.FromSeconds(60))], TimeSpan.Zero);
		RecordingClient client = new() { Pointers = canned };

		DnsQueryResult<DnsPtrRecord> result = await client.ResolvePtrAsync(IPAddress.Parse(address), cancellationToken);

		await Assert.That(result).IsEqualTo(canned);
		await Assert.That(client.Calls).IsEquivalentTo([(nameof(DnsPtrRecord), expected, AddressFamily.Unknown)], CollectionOrdering.Matching);
		await Assert.That(client.Tokens).IsEquivalentTo([cancellationToken]);
	}

	[Test]
	public async Task NullArgumentsThrowAtOnce()
	{
		RecordingClient client = new();
		IDnsClient? missing = null;

		await Assert.That(() => { _ = missing!.ResolveAddressesAsync("example.com"); }).Throws<ArgumentNullException>().WithParameterName("client");
		await Assert.That(() => { _ = missing!.ResolvePtrAsync(IPAddress.Loopback); }).Throws<ArgumentNullException>().WithParameterName("client");
		await Assert.That(() => { _ = client.ResolvePtrAsync(null!); }).Throws<ArgumentNullException>().WithParameterName("address");
		await Assert.That(() => { _ = missing!.GetHostAddressesAsync("example.com"); }).Throws<ArgumentNullException>().WithParameterName("client");
		await Assert.That(() => { _ = missing!.GetHostAddressesAsync("example.com", AddressFamily.InterNetwork); }).Throws<ArgumentNullException>().WithParameterName("client");

		// Even with a canceled token.
		await Assert.That(() => { _ = client.GetHostAddressesAsync(null!, new CancellationToken(true)); }).Throws<ArgumentNullException>().WithParameterName("hostNameOrAddress");
		await Assert.That(() => { _ = client.GetHostAddressesAsync(null!, AddressFamily.InterNetwork); }).Throws<ArgumentNullException>().WithParameterName("hostNameOrAddress");
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("example.com")]
	[Arguments("0.0.0.0")]
	[Arguments("")]
	[Arguments("bad\0name")]
	public async Task ACanceledTokenReturnsACanceledTaskBeforeOtherChecks(string host)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };
		CancellationToken canceled = new(true);

		ValueTask<IPAddress[]> task = client.GetHostAddressesAsync(host, (AddressFamily)12345, canceled);

		await Assert.That(task.IsCanceled).IsTrue();
		await Assert.That(async () => await task).Throws<OperationCanceledException>();
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments(AddressFamily.Unknown)]
	[Arguments(AddressFamily.Unix)]
	[Arguments(AddressFamily.AppleTalk)]
	[Arguments((AddressFamily)12345)]
	public async Task AnUnsupportedFamilyThrowsAtOnceBeforeTheHostIsLookedAt(AddressFamily family)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		await Assert.That(() => { _ = client.GetHostAddressesAsync("example.com", family); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("family");
		await Assert.That(() => { _ = client.GetHostAddressesAsync("127.0.0.1", family); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("family");
		await Assert.That(() => { _ = client.GetHostAddressesAsync("", family); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("family");
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("192.0.2.1", AddressFamily.Unspecified, "192.0.2.1", "192.0.2.1")]
	[Arguments("192.0.2.1", AddressFamily.InterNetwork, "192.0.2.1", "192.0.2.1")]
	[Arguments("192.0.2.1", AddressFamily.InterNetworkV6, null, null)]
	[Arguments("2001:db8::1", AddressFamily.Unspecified, "2001:db8::1", null)]
	[Arguments("2001:db8::1", AddressFamily.InterNetworkV6, "2001:db8::1", null)]
	[Arguments("2001:db8::1", AddressFamily.InterNetwork, null, null)]
	[Arguments("::ffff:192.0.2.1", AddressFamily.InterNetwork, null, null)]
	[Arguments("127.0.0.1", AddressFamily.Unspecified, "127.0.0.1", "127.0.0.1")]
	public async Task AnAddressResolvesToItselfWithoutAQuery(string host, AddressFamily family, string? expected, string? expectedWithoutIPv6, CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		IPAddress[] addresses = await Resolve(client, host, family, osSupportsIPv6: true, cancellationToken);
		IPAddress[] withoutIPv6 = await Resolve(client, host, family, osSupportsIPv6: false, cancellationToken);

		string[] expectedAddresses = expected is null ? [] : [expected];
		string[] expectedAddressesWithoutIPv6 = expectedWithoutIPv6 is null ? [] : [expectedWithoutIPv6];
		await Assert.That(Text(addresses)).IsEquivalentTo(expectedAddresses, CollectionOrdering.Matching);
		await Assert.That(Text(withoutIPv6)).IsEquivalentTo(expectedAddressesWithoutIPv6, CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("0.0.0.0")]
	[Arguments("::")]
	[Arguments("0:0:0:0:0:0:0:0")]
	public async Task TheUnspecifiedAddressesThrowAtOnce(string host)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		await Assert.That(() => { _ = client.GetHostAddressesAsync(host); }).ThrowsExactly<ArgumentException>().WithParameterName("hostNameOrAddress");
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	public async Task LongNamesAndNullCharactersThrowAtOnce(CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };
		string name254 = new('a', 254);

		await Assert.That(() => { _ = client.GetHostAddressesAsync(new string('a', 256) + "."); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("hostNameOrAddress");
		await Assert.That(() => { _ = client.GetHostAddressesAsync(name254 + "a"); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("hostNameOrAddress");
		await Assert.That(() => { _ = client.GetHostAddressesAsync("\0" + name254); }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("hostNameOrAddress");
		await Assert.That(() => { _ = client.GetHostAddressesAsync("exa\0mple.com"); }).ThrowsExactly<ArgumentException>().WithParameterName("hostNameOrAddress");
		await Assert.That(() => { _ = client.GetHostAddressesAsync("localhost\0"); }).ThrowsExactly<ArgumentException>().WithParameterName("hostNameOrAddress");
		await Assert.That(client.Calls).IsEmpty();

		// 255 characters with a trailing dot go to the client.
		IPAddress[] addresses = await Resolve(client, name254 + ".", AddressFamily.Unspecified, osSupportsIPv6: true, cancellationToken);
		IPAddress[] withoutIPv6 = await Resolve(client, name254 + ".", AddressFamily.Unspecified, osSupportsIPv6: false, cancellationToken);
		await Assert.That(addresses.Length).IsEqualTo(2);
		await Assert.That(withoutIPv6.Length).IsEqualTo(2);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", name254 + ".", AddressFamily.Unspecified), ("Addresses", name254 + ".", AddressFamily.InterNetwork)], CollectionOrdering.Matching);
	}

	[Test]
	public async Task AnEmptyNameThrowsAtOnce()
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		await Assert.That(() => { _ = client.GetHostAddressesAsync(""); }).ThrowsExactly<ArgumentException>().WithParameterName("hostNameOrAddress");
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("invalid")]
	[Arguments("INVALID")]
	[Arguments("invalid.")]
	[Arguments("host.invalid")]
	[Arguments("a.b.Invalid.")]
	public async Task NamesInInvalidFailWithoutAQuery(string host)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		ValueTask<IPAddress[]> task = client.GetHostAddressesAsync(host, AddressFamily.InterNetwork);

		// Fails through the task, not as an invalid argument.
		await Assert.That(task.IsFaulted).IsTrue();
		SocketException? exception = await Assert.That(async () => await task).ThrowsExactly<SocketException>();
		await Assert.That(exception!.SocketErrorCode).IsEqualTo(SocketError.HostNotFound);
		await Assert.That(exception.Message).Contains(host);
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("onion")]
	[Arguments("onion.")]
	[Arguments("service.onion")]
	[Arguments("SERVICE.ONION.")]
	[Arguments("a.b.onion")]
	[Arguments("service\u3002onion")]
	[Arguments(@"service.\111nion")]
	public async Task NamesInOnionFailWithoutAQuery(string host, CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		foreach (AddressFamily family in (AddressFamily[])[AddressFamily.Unspecified, AddressFamily.InterNetwork, AddressFamily.InterNetworkV6])
		{
			ValueTask<IPAddress[]> task = Resolve(client, host, family, osSupportsIPv6: true, cancellationToken);

			await Assert.That(task.IsFaulted).IsTrue();
			SocketException? exception = await Assert.That(async () => await task).ThrowsExactly<SocketException>();
			await Assert.That(exception!.SocketErrorCode).IsEqualTo(SocketError.HostNotFound);
			await Assert.That(exception.Message).Contains(host);
		}

		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("onion.example")]
	[Arguments("service.onion.example")]
	[Arguments("xonion")]
	public async Task NamesOutsideOnionGoToTheClient(string host, CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		IPAddress[] addresses = await Resolve(client, host, AddressFamily.Unspecified, osSupportsIPv6: true, cancellationToken);

		await Assert.That(Text(addresses)).IsEquivalentTo(["192.0.2.1", "2001:db8::1"], CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", host, AddressFamily.Unspecified)], CollectionOrdering.Matching);
	}

	[Test]
	[Arguments("localhost", AddressFamily.Unspecified, new[] { "::1", "127.0.0.1" }, new[] { "127.0.0.1" })]
	[Arguments("LocalHost.", AddressFamily.Unspecified, new[] { "::1", "127.0.0.1" }, new[] { "127.0.0.1" })]
	[Arguments("app.localhost", AddressFamily.InterNetwork, new[] { "127.0.0.1" }, new[] { "127.0.0.1" })]
	[Arguments("a.b.LOCALHOST.", AddressFamily.InterNetworkV6, new[] { "::1" }, new string[] { })]
	public async Task NamesInLocalhostResolveToLoopbackWithoutAQuery(string host, AddressFamily family, string[] expected, string[] expectedWithoutIPv6, CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		IPAddress[] addresses = await Resolve(client, host, family, osSupportsIPv6: true, cancellationToken);
		IPAddress[] withoutIPv6 = await Resolve(client, host, family, osSupportsIPv6: false, cancellationToken);

		await Assert.That(Text(addresses)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(Text(withoutIPv6)).IsEquivalentTo(expectedWithoutIPv6, CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	public async Task TheOverloadForBothFamiliesPutsIPv6FirstForLocalhost(CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		IPAddress[] addresses = await client.GetHostAddressesAsync("localhost", cancellationToken);

		string[] expected = Socket.OSSupportsIPv6 ? ["::1", "127.0.0.1"] : ["127.0.0.1"];
		await Assert.That(Text(addresses)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("printer\u3002localhost")]
	[Arguments("printer\uFF0Elocalhost")]
	[Arguments("printer\uFF61localhost")]
	[Arguments("localhost\u3002")]
	[Arguments("例え.localhost")]
	public async Task NamesWhoseAsciiFormIsInLocalhostResolveToLoopbackWithoutAQuery(string host, CancellationToken cancellationToken)
	{
		// IdnMapping maps these separators to dots in every globalization mode.
		RecordingClient client = new() { Addresses = TwoAddresses };

		IPAddress[] addresses = await client.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cancellationToken);

		await Assert.That(Text(addresses)).IsEquivalentTo(["127.0.0.1"], CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("host\u3002invalid")]
	[Arguments("host\uFF0Einvalid")]
	[Arguments("host\uFF61invalid.")]
	public async Task NamesWhoseAsciiFormIsInInvalidFailWithoutAQuery(string host)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		SocketException? exception = await Assert.That(async () => await client.GetHostAddressesAsync(host, AddressFamily.InterNetwork)).ThrowsExactly<SocketException>();

		await Assert.That(exception!.SocketErrorCode).IsEqualTo(SocketError.HostNotFound);
		await Assert.That(client.Calls).IsEmpty();
	}

	[Test]
	[Arguments("\uFF4C\uFF4F\uFF43\uFF41\uFF4C\uFF48\uFF4F\uFF53\uFF54")]
	[Arguments("printer.\uFF2C\uFF2F\uFF23\uFF21\uFF2C\uFF28\uFF2F\uFF33\uFF34")]
	public async Task FullWidthNamesAreInLocalhostWhereThePlatformMapsFullWidthLetters(string host, CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		IPAddress[] addresses = await client.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cancellationToken);

		if (PlatformMapsFullWidthLetters())
		{
			await Assert.That(Text(addresses)).IsEquivalentTo(["127.0.0.1"], CollectionOrdering.Matching);
			await Assert.That(client.Calls).IsEmpty();
		}
		else
		{
			await Assert.That(client.Calls).IsEquivalentTo([("Addresses", host, AddressFamily.InterNetwork)], CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task AFullWidthNameIsInInvalidWhereThePlatformMapsFullWidthLetters(CancellationToken cancellationToken)
	{
		const string host = "host.\uFF49\uFF4E\uFF56\uFF41\uFF4C\uFF49\uFF44";
		RecordingClient client = new() { Addresses = TwoAddresses };

		if (PlatformMapsFullWidthLetters())
		{
			SocketException? exception = await Assert.That(async () => await client.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cancellationToken)).ThrowsExactly<SocketException>();

			await Assert.That(exception!.SocketErrorCode).IsEqualTo(SocketError.HostNotFound);
			await Assert.That(client.Calls).IsEmpty();
		}
		else
		{
			_ = await client.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cancellationToken);

			await Assert.That(client.Calls).IsEquivalentTo([("Addresses", host, AddressFamily.InterNetwork)], CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task NamesThatTheConversionRejectsAreJudgedByTheirText(CancellationToken cancellationToken)
	{
		// The conversion rejects an underscore and an empty label.
		RecordingClient client = new() { Addresses = TwoAddresses };

		await Assert.That(Text(await client.GetHostAddressesAsync("_sip.例え.localhost", AddressFamily.InterNetwork, cancellationToken))).IsEquivalentTo(["127.0.0.1"], CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEmpty();

		_ = await client.GetHostAddressesAsync("例え..localhost", AddressFamily.InterNetwork, cancellationToken);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", "例え..localhost", AddressFamily.InterNetwork)], CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(".localhost")]
	[Arguments("a..localhost")]
	[Arguments("notlocalhost")]
	[Arguments("localhost.example")]
	[Arguments("..invalid")]
	[Arguments("xinvalid")]
	[Arguments("invalid.example")]
	public async Task OtherNamesGoToTheClient(string host, CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		IPAddress[] addresses = await Resolve(client, host, AddressFamily.Unspecified, osSupportsIPv6: true, cancellationToken);
		IPAddress[] withoutIPv6 = await Resolve(client, host, AddressFamily.Unspecified, osSupportsIPv6: false, cancellationToken);

		// Without IPv6, what the client returns is not filtered.
		await Assert.That(Text(addresses)).IsEquivalentTo(["192.0.2.1", "2001:db8::1"], CollectionOrdering.Matching);
		await Assert.That(Text(withoutIPv6)).IsEquivalentTo(["192.0.2.1", "2001:db8::1"], CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", host, AddressFamily.Unspecified), ("Addresses", host, AddressFamily.InterNetwork)], CollectionOrdering.Matching);
		await Assert.That(client.Tokens).IsEquivalentTo([cancellationToken, cancellationToken]);
	}

	[Test]
	public async Task SpecialNamesAreJudgedByTheirLabels(CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		// \108 is l, so the last label is localhost or invalid.
		await Assert.That(Text(await client.GetHostAddressesAsync(@"printer.\108ocalhost", AddressFamily.InterNetwork, cancellationToken))).IsEquivalentTo(["127.0.0.1"], CollectionOrdering.Matching);
		await Assert.That(async () => await client.GetHostAddressesAsync(@"host.\105nvalid", AddressFamily.InterNetwork, cancellationToken)).ThrowsExactly<SocketException>();
		await Assert.That(client.Calls).IsEmpty();

		// The escaped dot leaves a single label.
		_ = await client.GetHostAddressesAsync(@"printer\.localhost", AddressFamily.InterNetwork, cancellationToken);
		_ = await client.GetHostAddressesAsync(@"host\.invalid", AddressFamily.InterNetwork, cancellationToken);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", @"printer\.localhost", AddressFamily.InterNetwork), ("Addresses", @"host\.invalid", AddressFamily.InterNetwork)], CollectionOrdering.Matching);
	}

	[Test]
	public async Task WithoutIPv6TheFamilyNarrowsToIPv4(CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };

		await Assert.That(Text(await ResolveWithoutIPv6("localhost", AddressFamily.InterNetworkV6))).IsEmpty();
		await Assert.That(Text(await ResolveWithoutIPv6("localhost", AddressFamily.Unspecified))).IsEquivalentTo(["127.0.0.1"], CollectionOrdering.Matching);
		await Assert.That(Text(await ResolveWithoutIPv6("::1", AddressFamily.Unspecified))).IsEmpty();
		await Assert.That(Text(await ResolveWithoutIPv6("192.0.2.1", AddressFamily.Unspecified))).IsEquivalentTo(["192.0.2.1"], CollectionOrdering.Matching);
		await Assert.That(Text(await ResolveWithoutIPv6("example.com", AddressFamily.InterNetworkV6))).IsEmpty();
		await Assert.That(client.Calls).IsEmpty();

		_ = await ResolveWithoutIPv6("example.com", AddressFamily.Unspecified);
		_ = await ResolveWithoutIPv6("example.com", AddressFamily.InterNetwork);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", "example.com", AddressFamily.InterNetwork), ("Addresses", "example.com", AddressFamily.InterNetwork)], CollectionOrdering.Matching);

		ValueTask<IPAddress[]> ResolveWithoutIPv6(string host, AddressFamily family)
		{
			return Resolve(client, host, family, osSupportsIPv6: false, cancellationToken);
		}
	}

	[Test]
	public async Task ThePublicMethodsAskTheOperatingSystemWhetherItSupportsIPv6(CancellationToken cancellationToken)
	{
		RecordingClient client = new() { Addresses = TwoAddresses };
		bool supportsIPv6 = Socket.OSSupportsIPv6;
		string[] loopback = supportsIPv6 ? ["::1", "127.0.0.1"] : ["127.0.0.1"];
		string[] ipv6Address = supportsIPv6 ? ["2001:db8::1"] : [];

		await Assert.That(Text(await client.GetHostAddressesAsync("localhost", cancellationToken))).IsEquivalentTo(loopback, CollectionOrdering.Matching);
		await Assert.That(Text(await client.GetHostAddressesAsync("2001:db8::1", AddressFamily.InterNetworkV6, cancellationToken))).IsEquivalentTo(ipv6Address, CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEmpty();

		_ = await client.GetHostAddressesAsync("example.com", cancellationToken);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", "example.com", supportsIPv6 ? AddressFamily.Unspecified : AddressFamily.InterNetwork)], CollectionOrdering.Matching);
	}

	[Test]
	public async Task RecordsGiveTheirAddressesInOrder(CancellationToken cancellationToken)
	{
		DnsQueryResult<DnsAddressRecord> reversed = new(DnsResponseCode.NoError, [.. TwoAddresses.Records.Reverse()], TimeSpan.Zero);
		RecordingClient client = new() { Addresses = reversed };

		IPAddress[] addresses = await Resolve(client, "example.com", AddressFamily.Unspecified, osSupportsIPv6: true, cancellationToken);
		IPAddress[] withoutIPv6 = await Resolve(client, "example.com", AddressFamily.Unspecified, osSupportsIPv6: false, cancellationToken);

		await Assert.That(Text(addresses)).IsEquivalentTo(["2001:db8::1", "192.0.2.1"], CollectionOrdering.Matching);
		await Assert.That(Text(withoutIPv6)).IsEquivalentTo(["2001:db8::1", "192.0.2.1"], CollectionOrdering.Matching);
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", "example.com", AddressFamily.Unspecified), ("Addresses", "example.com", AddressFamily.InterNetwork)], CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(DnsResponseCode.NoError, SocketError.NoData)]
	[Arguments(DnsResponseCode.NxDomain, SocketError.HostNotFound)]
	[Arguments(DnsResponseCode.ServerFailure, SocketError.TryAgain)]
	[Arguments(DnsResponseCode.Refused, SocketError.NoRecovery)]
	[Arguments(DnsResponseCode.FormatError, SocketError.NoRecovery)]
	[Arguments((DnsResponseCode)23, SocketError.NoRecovery)]
	public async Task NoAddressesFailWithASocketError(DnsResponseCode responseCode, SocketError expected)
	{
		RecordingClient client = new() { Addresses = new DnsQueryResult<DnsAddressRecord>(responseCode, [], TimeSpan.FromSeconds(30)) };

		ValueTask<IPAddress[]> task = client.GetHostAddressesAsync("host.example.com", AddressFamily.InterNetwork);
		SocketException? exception = await Assert.That(async () => await task).ThrowsExactly<SocketException>();

		await Assert.That(exception!.SocketErrorCode).IsEqualTo(expected);
		await Assert.That(exception.Message).Contains("host.example.com");
		await Assert.That(client.Calls).IsEquivalentTo([("Addresses", "host.example.com", AddressFamily.InterNetwork)], CollectionOrdering.Matching);
	}

	[Test]
	public async Task ExceptionsOfTheClientComeThroughAsTheyAre()
	{
		IOException failure = new("The transport failed.");
		RecordingClient failing = new() { Failure = failure };
		RecordingClient rejecting = new() { RejectsNames = true };

		IOException? thrown = await Assert.That(async () => await failing.GetHostAddressesAsync("example.com")).ThrowsExactly<IOException>();
		await Assert.That(thrown).IsSameReferenceAs(failure);

		// The client throws before it returns a task.
		await Assert.That(() => { _ = rejecting.GetHostAddressesAsync("exa mple.com"); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
	}

	[Test]
	public async Task EachCallGetsItsOwnAddresses(CancellationToken cancellationToken)
	{
		// A caching client returns the same records each time, so each call needs its own addresses.
		DnsQueryResult<DnsAddressRecord> cached = new(
			DnsResponseCode.NoError,
			[new DnsAddressRecord(IPAddress.Parse("fe80::1%3"), TimeSpan.FromSeconds(60)), new DnsAddressRecord(IPAddress.Parse("192.0.2.1"), TimeSpan.FromSeconds(60))],
			TimeSpan.Zero);
		RecordingClient client = new() { Addresses = cached };

		IPAddress[] first = await Resolve(client, "host.example.com", AddressFamily.Unspecified, osSupportsIPv6: true, cancellationToken);
		IPAddress[] second = await Resolve(client, "host.example.com", AddressFamily.Unspecified, osSupportsIPv6: true, cancellationToken);

		await Assert.That(Text(first)).IsEquivalentTo(["fe80::1%3", "192.0.2.1"], CollectionOrdering.Matching);
		await Assert.That(Text(second)).IsEquivalentTo(["fe80::1%3", "192.0.2.1"], CollectionOrdering.Matching);
		await Assert.That(first[0].ScopeId).IsEqualTo(3);

		for (int i = 0; i < first.Length; ++i)
		{
			await Assert.That(first[i]).IsNotSameReferenceAs(second[i]);
			await Assert.That(first[i]).IsNotSameReferenceAs(cached.Records[i].Address);
			await Assert.That(second[i]).IsNotSameReferenceAs(cached.Records[i].Address);
		}

		first[0].ScopeId = 7;

		await Assert.That(second[0].ToString()).IsEqualTo("fe80::1%3");
		await Assert.That(cached.Records[0].Address.ToString()).IsEqualTo("fe80::1%3");
	}

	// GetHostAddressesAsync with the given OS support for IPv6.
	private static ValueTask<IPAddress[]> Resolve(IDnsClient client, string host, AddressFamily family, bool osSupportsIPv6, CancellationToken cancellationToken)
	{
		return DnsClientExtensions.GetHostAddressesCoreAsync(client, host, family, osSupportsIPv6, cancellationToken);
	}

	// IPAddress compares only through Equals, so the assertions compare text.
	private static string[] Text(IPAddress[] addresses)
	{
		return [.. addresses.Select(static address => address.ToString())];
	}

	// False in globalization-invariant mode, which encodes full-width letters in an A-label.
	private static bool PlatformMapsFullWidthLetters()
	{
		return new IdnMapping().GetAscii("\uFF41") == "a";
	}

	// Records each call and answers with canned results.
	private sealed class RecordingClient : IDnsClient
	{
		public List<(string Method, string Name, AddressFamily Family)> Calls { get; } = [];

		public List<CancellationToken> Tokens { get; } = [];

		public DnsQueryResult<DnsAddressRecord> Addresses { get; init; }

		public DnsQueryResult<DnsPtrRecord> Pointers { get; init; }

		// Thrown through the task.
		public Exception? Failure { get; init; }

		// Throws at once, as for an invalid name.
		public bool RejectsNames { get; init; }

		public ValueTask<DnsQueryResult<DnsAddressRecord>> ResolveAddressesAsync(string name, AddressFamily addressFamily, CancellationToken cancellationToken = default)
		{
			return Answer("Addresses", name, addressFamily, cancellationToken, Addresses);
		}

		// Pointers for PTR records, and no records for any other type.
		public ValueTask<DnsQueryResult<TRecord>> ResolveAsync<TRecord>(string name, CancellationToken cancellationToken = default) where TRecord : IDnsQueryRecord<TRecord>
		{
			return Answer(typeof(TRecord).Name, name, AddressFamily.Unknown, cancellationToken, Pointers is DnsQueryResult<TRecord> pointers ? pointers : default);
		}

		private ValueTask<DnsQueryResult<T>> Answer<T>(string method, string name, AddressFamily family, CancellationToken cancellationToken, DnsQueryResult<T> result)
		{
			if (RejectsNames)
			{
				throw new ArgumentException("The name is not valid.", nameof(name));
			}

			Calls.Add((method, name, family));
			Tokens.Add(cancellationToken);
			return Failure is null ? ValueTask.FromResult(result) : ValueTask.FromException<DnsQueryResult<T>>(Failure);
		}
	}
}
