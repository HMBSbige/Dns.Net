# Dns.Net
Package | NuGet
-|-
Dns.Net | [![NuGet.org](https://img.shields.io/nuget/v/Dns.Net.svg?logo=nuget)](https://www.nuget.org/packages/Dns.Net/)
Dns.Net.Abstractions | [![NuGet.org](https://img.shields.io/nuget/v/Dns.Net.Abstractions.svg?logo=nuget)](https://www.nuget.org/packages/Dns.Net.Abstractions/)

Modern DNS for .NET: a message model with its wire format, a query layer for any record type, and pluggable transports and server handlers.

## Status

| Icon | Description |
|:----:|-------------|
| ⚠️ | Pending |
| ⏳ | Underway |
| ✅ | Done |

| Features | Status |
| -------- |:------:|
| Messages, names and records, with the wire format (RFC 1035, RFC 3596, RFC 2782, RFC 3597) | ✅ |
| EDNS(0) (RFC 6891) | ✅ |
| Length framing for stream transports (RFC 7766) | ✅ |
| Query client over `System.Net.Dns` and `System.Net.DnsResolver` | ✅ |
| Query client over any transport: CNAME chains, negative caching TTLs (RFC 2308) | ✅ |
| Server handler contract | ✅ |
| Transports for classic DNS over UDP and TCP | ⚠️ |
| DNS over TLS, HTTPS and QUIC | ⚠️ |
| Server transports | ⚠️ |

## Installation

The packages target .NET 11.

| Package | Contents |
| --- | --- |
| `Dns.Net` | The clients `SystemDnsClient` and `DnsClient`; includes `Dns.Net.Abstractions`. |
| `Dns.Net.Abstractions` | The message layer, the transport and server handler contracts, and the query contract `IDnsClient`, for libraries that take a client or a transport rather than make one. |

```shell
dotnet add package Dns.Net
```

> [!IMPORTANT]
> The package adds the root namespace `Dns`, which hides the class `System.Net.Dns`: `Dns.GetHostAddresses("example.com")` then fails with error CS0234.
> Write `System.Net.Dns.GetHostAddresses("example.com")`, or use an alias such as `using SystemDns = System.Net.Dns;`.

## Querying with SystemDnsClient

`SystemDnsClient` resolves through the DNS resolver of .NET: `System.Net.Dns` with the system's servers, or a `System.Net.DnsResolver` with the servers you give, which the client owns and disposes.
A DNS outcome such as NXDOMAIN comes back in `ResponseCode`, not as an exception.
When no response arrives, it returns SERVFAIL on Windows and throws on other platforms.
It resolves addresses and SRV, MX, TXT, CNAME, PTR and NS records; `ResolveAsync` throws `NotSupportedException` for any other type.
Names come back without escapes, so `a\.b.example` reads as `a.b.example`; `DnsClient` keeps the escapes.

```csharp
using System.Net;
using System.Net.Sockets;
using Dns.Net;
using Dns.Net.Abstractions;

await using SystemDnsClient client = new();

DnsQueryResult<DnsMxRecord> mx = await client.ResolveAsync<DnsMxRecord>("example.com");

foreach (DnsMxRecord record in mx.Records)
{
	Console.WriteLine($"{record.Preference} {record.Exchange} (TTL {record.Ttl})");
}

DnsQueryResult<DnsAddressRecord> addresses = await client.ResolveAddressesAsync("example.com", AddressFamily.InterNetworkV6);
DnsQueryResult<DnsPtrRecord> ptr = await client.ResolvePtrAsync(IPAddress.Parse("192.0.2.1"));

await using SystemDnsClient custom = new(new DnsResolverOptions { Servers = [new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53)] });
DnsQueryResult<DnsTxtRecord> txt = await custom.ResolveAsync<DnsTxtRecord>("example.com");
```

`GetHostAddressesAsync` works like `System.Net.Dns.GetHostAddressesAsync`, over any `IDnsClient`.
Without a query, an IP address resolves to itself, a name in `localhost` to the loopback addresses, and a name in `invalid` or `onion` fails with `SocketError.HostNotFound`.
It consults no hosts file, search domain or mDNS, and an empty name throws `ArgumentException`.

```csharp
using System.Net;
using System.Net.Sockets;
using Dns.Net;
using Dns.Net.Abstractions;

await using SystemDnsClient client = new();

try
{
	IPAddress[] addresses = await client.GetHostAddressesAsync("example.com", AddressFamily.InterNetwork);
	Console.WriteLine(addresses[0]);
}
catch (SocketException e) when (e.SocketErrorCode is SocketError.HostNotFound)
{
	Console.WriteLine("No such host.");
}
```

## Querying over any transport with DnsClient

`DnsClient` queries over any `IDnsTransport`, which sends one query and returns the complete response to it.
The client follows CNAME chains, takes the negative-cache TTL from the SOA record (RFC 2308), and converts internationalized names.
Its `ResolveAsync<TRecord>` takes any record type that implements `IDnsQueryRecord<TSelf>`, one of your own included.
It is a stub resolver: it expects a recursive resolver behind the transport.
It answers a name in `onion` with NXDOMAIN without a query, unless `QueriesOnionNames` is `true`.

The example passes each query to a handler in the same process.

```csharp
using System.Net;
using System.Net.Sockets;
using Dns.Net;
using Dns.Net.Abstractions;

DnsClient client = new(new InProcessTransport(new LoopbackHandler()));

DnsQueryResult<DnsAddressRecord> result = await client.ResolveAddressesAsync("anything.test", AddressFamily.InterNetwork);
Console.WriteLine(result.Records[0].Address); // 127.0.0.1

sealed class InProcessTransport(IDnsRequestHandler handler) : IDnsTransport
{
	public const DnsProtocol InProcess = (DnsProtocol)100;

	public async ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		DnsMessage response = await handler.HandleAsync(new DnsRequestContext(query, InProcess), cancellationToken) ?? throw new TimeoutException("The handler sent no response.");

		// An IDnsTransport returns only a complete response to its query.
		return response.IsResponseTo(query) && !response.IsTruncated ? response : throw new InvalidDataException("The response does not answer the query.");
	}
}

sealed class LoopbackHandler : IDnsRequestHandler
{
	public ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
	{
		DnsMessage request = context.Request;

		DnsMessage response = request.CreateResponse() with
		{
			Answers = [.. request.Questions.Where(static q => q is { Type: DnsRecordType.A, Class: DnsClass.Internet }).Select(static q => new DnsResourceRecord(q.Name, TimeSpan.FromMinutes(5), new DnsAddressData(IPAddress.Loopback)))]
		};

		return ValueTask.FromResult<DnsMessage?>(response);
	}
}
```

## The message layer

`DnsMessage` holds a whole message, `DnsName` a domain name and `DnsResourceRecord` a record with typed data, such as `DnsAddressData` or `DnsMxData`; a type without a class of its own keeps its data as `DnsUnknownData`.
Messages are immutable records: derive one with `with`.
`DnsName` reads and writes the presentation format, with escapes such as `\032`; convert an internationalized name first with `IdnMapping.GetAscii`, or let `DnsClient` convert it.

```csharp
using Dns.Net.Abstractions;

DnsMessage query = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("example.com"), DnsRecordType.Https));
byte[] wire = query.Encode();

DnsMessage decoded = DnsMessage.Decode(wire); // InvalidDataException on malformed input; TryDecode does not throw.
Console.WriteLine(decoded); // As dig shows it.

static async Task PrintAnswersAsync(IDnsTransport transport)
{
	DnsMessage response = await transport.QueryAsync("example.com", DnsRecordType.Mx);

	foreach (DnsResourceRecord answer in response.Answers)
	{
		Console.WriteLine(answer);
	}
}
```

`DnsStreamExtensions` frames messages with their length on a stream, for TCP, DNS over TLS and DNS over QUIC.
The examples below leave out TSIG/SIG(0), DNS Cookies and EDNS Padding, and send each query as given, so give them only EDNS options that the protocol allows; `DnsClient` adds none.

```csharp
using System.Net.Quic;
using Dns.Net.Abstractions;

// TCP and DNS over TLS: one query at a time on the connection.
// Close the connection after a canceled or failed exchange, as a late response may follow.
static async Task<DnsMessage?> ExchangeAsync(Stream stream, DnsMessage query, CancellationToken cancellationToken = default)
{
	await stream.WriteDnsMessageAsync(query, cancellationToken);
	DnsMessage? response = await stream.ReadDnsMessageAsync(cancellationToken); // null at a clean end of the stream.

	return response is null || response.IsResponseTo(query) && !response.IsTruncated ? response : throw new InvalidDataException("The response does not answer the query.");
}

// DNS over QUIC: each query on a new stream, with ID 0 (RFC 9250, Sec. 4.2).
// Anything but one complete response is a protocol error (RFC 9250, Sec. 4.3.3).
static async Task<DnsMessage> ExchangeOverQuicAsync(QuicConnection connection, DnsMessage query, CancellationToken cancellationToken = default)
{
	DnsMessage sent = query with { Id = 0 };

	await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken);
	await stream.WriteDnsMessageAsync(sent, cancellationToken);
	stream.CompleteWrites();

	DnsMessage? response;

	try
	{
		response = await stream.ReadDnsMessageAsync(cancellationToken) is { } message && await stream.ReadDnsFrameAsync(cancellationToken) is null ? message : null;
	}
	catch (Exception e) when (e is EndOfStreamException or InvalidDataException)
	{
		response = null;
	}

	if (response is null || !response.IsResponseTo(sent) || response.IsTruncated || response.Edns?.Options.Any(static o => o.Code is DnsEdnsOptionCode.TcpKeepalive) is true)
	{
		await connection.CloseAsync(0x2); // DOQ_PROTOCOL_ERROR
		throw new InvalidDataException("The server broke the DNS over QUIC protocol.");
	}

	return response with { Id = query.Id };
}
```

## Server handlers

An `IDnsRequestHandler` answers requests; forwarding, caching and the like are handlers that wrap another.
A server transport receives the requests and sends the responses, and does whatever needs the bytes on the wire or the keys:
it drops messages with the QR bit set, answers a request that does not decode with `DnsMessage.CreateErrorResponse`, truncates responses for UDP, and verifies and signs TSIG and SIG(0).
On a stream, it reads requests with `ReadDnsFrameAsync`, which keeps the bytes as received.
A handler authorizes a request by `DnsRequestContext.Signer`, which is `null` for an unauthenticated request; check its `Type` as well as its `Name`, as a SIG(0) key may be one that a client registered for itself.
A handler answers each request with at most one response, so zone transfers are outside its contract.

`new QueryOnlyHandler(new LoopbackHandler())`, with `LoopbackHandler` above, is a handler that a server can take:

```csharp
using System.Net;
using Dns.Net.Abstractions;

// Implements only QUERY and EDNS version 0.
sealed class QueryOnlyHandler(IDnsRequestHandler inner) : IDnsRequestHandler
{
	// BADVERS, which DnsResponseCode does not name.
	private const DnsResponseCode BadVersion = (DnsResponseCode)16;

	public ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
	{
		DnsMessage request = context.Request;

		// FORMERR without the questions, even before BADVERS (RFC 9619, Sec. 4).
		if (request is { Opcode: DnsOpcode.Query, Questions.Count: > 1 })
		{
			return ValueTask.FromResult<DnsMessage?>(request.CreateResponse() with { ResponseCode = DnsResponseCode.FormatError, Questions = [] });
		}

		// BADVERS for any EDNS version above 0 (RFC 6891, Sec. 6.1.3).
		if (request.Edns is { Version: > 0 })
		{
			return ValueTask.FromResult<DnsMessage?>(request.CreateResponse() with { ResponseCode = BadVersion });
		}

		if (request.Opcode is not DnsOpcode.Query)
		{
			return ValueTask.FromResult<DnsMessage?>(request.CreateResponse() with { ResponseCode = DnsResponseCode.NotImplemented });
		}

		return inner.HandleAsync(context, cancellationToken);
	}
}
```
