using Dns.Net.Abstractions;
using System.Buffers;
using System.Runtime.Versioning;

namespace Dns.Net;

/// <summary>
/// Sends queries through the DNS resolver of Android, as <c>android.net.DnsResolver.rawQuery</c> does: with the servers, Private DNS and cache of the network, and over TCP when UDP truncates the response, for answers of up to 8 KiB in current versions of Android.
/// </summary>
/// <remarks>
/// Over UDP, the resolver moves on to the next server on SERVFAIL, NOTIMP or REFUSED, and reports such an answer from every server as a timeout, so the call throws <see cref="IOException" /> instead of returning the response.
/// </remarks>
[SupportedOSPlatform("android29.0")]
public sealed class AndroidDnsTransport : IDnsTransport
{
	/// <summary>
	/// Initializes a transport that queries on the default network of the app.
	/// </summary>
	/// <exception cref="PlatformNotSupportedException">The platform is not Android 10 (API level 29) or later.</exception>
	public AndroidDnsTransport() : this(0)
	{
	}

	/// <summary>
	/// Initializes a transport that queries on the network of <paramref name="networkHandle" />.
	/// </summary>
	/// <param name="networkHandle">The value of <c>android.net.Network.getNetworkHandle()</c>, or 0 for the default network of the app.</param>
	/// <exception cref="PlatformNotSupportedException">The platform is not Android 10 (API level 29) or later.</exception>
	public AndroidDnsTransport(long networkHandle)
	{
		if (!OperatingSystem.IsAndroidVersionAtLeast(29))
		{
			throw new PlatformNotSupportedException("The DNS resolver of Android needs Android 10 (API level 29) or later.");
		}

		NetworkHandle = networkHandle;
	}

	/// <summary>
	/// Gets the handle of the network that the transport queries on, or 0 for the default network of the app.
	/// </summary>
	public long NetworkHandle { get; }

	/// <inheritdoc />
	/// <exception cref="IOException">The resolver failed, such as when every server answered SERVFAIL, NOTIMP or REFUSED over UDP, or the query is longer than it accepts.</exception>
	/// <exception cref="InvalidDataException">The resolver returned a message that is malformed, such as an answer longer than it keeps, which it cuts short; or one that is truncated or does not answer the query.</exception>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
	public ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(query);
		return cancellationToken.IsCancellationRequested ? ValueTask.FromCanceled<DnsMessage>(cancellationToken) : SendCoreAsync(query, cancellationToken);
	}

	private async ValueTask<DnsMessage> SendCoreAsync(DnsMessage query, CancellationToken cancellationToken)
	{
		byte[] buffer = ArrayPool<byte>.Shared.Rent(DnsMessage.MaxEncodedLength);

		try
		{
			_ = query.TryEncode(buffer, out int length);

			// android_res_nsend has sent the query by the time it returns, so the same buffer then receives the answer.
			length = await AndroidResolver.SendAsync(NetworkHandle, buffer.AsSpan(0, length), buffer, cancellationToken).ConfigureAwait(false);
			DnsMessage response = DnsMessage.Decode(buffer.AsSpan(0, length));

			return response.IsResponseTo(query) && !response.IsTruncated ? response : throw new InvalidDataException("The DNS resolver of Android returned a truncated message or one that does not answer the query.");
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}
}
