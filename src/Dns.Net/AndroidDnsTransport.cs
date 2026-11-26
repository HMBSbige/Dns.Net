using Dns.Net.Abstractions;
using System.Buffers;
using System.Runtime.Versioning;

namespace Dns.Net;

/// <summary>
/// Sends queries through the DNS resolver of Android, as <c>android.net.DnsResolver.rawQuery</c> does: with the servers, Private DNS and cache of the network, and over TCP when UDP truncates the response.
/// </summary>
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
	/// <exception cref="IOException">The resolver failed, or the query is longer than it accepts.</exception>
	/// <exception cref="InvalidDataException">The resolver returned a message that is malformed or does not answer the query.</exception>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
	public ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(query);

		byte[] message = query.Encode();

		return cancellationToken.IsCancellationRequested ? ValueTask.FromCanceled<DnsMessage>(cancellationToken) : SendCoreAsync(query, message, cancellationToken);
	}

	private async ValueTask<DnsMessage> SendCoreAsync(DnsMessage query, byte[] message, CancellationToken cancellationToken)
	{
		byte[] answer = ArrayPool<byte>.Shared.Rent(AndroidResolver.MaxAnswerLength);

		try
		{
			int length = await AndroidResolver.SendAsync(NetworkHandle, message, answer, cancellationToken).ConfigureAwait(false);
			DnsMessage response = DnsMessage.Decode(answer.AsSpan(0, length));

			return response.IsResponseTo(query) ? response : throw new InvalidDataException("The DNS resolver of Android returned a message that does not answer the query.");
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(answer);
		}
	}
}
