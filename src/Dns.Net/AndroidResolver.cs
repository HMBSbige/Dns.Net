using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Dns.Net;

// The descriptor of android_res_nsend is a blocking socket that receives the response code and the answer in separate writes, and android_res_nresult does not retry a short read.
// A Socket would make it non-blocking, so one thread polls all descriptors instead; only that thread cancels, as android_res_cancel closes the descriptor.
[SupportedOSPlatform("android29.0")]
internal static unsafe partial class AndroidResolver
{
	private const short PollIn = 0x1;

	private const int EIntr = 4;

	private const int EfdNonBlock = 0x800;

	private const int EfdCloexec = 0x80000;

	private static Poller? _poller;

	private static object? _pollerLock;

	/// <summary>
	/// Sends <paramref name="message" /> on the network of <paramref name="networkHandle" /> and asynchronously reads the answer into <paramref name="answer" />.
	/// </summary>
	/// <returns>A task whose result is the length of the answer.</returns>
	/// <exception cref="IOException">The resolver failed.</exception>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled before the answer arrived.</exception>
	public static Task<int> SendAsync(long networkHandle, ReadOnlySpan<byte> message, byte[] answer, CancellationToken cancellationToken)
	{
		// Before the query, so that a poller that fails to start leaves no descriptor open.
		// Not Lazy<T>, which would keep a failure, such as running out of descriptors, for good; with a lock, as a second poller would never stop.
		Poller poller = LazyInitializer.EnsureInitialized(ref _poller, ref _pollerLock, static () => new Poller());
		int fd;

		fixed (byte* pointer = message)
		{
			fd = ResNSend((ulong)networkHandle, pointer, (nuint)message.Length, 0);
		}

		return fd < 0 ? Task.FromException<int>(ResolverError(-fd)) : poller.WaitAsync(fd, answer, cancellationToken);
	}

	private static IOException ResolverError(int errno)
	{
		return new IOException($"The DNS resolver of Android failed: {Marshal.GetPInvokeErrorMessage(errno)} (errno {errno}).");
	}

	[LibraryImport("libandroid.so", EntryPoint = "android_res_nsend")]
	private static partial int ResNSend(ulong network, byte* msg, nuint msglen, uint flags);

	[LibraryImport("libandroid.so", EntryPoint = "android_res_nresult")]
	private static partial int ResNResult(int fd, int* rcode, byte* answer, nuint anslen);

	[LibraryImport("libandroid.so", EntryPoint = "android_res_cancel")]
	private static partial void ResCancel(int fd);

	[LibraryImport("libc", EntryPoint = "poll", SetLastError = true)]
	private static partial int Poll(PollFd* fds, nuint nfds, int timeout);

	[LibraryImport("libc", EntryPoint = "eventfd", SetLastError = true)]
	private static partial int EventFd(uint initval, int flags);

	[LibraryImport("libc", EntryPoint = "read")]
	private static partial nint Read(int fd, void* buf, nuint count);

	[LibraryImport("libc", EntryPoint = "write")]
	private static partial nint Write(int fd, void* buf, nuint count);

	private struct PollFd
	{
		public int Fd;

		public short Events;

		public short Revents;
	}

	private sealed class Query(Poller poller, int fd, byte[] answer, CancellationToken cancellationToken) : TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously), IThreadPoolWorkItem
	{
		private volatile bool _cancelRequested;

		private CancellationTokenRegistration _registration;

		public int Fd { get; } = fd;

		public bool CancelRequested => _cancelRequested;

		public void Register()
		{
			_registration = cancellationToken.UnsafeRegister(static state => ((Query)state!).RequestCancel(), this);
		}

		// On the thread pool, as the rest of the answer may still be on its way.
		public void Execute()
		{
			int length;
			int rcode;

			fixed (byte* pointer = answer)
			{
				// Closes the descriptor.
				length = ResNResult(Fd, &rcode, pointer, (nuint)answer.Length);
			}

			_registration.Dispose();

			if (length < 0)
			{
				TrySetException(ResolverError(-length));
			}
			else
			{
				TrySetResult(length);
			}
		}

		public void Cancel()
		{
			ResCancel(Fd);
			_registration.Dispose();
			TrySetCanceled(cancellationToken);
		}

		public void Fail(int errno)
		{
			ResCancel(Fd);
			_registration.Dispose();
			TrySetException(ResolverError(errno));
		}

		private void RequestCancel()
		{
			_cancelRequested = true;
			poller.Wake();
		}
	}

	private sealed class Poller
	{
		private readonly int _wakeFd;

		private readonly Lock _lock = new();

		private List<Query> _added = [];

		public Poller()
		{
			_wakeFd = EventFd(0, EfdNonBlock | EfdCloexec);

			if (_wakeFd < 0)
			{
				throw ResolverError(Marshal.GetLastPInvokeError());
			}

			new Thread(Run) { IsBackground = true, Name = "Dns.Net resolver" }.UnsafeStart();
		}

		public Task<int> WaitAsync(int fd, byte[] answer, CancellationToken cancellationToken)
		{
			Query query = new(this, fd, answer, cancellationToken);

			// Before the poller can take the query, so that Execute and Cancel see the registration.
			query.Register();

			lock (_lock)
			{
				_added.Add(query);
			}

			Wake();
			return query.Task;
		}

		public void Wake()
		{
			ulong one = 1;

			// Fails only for a full counter, which wakes the poller anyway.
			_ = Write(_wakeFd, &one, sizeof(ulong));
		}

		private void Run()
		{
			List<Query> waiting = [];
			List<Query> added = [];
			PollFd[] fds = GC.AllocateUninitializedArray<PollFd>(16, pinned: true);

			while (true)
			{
				lock (_lock)
				{
					(added, _added) = (_added, added);
				}

				waiting.AddRange(added);
				added.Clear();

				// Every query, as a cancellation may come before the poller takes it.
				waiting.RemoveAll(static query =>
				{
					if (!query.CancelRequested)
					{
						return false;
					}

					query.Cancel();
					return true;
				});

				int count = waiting.Count + 1;

				if (fds.Length < count)
				{
					fds = GC.AllocateUninitializedArray<PollFd>(Math.Max(fds.Length * 2, count), pinned: true);
				}

				fds[0] = new PollFd { Fd = _wakeFd, Events = PollIn };

				for (int i = 0; i < waiting.Count; ++i)
				{
					fds[i + 1] = new PollFd { Fd = waiting[i].Fd, Events = PollIn };
				}

				int result;

				fixed (PollFd* pointer = fds)
				{
					result = Poll(pointer, (nuint)count, -1);
				}

				if (result < 0)
				{
					int errno = Marshal.GetLastPInvokeError();

					if (errno is EIntr)
					{
						continue;
					}

					// Fails the queries rather than spin on them.
					foreach (Query query in waiting)
					{
						query.Fail(errno);
					}

					waiting.Clear();
					continue;
				}

				if (fds[0].Revents is not 0)
				{
					ulong value;

					_ = Read(_wakeFd, &value, sizeof(ulong));
				}

				for (int i = waiting.Count - 1; i >= 0; --i)
				{
					// POLLHUP and POLLERR too, which android_res_nresult then reports.
					if (fds[i + 1].Revents is 0)
					{
						continue;
					}

					Query query = waiting[i];
					waiting.RemoveAt(i);
					ThreadPool.UnsafeQueueUserWorkItem(query, preferLocal: false);
				}
			}
		}
	}
}
