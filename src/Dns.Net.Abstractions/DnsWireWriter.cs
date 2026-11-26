using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;

namespace Dns.Net.Abstractions;

// Writes a message in wire format, compressing names (RFC 1035, Sec. 4.1.4).
// Callers give it room for a message of the greatest length, so that running out of room means that the message is too long.
internal ref struct DnsWireWriter
{
	// The greatest offset that the 14 bits of a pointer can hold.
	private const int MaxPointerOffset = 0x3FFF;

	// The most pointers that reading any name written here follows, within the caps of resolvers.
	private const int MaxPointerDepth = 10;

	private const int MaxLabels = (DnsName.MaxEncodedLength - 1) / 2;

	private const int InitialTableCapacity = 64;

	private readonly Span<byte> _buffer;

	// An open-addressing hash table of the suffixes written within reach of a pointer, with case folded, kept at most half full.
	// Only suffixes that a reader reaches with fewer than MaxPointerDepth pointers are entered, so that pointing to one keeps a name within that cap.
	private CompressionEntry[] _table;

	private int _mask;

	private int _count;

	public DnsWireWriter(Span<byte> buffer)
	{
		Debug.Assert(buffer.Length <= DnsMessage.MaxEncodedLength);
		_buffer = buffer;
		_table = RentTable(InitialTableCapacity);
		_mask = InitialTableCapacity - 1;
	}

	public int Position { readonly get; private set; }

	public void WriteUInt8(byte value)
	{
		Allocate(sizeof(byte))[0] = value;
	}

	public void WriteUInt16(ushort value)
	{
		BinaryPrimitives.WriteUInt16BigEndian(Allocate(sizeof(ushort)), value);
	}

	public void WriteUInt32(uint value)
	{
		BinaryPrimitives.WriteUInt32BigEndian(Allocate(sizeof(uint)), value);
	}

	public void WriteBytes(ReadOnlySpan<byte> value)
	{
		value.CopyTo(Allocate(value.Length));
	}

	// Reserves the 16-bit length of the data that follows, which EndLength fills in.
	public int BeginLength()
	{
		int offset = Position;
		WriteUInt16(0);
		return offset;
	}

	public readonly void EndLength(int offset)
	{
		BinaryPrimitives.WriteUInt16BigEndian(_buffer.Slice(offset), (ushort)(Position - offset - sizeof(ushort)));
	}

	public Span<byte> Allocate(int length)
	{
		if (_buffer.Length - Position < length)
		{
			ThrowHelper.ThrowMessageTooLong();
		}

		Span<byte> span = _buffer.Slice(Position, length);
		Position += length;
		return span;
	}

	// Writes name, replacing the longest suffix that the message already holds, regardless of case, with a pointer when compress is true.
	// Only names that may be compressed become targets (RFC 3597, Sec. 4; RFC 2782).
	public void WriteName(DnsName name, bool compress)
	{
		ReadOnlySpan<byte> encoded = name.Encoded;

		if (!compress || name.IsRoot)
		{
			WriteBytes(encoded);
			return;
		}

		Span<int> starts = stackalloc int[MaxLabels];
		Span<int> hashes = stackalloc int[MaxLabels];
		Span<byte> folded = stackalloc byte[DnsName.MaxLabelLength];
		int labels = 0;

		for (int i = 0; encoded[i] is not 0; i += encoded[i] + 1)
		{
			starts[labels++] = i;
		}

		// Each suffix hash chains the hash of the rest, so one pass from the last label back hashes them all.
		int hash = 0;

		for (int i = labels - 1; i >= 0; --i)
		{
			hash = hashes[i] = HashLabel(encoded.Slice(starts[i] + 1, encoded[starts[i]]), hash, folded);
		}

		int start = Position;
		int matched = labels;
		CompressionEntry target = default;

		for (int i = 0; i < labels; ++i)
		{
			target = Find(hashes[i], encoded.Slice(starts[i]));

			if (target.Offset is not 0)
			{
				matched = i;
				break;
			}
		}

		// Reading the labels written here follows one pointer more than reading the target.
		int depth = 0;

		if (matched < labels)
		{
			WriteBytes(encoded.Slice(0, starts[matched]));
			WriteUInt16((ushort)(0xC000 | target.Offset));
			depth = target.Depth + 1;
		}
		else
		{
			WriteBytes(encoded);
		}

		if (depth >= MaxPointerDepth)
		{
			return;
		}

		// The suffixes written out become targets while a pointer can reach them.
		for (int i = 0; i < matched && start + starts[i] <= MaxPointerOffset; ++i)
		{
			Insert(hashes[i], start + starts[i], (byte)depth);
		}
	}

	public void Dispose()
	{
		CompressionEntry[] table = _table;
		_table = [];

		if (table.Length is not 0)
		{
			ArrayPool<CompressionEntry>.Shared.Return(table);
		}
	}

	private static int HashLabel(ReadOnlySpan<byte> label, int next, Span<byte> folded)
	{
		folded = folded.Slice(0, label.Length);

		for (int i = 0; i < label.Length; ++i)
		{
			folded[i] = DnsName.ToLowerAscii(label[i]);
		}

		// HashCode is seeded randomly for each process, which keeps crafted names from colliding on purpose.
		HashCode hash = new();
		hash.Add(next);
		hash.AddBytes(folded);
		return hash.ToHashCode();
	}

	private static CompressionEntry[] RentTable(int capacity)
	{
		CompressionEntry[] table = ArrayPool<CompressionEntry>.Shared.Rent(capacity);
		table.AsSpan(0, capacity).Clear();
		return table;
	}

	// Returns the entry of a written suffix equal to suffix, or an empty entry, with offset 0, if there is none.
	private readonly CompressionEntry Find(int hash, ReadOnlySpan<byte> suffix)
	{
		for (int i = hash & _mask; ; i = i + 1 & _mask)
		{
			CompressionEntry entry = _table[i];

			if (entry.Offset is 0 || entry.Hash == hash && SuffixEquals(entry.Offset, suffix))
			{
				return entry;
			}
		}
	}

	// Compares the name written at offset, following its pointers, with suffix, ignoring case; all pointers point back, so the walk ends.
	private readonly bool SuffixEquals(int offset, ReadOnlySpan<byte> suffix)
	{
		int i = 0;

		while (true)
		{
			int length = _buffer[offset];

			if (length >= 0xC0)
			{
				offset = (length & 0x3F) << 8 | _buffer[offset + 1];
				continue;
			}

			if (length != suffix[i])
			{
				return false;
			}

			if (length is 0)
			{
				return true;
			}

			if (!DnsName.EqualsIgnoreCase(_buffer.Slice(offset + 1, length), suffix.Slice(i + 1, length)))
			{
				return false;
			}

			offset += length + 1;
			i += length + 1;
		}
	}

	private void Insert(int hash, int offset, byte depth)
	{
		if ((_count + 1) * 2 > _mask + 1)
		{
			Grow();
		}

		Place(new CompressionEntry(hash, (ushort)offset, depth));
		++_count;
	}

	private void Grow()
	{
		CompressionEntry[] old = _table;
		int oldCapacity = _mask + 1;
		int capacity = oldCapacity * 2;
		_table = RentTable(capacity);
		_mask = capacity - 1;

		foreach (CompressionEntry entry in old.AsSpan(0, oldCapacity))
		{
			if (entry.Offset is not 0)
			{
				Place(entry);
			}
		}

		ArrayPool<CompressionEntry>.Shared.Return(old);
	}

	private readonly void Place(CompressionEntry entry)
	{
		int i = entry.Hash & _mask;

		while (_table[i].Offset is not 0)
		{
			i = i + 1 & _mask;
		}

		_table[i] = entry;
	}

	// Offset 0 marks an empty slot: the header starts there, so no name can.
	// Depth is the number of pointers that reading the suffix at Offset follows.
	private readonly record struct CompressionEntry(int Hash, ushort Offset, byte Depth);
}
