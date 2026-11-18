using System.Buffers.Binary;
using System.Diagnostics;

namespace Dns.Net.Abstractions;

// Reads a message in wire format. A failed read returns false and records why, so that decoding malformed input never throws.
internal ref struct DnsWireReader
{
	public const int HeaderLength = 12;

	// A pointer that adds no label to a name is pointless, so a name needs at most one pointer for each label it can have.
	private const int MaxPointers = (DnsName.MaxEncodedLength - 1) / 2;

	private const string MessageTruncated = "The message ends inside a field.";

	private const string RdataTruncated = "The RDATA ends before the data that its type requires.";

	private const string RdataTooLong = "The RDATA is longer than the data of its type.";

	private const string NameTooLong = "A name is longer than 255 bytes.";

	private const string ReservedLabelType = "A name has a label of type 0x40 or 0x80, which has no defined use.";

	private const string BadPointer = "A compression pointer leads to labels that do not lie wholly before the labels that lead to it.";

	private const string HeaderPointer = "A compression pointer points into the header.";

	private const string TooManyPointers = "A name follows more than 127 compression pointers.";

	private readonly ReadOnlySpan<byte> _message;

	private int _position;

	// Sequential reads stop here: at the end of the message, or of the RDATA being read. Pointers may still lead anywhere before the name.
	private int _limit;

	private bool _inRdata;

	// The bytes of the last name read, which the next name shares if it is the same.
	private byte[]? _lastName;

	public DnsWireReader(ReadOnlySpan<byte> message)
	{
		_message = message;
		_limit = message.Length;
	}

	// The bytes left before the limit.
	public readonly int Remaining => _limit - _position;

	// The first failure, or null if every read has succeeded.
	public string? Error { readonly get; private set; }

	// Records error unless an earlier failure has been recorded, and returns false.
	public bool Fail(string error)
	{
		Error ??= error;
		return false;
	}

	// Limits sequential reads to the next length bytes, which the caller has checked are in the message.
	public void BeginRdata(int length)
	{
		Debug.Assert(length <= Remaining);
		_limit = _position + length;
		_inRdata = true;
	}

	// Lifts the limit, failing unless the reads since BeginRdata consumed all the RDATA.
	public bool EndRdata()
	{
		if (_position != _limit)
		{
			return Fail(RdataTooLong);
		}

		_limit = _message.Length;
		_inRdata = false;
		return true;
	}

	public bool TryReadUInt16(out ushort value)
	{
		if (Remaining >= sizeof(ushort))
		{
			value = BinaryPrimitives.ReadUInt16BigEndian(_message.Slice(_position));
			_position += sizeof(ushort);
			return true;
		}

		value = 0;
		return FailTruncated();
	}

	// Reads every byte up to the limit.
	public ReadOnlySpan<byte> ReadToLimit()
	{
		ReadOnlySpan<byte> value = _message.Slice(_position, Remaining);
		_position = _limit;
		return value;
	}

	public bool TryReadBytes(int count, out ReadOnlySpan<byte> value)
	{
		if (Remaining >= count)
		{
			value = _message.Slice(_position, count);
			_position += count;
			return true;
		}

		value = default;
		return FailTruncated();
	}

	// Reads a name, following compression pointers (RFC 1035, Sec. 4.1.4).
	// A pointer must lead wholly before the labels that led to it, which rules out loops; the cap on pointers bounds the work.
	public bool TryReadName(out DnsName name)
	{
		Span<byte> buffer = stackalloc byte[DnsName.MaxEncodedLength];
		int length = 0;
		int position = _position;
		int end = _limit;
		int segmentStart = position;
		int resume = -1;
		int pointers = 0;

		while (true)
		{
			if (position >= end)
			{
				name = default;
				return FailOverrun(pointers);
			}

			int label = _message[position];

			if (label is 0)
			{
				buffer[length++] = 0;
				++position;
				break;
			}

			if (label <= DnsName.MaxLabelLength)
			{
				int next = position + 1 + label;

				if (next > end)
				{
					name = default;
					return FailOverrun(pointers);
				}

				// The label and the root label that ends the name must both fit.
				if (length + 1 + label >= DnsName.MaxEncodedLength)
				{
					name = default;
					return Fail(NameTooLong);
				}

				_message.Slice(position, 1 + label).CopyTo(buffer.Slice(length));
				length += 1 + label;
				position = next;
				continue;
			}

			// 01 in the top bits marks the extended label types (RFC 6891, Sec. 5) and 10 is unallocated.
			if (label < 0xC0)
			{
				name = default;
				return Fail(ReservedLabelType);
			}

			if (end - position < 2)
			{
				name = default;
				return FailOverrun(pointers);
			}

			int target = (label & 0x3F) << 8 | _message[position + 1];

			if (target >= segmentStart)
			{
				name = default;
				return Fail(BadPointer);
			}

			if (target < HeaderLength)
			{
				name = default;
				return Fail(HeaderPointer);
			}

			if (++pointers > MaxPointers)
			{
				name = default;
				return Fail(TooManyPointers);
			}

			if (resume < 0)
			{
				resume = position + 2;
			}

			end = segmentStart;
			segmentStart = target;
			position = target;
		}

		_position = resume < 0 ? position : resume;
		name = CreateName(buffer.Slice(0, length));
		return true;
	}

	private bool FailTruncated()
	{
		return Fail(_inRdata ? RdataTruncated : MessageTruncated);
	}

	// Before any pointer, a name that runs out of room runs past the message or the RDATA; after one, into the labels that led to it.
	private bool FailOverrun(int pointers)
	{
		return pointers is 0 ? FailTruncated() : Fail(BadPointer);
	}

	private DnsName CreateName(scoped ReadOnlySpan<byte> encoded)
	{
		if (encoded.Length is 1)
		{
			return default;
		}

		// The records of an RRset share their owner, so reusing the last name saves most allocations.
		if (_lastName is null || !encoded.SequenceEqual(_lastName))
		{
			_lastName = encoded.ToArray();
		}

		return new DnsName(_lastName);
	}
}
