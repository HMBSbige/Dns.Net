using System.Text;

namespace Dns.Net.Tests;

// Builds wire-format test inputs.
internal static class Wire
{
	// example.com A IN, at offsets 12 to 28 of a message.
	public static readonly byte[] Question = [.. Name("example", "com"), 0x00, 0x01, 0x00, 0x01];

	public static byte[] U16(int value)
	{
		return [(byte)(value >> 8), (byte)value];
	}

	public static byte[] U32(uint value)
	{
		return [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];
	}

	// Uncompressed labels of ASCII text, then the root label.
	public static byte[] Name(params ReadOnlySpan<string> labels)
	{
		List<byte> name = [];

		foreach (string label in labels)
		{
			name.Add((byte)label.Length);
			name.AddRange(Encoding.ASCII.GetBytes(label));
		}

		name.Add(0);
		return [.. name];
	}

	// Labels followed by a pointer instead of the root label.
	public static byte[] CompressedName(int pointer, params ReadOnlySpan<string> labels)
	{
		byte[] name = Name(labels);
		return [.. name.AsSpan(0, name.Length - 1), .. Pointer(pointer)];
	}

	public static byte[] Pointer(int offset)
	{
		return [(byte)(0xC0 | offset >> 8), (byte)offset];
	}

	public static byte[] Header(int id, int flags, int questions, int answers, int authorities, int additionals)
	{
		return [.. U16(id), .. U16(flags), .. U16(questions), .. U16(answers), .. U16(authorities), .. U16(additionals)];
	}

	public static byte[] Record(byte[] owner, int type, ReadOnlySpan<byte> data, uint ttl = 60, int @class = 1)
	{
		return [.. owner, .. U16(type), .. U16(@class), .. U32(ttl), .. U16(data.Length), .. data];
	}

	// The offset just past the name at offset.
	public static int SkipName(ReadOnlySpan<byte> message, int offset)
	{
		while (message[offset] is not 0)
		{
			if (message[offset] >= 0xC0)
			{
				return offset + 2;
			}

			offset += message[offset] + 1;
		}

		return offset + 1;
	}

	// The number of pointers followed to read the name at offset; throws on a loop.
	public static int PointerHops(ReadOnlySpan<byte> message, int offset)
	{
		int hops = 0;

		while (message[offset] is not 0)
		{
			if (message[offset] >= 0xC0)
			{
				offset = (message[offset] & 0x3F) << 8 | message[offset + 1];

				if (++hops > message.Length)
				{
					throw new InvalidDataException("The pointers of a name form a loop.");
				}
			}
			else
			{
				offset += message[offset] + 1;
			}
		}

		return hops;
	}

	public static byte[] Concat(params ReadOnlySpan<byte[]> parts)
	{
		List<byte> result = [];

		foreach (byte[] part in parts)
		{
			result.AddRange(part);
		}

		return [.. result];
	}
}
