using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;

namespace Dns.Net.Abstractions;

// The wire format of a whole message (RFC 1035, Sec. 4.1); the record data classes read and write their own RDATA.
internal static class DnsMessageCodec
{
	// The root name, the type and the class.
	private const int MinQuestionLength = 5;

	// The root name, the type, the class, the TTL and the RDATA length.
	private const int MinRecordLength = 11;

	private const int RecordFieldsLength = 10;

	private const ushort ResponseFlag = 0x8000;

	private const ushort AuthoritativeAnswerFlag = 0x0400;

	private const ushort TruncatedFlag = 0x0200;

	private const ushort RecursionDesiredFlag = 0x0100;

	private const ushort RecursionAvailableFlag = 0x0080;

	private const ushort AuthenticDataFlag = 0x0020;

	private const ushort CheckingDisabledFlag = 0x0010;

	private const string MessageTooLong = "The message is longer than 65535 bytes.";

	// Writes message into buffer, which has room for MaxEncodedLength bytes, and returns the length written.
	public static int Encode(DnsMessage message, Span<byte> buffer)
	{
		IReadOnlyList<DnsQuestion> questions = message.Questions;
		IReadOnlyList<DnsResourceRecord> answers = message.Answers;
		IReadOnlyList<DnsResourceRecord> authorities = message.Authorities;
		IReadOnlyList<DnsResourceRecord> additionals = message.Additionals;
		DnsEdns? edns = message.Edns;
		int responseCode = (ushort)message.ResponseCode;
		int additionalCount = additionals.Count + (edns is null ? 0 : 1);

		if ((byte)message.Opcode > 0xF)
		{
			throw new InvalidOperationException("The opcode is greater than 15, which is more than its 4 bits in the header can hold.");
		}

		if (responseCode > 0xFFF)
		{
			throw new InvalidOperationException("The response code is greater than 4095, which is more than its 12 bits in the header and the OPT record can hold.");
		}

		if (responseCode > 0xF && edns is null)
		{
			throw new InvalidOperationException("The response code is greater than 15, which needs EDNS: the OPT record holds its upper 8 bits.");
		}

		DnsWireWriter writer = new(buffer);

		try
		{
			writer.WriteUInt16(message.Id);
			writer.WriteUInt16(GetFlags(message, responseCode));
			// Every entry takes at least 5 bytes, so a section of more than 65535 entries overflows the writer before a truncated count could be returned.
			writer.WriteUInt16((ushort)questions.Count);
			writer.WriteUInt16((ushort)answers.Count);
			writer.WriteUInt16((ushort)authorities.Count);
			writer.WriteUInt16((ushort)additionalCount);

			for (int i = 0; i < questions.Count; ++i)
			{
				DnsQuestion question = questions[i];
				writer.WriteName(question.Name, compress: true);
				writer.WriteUInt16((ushort)question.Type);
				writer.WriteUInt16((ushort)question.Class);
			}

			// A TSIG or SIG(0) record must stay last (RFC 8945, Sec. 5.1; RFC 2931, Sec. 3.1), so the OPT record goes before it.
			int beforeOpt = edns is not null && additionals is [.., { Type: DnsRecordType.Tsig or DnsRecordType.Sig }] ? additionals.Count - 1 : additionals.Count;

			WriteRecords(ref writer, answers, 0, answers.Count);
			WriteRecords(ref writer, authorities, 0, authorities.Count);
			WriteRecords(ref writer, additionals, 0, beforeOpt);
			edns?.Write(ref writer, responseCode >> 4);
			WriteRecords(ref writer, additionals, beforeOpt, additionals.Count);
			return writer.Position;
		}
		finally
		{
			writer.Dispose();
		}
	}

	// Returns the message, or null with the reason in error if source is malformed; never throws.
	public static DnsMessage? Decode(ReadOnlySpan<byte> source, out string? error)
	{
		// No transport carries a longer message, and it could not be encoded again.
		if (source.Length > DnsMessage.MaxEncodedLength)
		{
			error = MessageTooLong;
			return null;
		}

		DnsWireReader reader = new(source);
		DnsMessage? message = Read(ref reader);
		error = reader.Error;
		Debug.Assert(message is null == error is not null);
		return message;
	}

	// DnsMessage.CreateErrorResponse describes this; request may be malformed and of any length.
	public static DnsMessage? CreateErrorResponse(ReadOnlySpan<byte> request)
	{
		DnsWireReader reader = new(request);

		if (!reader.TryReadBytes(DnsWireReader.HeaderLength, out ReadOnlySpan<byte> header))
		{
			return null;
		}

		int flags = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(2));

		if ((flags & ResponseFlag) is not 0)
		{
			return null;
		}

		DnsOpcode opcode = (DnsOpcode)(flags >> 11 & 0xF);
		DnsResponseCode responseCode = DnsResponseCode.NotImplemented;
		DnsQuestion? question = null;
		DnsEdns? edns = null;

		// Only these opcodes have the sections that decoding reads; any other gets NOTIMP (RFC 8906, Sec. 7).
		if (opcode is DnsOpcode.Query or DnsOpcode.Notify or DnsOpcode.Update)
		{
			int questionCount = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(4));
			int recordCount = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(6)) + BinaryPrimitives.ReadUInt16BigEndian(header.Slice(8)) + BinaryPrimitives.ReadUInt16BigEndian(header.Slice(10));
			responseCode = DnsResponseCode.FormatError;

			if (request.Length <= DnsMessage.MaxEncodedLength && TryReadQuestions(ref reader, questionCount, out question) && FindOptFlags(ref reader, recordCount) is { } optFlags)
			{
				edns = new DnsEdns { Flags = optFlags & DnsEdnsFlags.DnssecOk };
			}
		}

		return new DnsMessage(question is { } only ? [only] : [], [], [], [])
		{
			Id = BinaryPrimitives.ReadUInt16BigEndian(header),
			IsResponse = true,
			Opcode = opcode,
			IsRecursionDesired = (flags & RecursionDesiredFlag) is not 0,
			IsCheckingDisabled = (flags & CheckingDisabledFlag) is not 0,
			ResponseCode = responseCode,
			Edns = edns
		};

		// Reads count questions, and gives the question if it is the only one; false if one does not read in full.
		static bool TryReadQuestions(ref DnsWireReader reader, int count, out DnsQuestion? only)
		{
			only = null;

			for (int i = 0; i < count; ++i)
			{
				if (!TryReadQuestion(ref reader, out DnsQuestion question))
				{
					return false;
				}

				if (count is 1)
				{
					only = question;
				}
			}

			return true;
		}

		// The flags of the first OPT record among the next count records, whose data is skipped unread; null if there is none.
		static DnsEdnsFlags? FindOptFlags(ref DnsWireReader reader, int count)
		{
			for (int i = 0; i < count; ++i)
			{
				if (!reader.TryReadName(out _) || !reader.TryReadBytes(RecordFieldsLength, out ReadOnlySpan<byte> fields))
				{
					return null;
				}

				// The flags are the lower 16 bits of the TTL (RFC 6891, Sec. 6.1.3).
				if ((DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(fields) is DnsRecordType.Opt)
				{
					return (DnsEdnsFlags)BinaryPrimitives.ReadUInt16BigEndian(fields.Slice(6));
				}

				if (!reader.TryReadBytes(BinaryPrimitives.ReadUInt16BigEndian(fields.Slice(8)), out _))
				{
					return null;
				}
			}

			return null;
		}
	}

	private static ushort GetFlags(DnsMessage message, int responseCode)
	{
		int flags = (byte)message.Opcode << 11 | responseCode & 0xF
			| (message.IsResponse ? ResponseFlag : 0)
			| (message.IsAuthoritativeAnswer ? AuthoritativeAnswerFlag : 0)
			| (message.IsTruncated ? TruncatedFlag : 0)
			| (message.IsRecursionDesired ? RecursionDesiredFlag : 0)
			| (message.IsRecursionAvailable ? RecursionAvailableFlag : 0)
			| (message.IsAuthenticData ? AuthenticDataFlag : 0)
			| (message.IsCheckingDisabled ? CheckingDisabledFlag : 0);
		return (ushort)flags;
	}

	private static void WriteRecords(ref DnsWireWriter writer, IReadOnlyList<DnsResourceRecord> records, int start, int end)
	{
		for (int i = start; i < end; ++i)
		{
			DnsResourceRecord record = records[i];
			writer.WriteName(record.Name, compress: true);
			writer.WriteUInt16((ushort)record.Type);
			writer.WriteUInt16((ushort)record.Class);
			writer.WriteUInt32(WireSeconds.Of(record.Ttl));
			int lengthOffset = writer.BeginLength();
			record.Data.Write(ref writer);
			writer.EndLength(lengthOffset);
		}
	}

	private static DnsMessage? Read(ref DnsWireReader reader)
	{
		if (!reader.TryReadBytes(DnsWireReader.HeaderLength, out ReadOnlySpan<byte> header))
		{
			return null;
		}

		ushort id = BinaryPrimitives.ReadUInt16BigEndian(header);
		int flags = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(2));
		int questionCount = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(4));
		int answerCount = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(6));
		int authorityCount = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(8));
		int additionalCount = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(10));

		// Counts that the rest of the message cannot hold fail before anything is allocated for them.
		if (questionCount * MinQuestionLength + (answerCount + authorityCount + additionalCount) * MinRecordLength > reader.Remaining)
		{
			reader.Fail("The section counts need more entries than the message can hold.");
			return null;
		}

		DnsQuestion[] questions = questionCount is 0 ? [] : new DnsQuestion[questionCount];

		for (int i = 0; i < questions.Length; ++i)
		{
			if (!TryReadQuestion(ref reader, out questions[i]))
			{
				return null;
			}
		}

		DnsOpcode opcode = (DnsOpcode)(flags >> 11 & 0xF);
		// In an UPDATE, data of class NONE is in the class of the zone (RFC 2136, Sec. 2.5.4); other messages read it as class IN.
		DnsClass noneClass = opcode is DnsOpcode.Update && questions is [{ Class: DnsClass zoneClass }] ? zoneClass : DnsClass.Internet;
		DnsEdns? edns = null;
		int upperResponseCode = 0;

		if (ReadRecords(ref reader, answerCount, isAdditional: false, noneClass, ref edns, ref upperResponseCode) is not { } answers
			|| ReadRecords(ref reader, authorityCount, isAdditional: false, noneClass, ref edns, ref upperResponseCode) is not { } authorities
			|| ReadRecords(ref reader, additionalCount, isAdditional: true, noneClass, ref edns, ref upperResponseCode) is not { } additionals)
		{
			return null;
		}

		if (reader.Remaining is not 0)
		{
			reader.Fail("The message has bytes after its last section.");
			return null;
		}

		return new DnsMessage(questions, answers, authorities, additionals)
		{
			Id = id,
			IsResponse = (flags & ResponseFlag) is not 0,
			Opcode = opcode,
			IsAuthoritativeAnswer = (flags & AuthoritativeAnswerFlag) is not 0,
			IsTruncated = (flags & TruncatedFlag) is not 0,
			IsRecursionDesired = (flags & RecursionDesiredFlag) is not 0,
			IsRecursionAvailable = (flags & RecursionAvailableFlag) is not 0,
			IsAuthenticData = (flags & AuthenticDataFlag) is not 0,
			IsCheckingDisabled = (flags & CheckingDisabledFlag) is not 0,
			// The extended response code takes its upper 8 bits from the OPT record (RFC 6891, Sec. 6.1.3).
			ResponseCode = (DnsResponseCode)(upperResponseCode << 4 | flags & 0xF),
			Edns = edns
		};
	}

	private static bool TryReadQuestion(ref DnsWireReader reader, out DnsQuestion question)
	{
		if (reader.TryReadName(out DnsName name) && reader.TryReadUInt16(out ushort type) && reader.TryReadUInt16(out ushort @class))
		{
			question = new DnsQuestion(name, (DnsRecordType)type, (DnsClass)@class);
			return true;
		}

		question = default;
		return false;
	}

	// Reads count records, whose data in class NONE is in noneClass. The OPT record goes into edns and its upper response code bits into upperResponseCode (RFC 6891, Sec. 6.1.1).
	private static DnsResourceRecord[]? ReadRecords(ref DnsWireReader reader, int count, bool isAdditional, DnsClass noneClass, ref DnsEdns? edns, ref int upperResponseCode)
	{
		// Allocated at the first record that is not OPT, so that an additional section that holds only the OPT record allocates no array.
		DnsResourceRecord[]? records = null;
		int index = 0;

		for (int i = 0; i < count; ++i)
		{
			if (!reader.TryReadName(out DnsName name) || !reader.TryReadBytes(RecordFieldsLength, out ReadOnlySpan<byte> fields))
			{
				return null;
			}

			DnsRecordType type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(fields);
			ushort @class = BinaryPrimitives.ReadUInt16BigEndian(fields.Slice(2));
			uint ttl = BinaryPrimitives.ReadUInt32BigEndian(fields.Slice(4));
			int length = BinaryPrimitives.ReadUInt16BigEndian(fields.Slice(8));

			if (length > reader.Remaining)
			{
				reader.Fail("The RDATA length runs past the end of the message.");
				return null;
			}

			reader.BeginRdata(length);

			if (type is DnsRecordType.Opt)
			{
				string? problem = !isAdditional ? "An OPT record is outside the additional section."
					: edns is not null ? "The message has more than one OPT record."
					: !name.IsRoot ? "The owner of the OPT record is not the root."
					: null;

				if (problem is not null)
				{
					reader.Fail(problem);
					return null;
				}

				edns = DnsEdns.Read(ref reader, @class, ttl);

				if (edns is null || !reader.EndRdata())
				{
					return null;
				}

				upperResponseCode = (int)(ttl >> 24);
				continue;
			}

			DnsRecordData? data = ReadData(ref reader, type, (DnsClass)@class, noneClass, length);

			if (data is null || !reader.EndRdata())
			{
				return null;
			}

			// The TTL is unsigned (RFC 8767, Sec. 4).
			TimeSpan timeToLive = TimeSpan.FromSeconds(ttl);
			records ??= new DnsResourceRecord[count - i];
			records[index++] = new DnsResourceRecord(name, timeToLive, data) { Class = (DnsClass)@class };
		}

		if (records is null)
		{
			return [];
		}

		return index == records.Length ? records : records.AsSpan(0, index).ToArray();
	}

	private static DnsRecordData? ReadData(ref DnsWireReader reader, DnsRecordType type, DnsClass @class, DnsClass noneClass, int length)
	{
		// Dynamic updates give records of class ANY or NONE empty data, whatever their type (RFC 2136, Sec. 2.4 and 2.5).
		if (length is 0 && @class is DnsClass.Any or DnsClass.None)
		{
			return new DnsUnknownData(type, ReadOnlyMemory<byte>.Empty);
		}

		// These types take another form in other classes, such as the A record of class CH.
		bool isInternet = (@class is DnsClass.None ? noneClass : @class) is DnsClass.Internet;

		return type switch
		{
			DnsRecordType.A when isInternet => DnsAddressData.Read(ref reader, ipv6: false),
			DnsRecordType.Aaaa when isInternet => DnsAddressData.Read(ref reader, ipv6: true),
			DnsRecordType.Ns => DnsNsData.Read(ref reader),
			DnsRecordType.CName => DnsCNameData.Read(ref reader),
			DnsRecordType.Ptr => DnsPtrData.Read(ref reader),
			DnsRecordType.Mx => DnsMxData.Read(ref reader),
			DnsRecordType.Srv when isInternet => DnsSrvData.Read(ref reader),
			// TXT data holds at least one string (RFC 1035, Sec. 3.3.14); data without any is kept as it is.
			DnsRecordType.Txt when length is not 0 => DnsTxtData.Read(ref reader),
			DnsRecordType.Soa => DnsSoaData.Read(ref reader),
			_ => DnsUnknownData.Read(ref reader, type, isInternet)
		};
	}
}
