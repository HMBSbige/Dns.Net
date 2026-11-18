using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents a DNS message (RFC 1035, Sec. 4.1): a header, and the question, answer, authority and additional sections.
/// </summary>
/// <remarks>
/// <para>
/// A message is immutable: derive another with a <see langword="with" /> expression. Each section holds a copy of the list that it is set to.
/// The address of a <see cref="DnsAddressData" /> is shared and must not be changed, such as by setting <see cref="IPAddress.ScopeId" />, as that changes the equality of every message that holds it.
/// Equality ignores the case of ASCII letters in names, except within <see cref="DnsUnknownData" />.
/// </para>
/// <para>
/// Encoding compresses names regardless of case (RFC 4343, Sec. 4.1), so a decoded name may take the case of an earlier name with the same suffix.
/// A decoded message may encode to more bytes than it was decoded from, as names that decoding expands are written in full.
/// </para>
/// <para>Decoding rejects malformed input, so it is safe for untrusted data; <see cref="TryDecode" /> describes what it checks.</para>
/// </remarks>
public sealed record DnsMessage
{
	/// <summary>
	/// The maximum length of a message in wire format, in bytes (RFC 1035, Sec. 4.2.2).
	/// </summary>
	public const int MaxEncodedLength = 65535;

	private readonly DnsQuestion[] _questions = [];

	private readonly DnsResourceRecord[] _answers = [];

	private readonly DnsResourceRecord[] _authorities = [];

	private readonly DnsResourceRecord[] _additionals = [];

	/// <summary>
	/// Initializes an empty query with identifier 0 and no flags set.
	/// </summary>
	public DnsMessage()
	{
	}

	// Takes ownership of the arrays, which no caller can reach, so that decoding need not copy them again.
	internal DnsMessage(DnsQuestion[] questions, DnsResourceRecord[] answers, DnsResourceRecord[] authorities, DnsResourceRecord[] additionals)
	{
		_questions = questions;
		_answers = answers;
		_authorities = authorities;
		_additionals = additionals;
	}

	/// <summary>
	/// Gets the identifier that a response copies from its query (RFC 1035, Sec. 4.1.1).
	/// </summary>
	public ushort Id { get; init; }

	/// <summary>
	/// Gets a value that indicates whether the message is a response, the QR bit.
	/// </summary>
	public bool IsResponse { get; init; }

	/// <summary>
	/// Gets the kind of message, the OPCODE.
	/// </summary>
	public DnsOpcode Opcode { get; init; }

	/// <summary>
	/// Gets a value that indicates whether the responding server is an authority for the name in the question section, the AA bit.
	/// </summary>
	public bool IsAuthoritativeAnswer { get; init; }

	/// <summary>
	/// Gets a value that indicates whether the message was cut short to fit the transport, the TC bit.
	/// </summary>
	public bool IsTruncated { get; init; }

	/// <summary>
	/// Gets a value that indicates whether a query asks the server to pursue it recursively, the RD bit, which the response copies.
	/// </summary>
	public bool IsRecursionDesired { get; init; }

	/// <summary>
	/// Gets a value that indicates whether the server supports recursive queries, the RA bit.
	/// </summary>
	public bool IsRecursionAvailable { get; init; }

	/// <summary>
	/// Gets a value that indicates whether the server considers the answer and authority sections authentic, the AD bit (RFC 4035, Sec. 3.2.3; RFC 6840, Sec. 5.8).
	/// </summary>
	public bool IsAuthenticData { get; init; }

	/// <summary>
	/// Gets a value that indicates whether the client accepts data that the server has not validated, the CD bit (RFC 4035, Sec. 3.2.2), which the response copies.
	/// </summary>
	public bool IsCheckingDisabled { get; init; }

	/// <summary>
	/// Gets the response code, with all 12 bits of the extended RCODE (RFC 6891, Sec. 6.1.3).
	/// </summary>
	/// <remarks>A value greater than 15 needs <see cref="Edns" />, which holds the upper 8 bits.</remarks>
	public DnsResponseCode ResponseCode { get; init; }

	/// <summary>
	/// Gets the question section; empty by default.
	/// </summary>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	public IReadOnlyList<DnsQuestion> Questions { get => _questions; init => _questions = ListCopy.ToArray(value, nameof(Questions)); }

	/// <summary>
	/// Gets the answer section; empty by default.
	/// </summary>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The value set has a <see langword="null" /> record.</exception>
	public IReadOnlyList<DnsResourceRecord> Answers { get => _answers; init => _answers = ListCopy.ToArray(value, nameof(Answers)); }

	/// <summary>
	/// Gets the authority section; empty by default.
	/// </summary>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The value set has a <see langword="null" /> record.</exception>
	public IReadOnlyList<DnsResourceRecord> Authorities { get => _authorities; init => _authorities = ListCopy.ToArray(value, nameof(Authorities)); }

	/// <summary>
	/// Gets the additional section, without the OPT pseudo-record, which <see cref="Edns" /> represents; empty by default.
	/// </summary>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The value set has a <see langword="null" /> record.</exception>
	public IReadOnlyList<DnsResourceRecord> Additionals { get => _additionals; init => _additionals = ListCopy.ToArray(value, nameof(Additionals)); }

	/// <summary>
	/// Gets the EDNS data that the OPT pseudo-record carries, or <see langword="null" /> for a message without EDNS.
	/// </summary>
	public DnsEdns? Edns { get; init; }

	/// <summary>
	/// Creates a query that asks <paramref name="question" /> with recursion desired and default EDNS.
	/// </summary>
	/// <param name="question">The question to ask.</param>
	/// <returns>A query with identifier 0 and <paramref name="question" /> as its only question.</returns>
	public static DnsMessage CreateQuery(DnsQuestion question)
	{
		return new DnsMessage
		{
			IsRecursionDesired = true,
			Questions = [question],
			Edns = new DnsEdns()
		};
	}

	/// <summary>
	/// Creates the start of a response to the message.
	/// </summary>
	/// <remarks>
	/// The response copies the identifier, the opcode, the RD and CD bits and the questions, and has no records.
	/// If the message has EDNS, so does the response, with the default payload size and only the DO flag of the message.
	/// </remarks>
	/// <returns>A response with no error, to be completed with a <see langword="with" /> expression.</returns>
	public DnsMessage CreateResponse()
	{
		return new DnsMessage(_questions, [], [], [])
		{
			Id = Id,
			IsResponse = true,
			Opcode = Opcode,
			IsRecursionDesired = IsRecursionDesired,
			IsCheckingDisabled = IsCheckingDisabled,
			Edns = Edns is null ? null : new DnsEdns { Flags = Edns.Flags & DnsEdnsFlags.DnssecOk }
		};
	}

	/// <summary>
	/// Creates the FORMERR or NOTIMP response that a server sends for a request that cannot be decoded.
	/// </summary>
	/// <remarks>
	/// A request of opcode <see cref="DnsOpcode.Query" />, <see cref="DnsOpcode.Notify" /> or <see cref="DnsOpcode.Update" /> gets FORMERR, with its question and EDNS where they can be read; any other gets NOTIMP (RFC 8906, Sec. 7).
	/// The method returns <see langword="null" /> for fewer than 12 bytes and for a response, so that two servers cannot keep answering each other.
	/// </remarks>
	/// <param name="request">The bytes of the request, as received.</param>
	/// <returns>The response, or <see langword="null" /> when no response is to be sent.</returns>
	public static DnsMessage? CreateErrorResponse(ReadOnlySpan<byte> request)
	{
		return DnsMessageCodec.CreateErrorResponse(request);
	}

	/// <summary>
	/// Determines whether the message is a response to <paramref name="query" />, as a transport checks before it accepts one.
	/// </summary>
	/// <remarks>
	/// The message must be a response with the identifier, opcode and questions of <paramref name="query" />, whose names compare regardless of case.
	/// A FORMERR or NOTIMP response, or one to an UPDATE, may have no questions instead.
	/// </remarks>
	/// <param name="query">The query.</param>
	/// <returns><see langword="true" /> if the message answers <paramref name="query" />; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="query" /> is <see langword="null" />.</exception>
	public bool IsResponseTo(DnsMessage query)
	{
		ArgumentNullException.ThrowIfNull(query);

		return IsResponse
			&& !query.IsResponse
			&& Id == query.Id
			&& Opcode == query.Opcode
			&& (ListEquality.SequenceEqual(Questions, query.Questions) || _questions.Length is 0 && (Opcode is DnsOpcode.Update || ResponseCode is DnsResponseCode.FormatError or DnsResponseCode.NotImplemented));
	}

	/// <summary>
	/// Tries to write the message in wire format, with names compressed.
	/// </summary>
	/// <param name="destination">The buffer that receives the message; <see cref="MaxEncodedLength" /> bytes always suffice.</param>
	/// <param name="bytesWritten">The length of the message in bytes, or 0 on failure.</param>
	/// <returns><see langword="true" /> if <paramref name="destination" /> is long enough; otherwise, <see langword="false" />, with <paramref name="destination" /> unchanged.</returns>
	/// <exception cref="InvalidOperationException">
	/// <see cref="Opcode" /> or <see cref="ResponseCode" /> is out of range, a section has more than 65535 entries, or the message would be longer than <see cref="MaxEncodedLength" /> bytes.
	/// </exception>
	public bool TryEncode(Span<byte> destination, out int bytesWritten)
	{
		if (destination.Length >= MaxEncodedLength)
		{
			bytesWritten = DnsMessageCodec.Encode(this, destination.Slice(0, MaxEncodedLength));
			return true;
		}

		// Encoding in full first tells a short destination from a message too long for any, and leaves destination unchanged on failure.
		byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxEncodedLength);

		try
		{
			int length = DnsMessageCodec.Encode(this, buffer.AsSpan(0, MaxEncodedLength));

			if (buffer.AsSpan(0, length).TryCopyTo(destination))
			{
				bytesWritten = length;
				return true;
			}

			bytesWritten = 0;
			return false;
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	/// <summary>
	/// Writes the message in wire format, with names compressed.
	/// </summary>
	/// <returns>The message in wire format.</returns>
	/// <exception cref="InvalidOperationException">
	/// <see cref="Opcode" /> or <see cref="ResponseCode" /> is out of range, a section has more than 65535 entries, or the message would be longer than <see cref="MaxEncodedLength" /> bytes.
	/// </exception>
	public byte[] Encode()
	{
		byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxEncodedLength);

		try
		{
			int length = DnsMessageCodec.Encode(this, buffer.AsSpan(0, MaxEncodedLength));
			return buffer.AsSpan(0, length).ToArray();
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	/// <summary>
	/// Reads a message in wire format.
	/// </summary>
	/// <remarks><see cref="TryDecode" /> describes what decoding accepts.</remarks>
	/// <param name="source">The whole message and nothing else.</param>
	/// <returns>The message.</returns>
	/// <exception cref="InvalidDataException"><paramref name="source" /> is not a well-formed message.</exception>
	public static DnsMessage Decode(ReadOnlySpan<byte> source)
	{
		DnsMessage? message = DnsMessageCodec.Decode(source, out string? error);
		return message ?? ThrowHelper.ThrowInvalidData<DnsMessage>(error);
	}

	/// <summary>
	/// Tries to read a message in wire format, without throwing on malformed input.
	/// </summary>
	/// <remarks>
	/// <para>
	/// <paramref name="source" /> may be at most <see cref="MaxEncodedLength" /> bytes long.
	/// Decoding checks the data of A, AAAA and SRV records in class IN, and of NS, CNAME, PTR, MX, SOA and TXT records.
	/// The data of most other types, such as SVCB or CAA, becomes <see cref="DnsUnknownData" /> unchecked, for the caller to check, such as with <see cref="DnsName.TryDecode" />.
	/// </para>
	/// <para>A server answers a request that fails to decode with <see cref="CreateErrorResponse" />.</para>
	/// </remarks>
	/// <param name="source">The whole message and nothing else.</param>
	/// <param name="message">When the method returns <see langword="true" />, the message; otherwise, <see langword="null" />.</param>
	/// <returns><see langword="true" /> if <paramref name="source" /> is a well-formed message; otherwise, <see langword="false" />.</returns>
	public static bool TryDecode(ReadOnlySpan<byte> source, [NotNullWhen(true)] out DnsMessage? message)
	{
		message = DnsMessageCodec.Decode(source, out _);
		return message is not null;
	}

	/// <summary>
	/// Determines whether <paramref name="other" /> has the same header fields, EDNS data and sections.
	/// </summary>
	/// <param name="other">The message to compare with.</param>
	/// <returns><see langword="true" /> if the messages are equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsMessage? other)
	{
		if (ReferenceEquals(this, other))
		{
			return true;
		}

		return other is not null
			&& Id == other.Id
			&& IsResponse == other.IsResponse
			&& Opcode == other.Opcode
			&& IsAuthoritativeAnswer == other.IsAuthoritativeAnswer
			&& IsTruncated == other.IsTruncated
			&& IsRecursionDesired == other.IsRecursionDesired
			&& IsRecursionAvailable == other.IsRecursionAvailable
			&& IsAuthenticData == other.IsAuthenticData
			&& IsCheckingDisabled == other.IsCheckingDisabled
			&& ResponseCode == other.ResponseCode
			&& Edns == other.Edns
			&& ListEquality.SequenceEqual(Questions, other.Questions)
			&& ListEquality.SequenceEqual(Answers, other.Answers)
			&& ListEquality.SequenceEqual(Authorities, other.Authorities)
			&& ListEquality.SequenceEqual(Additionals, other.Additionals);
	}

	/// <summary>
	/// Returns a hash code consistent with <see cref="Equals(DnsMessage)" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(Id);
		hash.Add(IsResponse);
		hash.Add(Opcode);
		hash.Add(IsAuthoritativeAnswer);
		hash.Add(IsTruncated);
		hash.Add(IsRecursionDesired);
		hash.Add(IsRecursionAvailable);
		hash.Add(IsAuthenticData);
		hash.Add(IsCheckingDisabled);
		hash.Add(ResponseCode);
		hash.Add(Edns);
		ListEquality.AddTo(ref hash, Questions);
		ListEquality.AddTo(ref hash, Answers);
		ListEquality.AddTo(ref hash, Authorities);
		ListEquality.AddTo(ref hash, Additionals);
		return hash.ToHashCode();
	}

	/// <summary>
	/// Returns the message as dig shows it: the header, the OPT pseudosection if the message has EDNS, and the sections that are not empty.
	/// </summary>
	/// <remarks>The additional count includes the OPT record, as on the wire. The sections of an UPDATE take the names of RFC 2136, Sec. 2.</remarks>
	/// <returns>The message in presentation format, with the lines separated by <see cref="Environment.NewLine" />.</returns>
	public override string ToString()
	{
		StringBuilder builder = new();
		builder.Append($";; ->>HEADER<<- opcode: {Opcode.Mnemonic}, status: {ResponseCode.Mnemonic}, id: {Id}");
		builder.AppendLine().Append(";; flags:");
		AppendFlag(builder, IsResponse, "qr");
		AppendFlag(builder, IsAuthoritativeAnswer, "aa");
		AppendFlag(builder, IsTruncated, "tc");
		AppendFlag(builder, IsRecursionDesired, "rd");
		AppendFlag(builder, IsRecursionAvailable, "ra");
		AppendFlag(builder, IsAuthenticData, "ad");
		AppendFlag(builder, IsCheckingDisabled, "cd");
		builder.Append($"; QUERY: {Questions.Count}, ANSWER: {Answers.Count}, AUTHORITY: {Authorities.Count}, ADDITIONAL: {Additionals.Count + (Edns is null ? 0 : 1)}");

		if (Edns is not null)
		{
			builder.AppendLine().AppendLine().Append(";; OPT PSEUDOSECTION:").AppendLine();
			Edns.AppendTo(builder);
		}

		bool isUpdate = Opcode is DnsOpcode.Update;

		if (Questions.Count is not 0)
		{
			builder.AppendLine().AppendLine().Append(isUpdate ? ";; ZONE SECTION:" : ";; QUESTION SECTION:");

			for (int i = 0; i < Questions.Count; ++i)
			{
				builder.AppendLine().Append($";{Questions[i]}");
			}
		}

		AppendSection(builder, isUpdate ? ";; PREREQUISITE SECTION:" : ";; ANSWER SECTION:", Answers);
		AppendSection(builder, isUpdate ? ";; UPDATE SECTION:" : ";; AUTHORITY SECTION:", Authorities);
		AppendSection(builder, ";; ADDITIONAL SECTION:", Additionals);
		return builder.ToString();
	}

	private static void AppendFlag(StringBuilder builder, bool value, string name)
	{
		if (value)
		{
			builder.Append(' ').Append(name);
		}
	}

	private static void AppendSection(StringBuilder builder, string title, IReadOnlyList<DnsResourceRecord> records)
	{
		if (records.Count is 0)
		{
			return;
		}

		builder.AppendLine().AppendLine().Append(title);

		for (int i = 0; i < records.Count; ++i)
		{
			builder.AppendLine().Append(records[i]);
		}
	}
}
