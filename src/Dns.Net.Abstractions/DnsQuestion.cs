using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents a question (RFC 1035, Sec. 4.1.2): a name, and the type and class of the records asked for.
/// </summary>
/// <param name="Name">The name asked about.</param>
/// <param name="Type">The type of the records asked for.</param>
/// <param name="Class">The class of the records asked for; <see cref="DnsClass.Internet" /> by default.</param>
public readonly record struct DnsQuestion(DnsName Name, DnsRecordType Type, DnsClass Class = DnsClass.Internet)
{
	/// <summary>
	/// Initializes a question of class <see cref="DnsClass.Internet" /> about the root name.
	/// </summary>
	/// <remarks>The <see langword="default" /> value, unlike this one, has class 0.</remarks>
	public DnsQuestion() : this(DnsName.Root, default)
	{
	}

	/// <summary>
	/// Returns the question as dig shows it, without the leading semicolon, such as <c>example.com. IN A</c>.
	/// </summary>
	/// <returns>The question in presentation format.</returns>
	public override string ToString()
	{
		StringBuilder builder = new();
		Name.AppendAbsolute(builder);
		builder.Append($" {Class.Mnemonic} {Type.Mnemonic}");
		return builder.ToString();
	}
}
