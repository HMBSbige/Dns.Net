using System.Globalization;
using System.Net;

namespace Dns.Net.Abstractions;

// The mnemonics that master files and dig show for protocol numbers.
internal static class DnsMnemonics
{
	extension(DnsRecordType type)
	{
		// TYPE followed by the number for a type without a mnemonic (RFC 3597, Sec. 5).
		public string Mnemonic => type switch
		{
			DnsRecordType.A => "A",
			DnsRecordType.Ns => "NS",
			DnsRecordType.CName => "CNAME",
			DnsRecordType.Soa => "SOA",
			DnsRecordType.Ptr => "PTR",
			DnsRecordType.HInfo => "HINFO",
			DnsRecordType.Mx => "MX",
			DnsRecordType.Txt => "TXT",
			DnsRecordType.Sig => "SIG",
			DnsRecordType.Aaaa => "AAAA",
			DnsRecordType.Srv => "SRV",
			DnsRecordType.Naptr => "NAPTR",
			DnsRecordType.DName => "DNAME",
			DnsRecordType.Opt => "OPT",
			DnsRecordType.Ds => "DS",
			DnsRecordType.Rrsig => "RRSIG",
			DnsRecordType.Nsec => "NSEC",
			DnsRecordType.DnsKey => "DNSKEY",
			DnsRecordType.Nsec3 => "NSEC3",
			DnsRecordType.Tlsa => "TLSA",
			DnsRecordType.Svcb => "SVCB",
			DnsRecordType.Https => "HTTPS",
			DnsRecordType.Tsig => "TSIG",
			DnsRecordType.Ixfr => "IXFR",
			DnsRecordType.Axfr => "AXFR",
			DnsRecordType.Any => "ANY",
			DnsRecordType.Caa => "CAA",
			_ => $"TYPE{(ushort)type}"
		};
	}

	extension(DnsClass @class)
	{
		// CLASS followed by the number for a class without a mnemonic (RFC 3597, Sec. 5).
		public string Mnemonic => @class switch
		{
			DnsClass.Internet => "IN",
			DnsClass.Chaos => "CH",
			DnsClass.Hesiod => "HS",
			DnsClass.None => "NONE",
			DnsClass.Any => "ANY",
			_ => $"CLASS{(ushort)@class}"
		};
	}

	extension(DnsOpcode opcode)
	{
		public string Mnemonic => opcode switch
		{
			DnsOpcode.Query => "QUERY",
			DnsOpcode.Status => "STATUS",
			DnsOpcode.Notify => "NOTIFY",
			DnsOpcode.Update => "UPDATE",
			_ => ((byte)opcode).ToString(CultureInfo.InvariantCulture)
		};
	}

	extension(DnsResponseCode code)
	{
		public string Mnemonic => (ushort)code switch
		{
			0 => "NOERROR",
			1 => "FORMERR",
			2 => "SERVFAIL",
			3 => "NXDOMAIN",
			4 => "NOTIMP",
			5 => "REFUSED",
			6 => "YXDOMAIN",
			7 => "YXRRSET",
			8 => "NXRRSET",
			9 => "NOTAUTH",
			10 => "NOTZONE",
			16 => "BADVERS",
			23 => "BADCOOKIE",
			_ => ((ushort)code).ToString(CultureInfo.InvariantCulture)
		};
	}

	extension(DnsEdnsOptionCode code)
	{
		public string Mnemonic => code switch
		{
			DnsEdnsOptionCode.Nsid => "NSID",
			DnsEdnsOptionCode.ClientSubnet => "CLIENT-SUBNET",
			DnsEdnsOptionCode.Expire => "EXPIRE",
			DnsEdnsOptionCode.Cookie => "COOKIE",
			DnsEdnsOptionCode.TcpKeepalive => "TCP-KEEPALIVE",
			DnsEdnsOptionCode.Padding => "PADDING",
			DnsEdnsOptionCode.ExtendedDnsError => "EDE",
			_ => $"OPT={(ushort)code}"
		};
	}
}
