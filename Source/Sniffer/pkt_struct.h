#pragma once
//#define _XKEYCHECK_H
#define WPCAP
#define HAVE_REMOTE
#include <WinSock2.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <iterator>
#include <bitset>
#include <string>
#include <cstring>
#include <ctime>
#include <conio.h>
#include "pcap.h"

//TODO: CODE REVIEW
//TODO: bits as Wireshark

template<typename res_type, typename src_type>
res_type pointer_cast(src_type *p, std::size_t offset = 0U)
{
	return reinterpret_cast<res_type>(reinterpret_cast<u_char*>(p) + offset);
}
template<typename res_type, typename src_type>
res_type pointer_cast(const src_type* p, std::size_t offset = 0U)
{
	return reinterpret_cast<res_type>(reinterpret_cast<const u_char*>(p) + offset);
}

template<typename res_type, typename src_type>
res_type s_cast(src_type param) { return static_cast<res_type>(param); }
template<typename res_type, typename src_type>
res_type r_cast(src_type param) { return reinterpret_cast<res_type>(param); }

constexpr char nl = '\n';
const char *indent[6] = { "", "\t", "\t\t", "\t\t\t", "\t\t\t\t", "\t\t\t\t\t" };

#define hexbase std::hex << std::showbase
#define decnobase std::dec << std::noshowbase

std::stringstream sstreambuf;
std::ofstream capture_dump;

class STATISTICS {
public:
	void Reset() {
		std::memset(s_cast<void*>(count), 0, sizeof(count));
		pkt_average_len = 0.0;
		pkt_min_len = 1'000'000;
		pkt_count = pkt_max_len = 0;
		active = false;
	}
	STATISTICS() { Reset(); }
	void Update(std::size_t pkt_len) {
		active = true;
		++pkt_count;
		pkt_total_len += pkt_len;
		if (pkt_len < pkt_min_len) pkt_min_len = pkt_len;
		if (pkt_len > pkt_max_len) pkt_max_len = pkt_len;
		pkt_average_len = pkt_total_len / s_cast<decltype(pkt_average_len)>(pkt_count);
		for (std::size_t i{}; i < 5; ++i) {
			if (pkt_len <= len[i][1]) {
				++count[i]; break;
			}
		}
	}
	template<typename stream>
	void Print(stream &s) {
		if (active) {
			s << nl << "Packet lengths statistics: "
				<< nl << "Count: " << pkt_count << " packets"
				<< nl << "Total: " << pkt_total_len << " bytes"
				<< nl << "Min: " << pkt_min_len << " bytes"
				<< nl << "Max: " << pkt_max_len << " bytes"
				<< nl << "Average: " << pkt_average_len << " bytes";
			for (std::size_t i{}; i < 5; ++i) {
				s << nl << "From " << len[i][0] 
					<< " to " << len[i][1] << " bytes" << ": " << count[i] << " packets";
			}
		}
	}
	std::size_t pkt_count;
	std::size_t pkt_min_len;
	std::size_t pkt_max_len;
	double pkt_total_len;
	double pkt_average_len;

	//enum CATEGORY{ COUNT_BETWEEN_0_and_100, COUNT_BETWEEN_101_and_1000,
	//	COUNT_BETWEEN_1001_and_2500, COUNT_BETWEEN_2501_and_5000, COUNT_GREATER_5001
	//};
	static constexpr std::size_t len[5][5]{ {0, 100}, {101, 1000}, {1001, 2500}, {2501, 5000}, {5001, 1'000'000} };
	std::size_t count[5]{};
	bool active;
} statistics;

struct PROTOCOL {
	static constexpr u_short IPv4 = 0x0800, ARP = 0x0806, IPv6 = 0x86DD,
		ICMP = 0x1, IGMP = 0x2, TCP = 0x6, UDP = 0x11, ICMPv6 = 0x3A;
};


struct PORT {
	static constexpr std::size_t FTP = 21U, HTTP = 80U, SSDP = 1900U;
};


struct MAC_ADDR {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
	static constexpr std::size_t SIZE = 6U * sizeof(u_char);
};
struct IPv4_ADDR {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	static constexpr std::size_t SIZE = 4U * sizeof(u_char);
};
struct IPv6_ADDR {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
	u_char byte7;
	u_char byte8;
	u_char byte9;
	u_char byte10;
	u_char byte11;
	u_char byte12;
	u_char byte13;
	u_char byte14;
	u_char byte15;
	u_char byte16;
	static constexpr std::size_t SIZE = 16U * sizeof(u_char);
};
struct ETHERNET_HEADER {
	MAC_ADDR dest;//6 bytes (Destination MAC-address)
	MAC_ADDR src;//6 bytes (Source MAC-address)
	u_short proto;//2 bytes (Protocol type)
	//Optional: padding

	static constexpr std::size_t SIZE = 2U * MAC_ADDR::SIZE + sizeof(u_short);
};
struct ARP_HEADER {
	u_short h_type;//2 bytes (Hardware type)
	u_short proto;//2 bytes (Protocol type)
	u_char h_len;//1 bytes (Hardware length)
	u_char p_len;//1 bytes (Protocol length)
	u_short opcode;//2 bytes (Operation)
	MAC_ADDR sha;//6 bytes (Sender hardware address)
	IPv4_ADDR spa;//4 bytes (Sender protocol address)
	MAC_ADDR tha;//6 bytes (Target hardware address)
	IPv4_ADDR tpa;//4 bytes (Target protocol address)
	enum HARDWARE_TYPE {
		ETHERNET = 1, EXPERIMENTAL_ETHERNET = 2, AMATEUR_RADIO_AX25 = 3,
		PROTEON_PRONET_TOKEN_RING = 4, CHAOS = 5, IEEE_802_NETWORKS = 6, ARCNET = 7 
	};
	static constexpr std::size_t SIZE = 2U * IPv4_ADDR::SIZE
		+ 2U * MAC_ADDR::SIZE + 3U * sizeof(u_short) + 2U * sizeof(u_char);
};
struct IPv4_HEADER {
	u_char ver_hdrlen;//1 byte (Version (4 bits) + Internet header length (4 bits))
	u_char tos;//1 byte (Type Of service)
	u_short total_len;//2 bytes (Total length)
	u_short id;//2 bytes (Identification)
	u_short flags_offset;//2 bytes  (Flags (3 bits) + Fragment offset (13 bits))
	u_char ttl;//1 byte (Time to live)
	u_char proto;//1 byte  (Protocol)
	u_short checksum;//2 bytes (Header checksum)
	IPv4_ADDR src;//4 bytes (Source address)
	IPv4_ADDR dest;//4 bytes (Destination address)
	//Optional: options

	static constexpr std::size_t SIZE = 2U * IPv4_ADDR::SIZE 
		+ 4U * sizeof(u_short) + 4U * sizeof(u_char);
};
struct IPv6_HEADER {
	u_long ver_traff_label;//4 bytes (Version (4 bits) + Traffic class (8 bits) + Flow label (20 bits))
	u_short payload_len;//2 bytes (Payload length)
	u_char next_hdr;//1 byte (Next header)
	u_char hop_limit;//1 byte (Hop limit)
	IPv6_ADDR src;//16 bytes (Source address)
	IPv6_ADDR dest;//16 bytes (Destination address)
	//Optional: extension headers

	static constexpr std::size_t SIZE = sizeof(u_long) + sizeof(u_short) 
		+ 2U * sizeof(u_char) + 2U * IPv6_ADDR::SIZE;
};
struct ICMP_HEADER {
	u_char type;//1 byte (ICMP type)
	u_char code;//1 byte (ICMP subtype)
	u_short checksum;//2 bytes (Checksum)
	u_short identifier;//2 bytes (Identifier - echo reply, request; Unused - time exceeded) 
	u_short seq_num;//2 bytes (Sequence Number - echo reply, request; Unused - time exceeded) 
	enum TYPE {ECHO_REPLY = 0, ECHO_REQUEST = 8, TIME_EXCEEDED = 11};
	static constexpr std::size_t SIZE = 2U * sizeof(u_char) + 3U * sizeof(u_short);
};
struct IGMPv2_HEADER {
	u_char type;//1 byte (Type)
	u_char max_resp_time;//1 byte (Max Response Time)
	u_short checksum;//2 bytes (Header checksum)
	IPv4_ADDR mult_addr;//4 bytes (Multicast Address)
	enum MESSAGE_TYPE{MEMBERSHIP_QUERY = 0x11, MEMBERSHIP_REPORTv1 = 0x12, 
		MEMBERSHIP_REPORTv2 = 0x16, LEAVE_GROUP = 0x17};
	static constexpr std::size_t SIZE = 2U * sizeof(u_char) 
		+ sizeof(u_short) + IPv4_ADDR::SIZE;
};
struct UDP_HEADER {
	u_short src_port;//2 bytes (Source port)
	u_short dest_port;//2 bytes (Destination port)
	u_short total_len;//2 bytes (Total length)
	u_short checksum;//2 bytes (Checksum)
	static constexpr std::size_t SIZE = 4U * sizeof(u_short);
};
struct TCP_HEADER {
	u_short src_port;//2 bytes (Source Pprt)
	u_short dest_port;//2 bytes (Destination port)
	u_long seq_num;//4 bytes (Sequence number)
	u_long ack_num;//4 bytes (Ack number)
	u_short hdrlen_flags;//2 bytes (Header length (4 bits) + Reserved (6 bits) + Control bits (6 bits)
	u_short win_size;//2 bytes (Window size value)
	u_short checksum;//2 bytes (Checksum)
	u_short urg_pointer;//2 bytes (Urgent pointer)
	//Optional: options

	static constexpr std::size_t SIZE = 6U * sizeof(u_short) + 2U * sizeof(u_long);
};
struct HTTP_HEADER {};
struct FTP_HEADER {};


template <typename stream>
void print_data(stream &s, std::size_t i, std::size_t count, const u_char *data);

template<typename stream> 
void print_addr(stream &s, const MAC_ADDR &addr);
template<typename stream>
void print_addr(stream &s, const IPv4_ADDR &addr);
template<typename stream>
void print_addr(stream &s, const IPv6_ADDR &addr);

template <typename T>
void print_header(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<HTTP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<FTP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<ARP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<IGMPv2_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<ICMP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<TCP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<UDP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<IPv4_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<IPv6_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);
template <>
void print_header<ETHERNET_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr);

template <typename stream>
void print_data(stream &s, std::size_t i, std::size_t count, const u_char *data) {
	std::size_t j{};
	const std::size_t ABREAST = 16U;
	sstreambuf << indent[i] << "Data: " << nl;
	while (!false) {
		if (count >= ABREAST) {
			s << indent[i] << std::hex;
			for (j = 0; j < ABREAST; ++j)
				s << std::setw(2) << std::setfill('0') << s_cast<int>(data[j]) << ' ';
			s << std::dec << ' ';
			for (j = 0; j < ABREAST; ++j)
				s << (((data[j] == s_cast<u_char>('\r')) || (data[j] == s_cast<u_char>('\n')))
					? s_cast<u_char>(' ') : data[j]);
			s << nl;
			data += ABREAST; count -= ABREAST;
		}
		else if (count > 0) {
			s << indent[i] << std::hex;
			for (j = 0; j < count; ++j)
				s << std::setw(2) << std::setfill('0') << s_cast<int>(data[j]) << ' ';
			for (j = 0; j < ABREAST - count; ++j) s << "   ";
			s << std::dec << ' ';
			for (j = 0; j < count; ++j) 
				s << (((data[j] == s_cast<u_char>('\r')) || (data[j] == s_cast<u_char>('\n')))
					? s_cast<u_char>(' ') : data[j]);
			s << nl;
			return;
		}
		else return;
	}
}

template<typename stream>
void print_addr(stream &s, const MAC_ADDR &addr) {
	s << std::hex << s_cast<int>(addr.byte1) << ":" << s_cast<int>(addr.byte2) 
		<< ":" << s_cast<int>(addr.byte3) << ":" << s_cast<int>(addr.byte4) << ":" 
		<< s_cast<int>(addr.byte5) << ":" << s_cast<int>(addr.byte6) << std::dec;
}

template<typename stream>
void print_addr(stream &s, const IPv4_ADDR &addr) {
	s << s_cast<int>(addr.byte1) << "." << s_cast<int>(addr.byte2)
		<< "." << s_cast<int>(addr.byte3) << "." << s_cast<int>(addr.byte4);
}

template<typename stream>
void print_addr(stream &s, const IPv6_ADDR &addr) {
	s << std::hex << s_cast<int>(addr.byte1) << s_cast<int>(addr.byte2) << ':'
		<< s_cast<int>(addr.byte3) << s_cast<int>(addr.byte4) << ':'
		<< s_cast<int>(addr.byte5) << s_cast<int>(addr.byte6)  << ':'
		<< s_cast<int>(addr.byte7) << s_cast<int>(addr.byte8) << ':'
		<< s_cast<int>(addr.byte9) << s_cast<int>(addr.byte10) << ':'
		<< s_cast<int>(addr.byte11) << s_cast<int>(addr.byte12) << ':' 
		<< s_cast<int>(addr.byte13) << s_cast<int>(addr.byte14) << ':'
		<< s_cast<int>(addr.byte15) << s_cast<int>(addr.byte16) << std::dec;
}

template <>
void print_header<HTTP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr) {
	/*sstreambuf << indent[i] << "Hypertext Transfer Protocol (HTTP)" << nl;
	print_data(sstreambuf, i, pkt_len - offset, pointer_cast<const u_char *>(hdr, offset));*/
	// or
	using cc = const char*;
	cc http_head = pointer_cast<cc>(hdr, offset);
	cc http_body = std::strstr(http_head, "\r\n\r\n");
	sstreambuf << indent[i] << "Hypertext Transfer Protocol (HTTP)";
	//WARNING!!! BUG!!! HACK!!!
	if (!http_body) {
		sstreambuf << nl;
		print_data(sstreambuf, i, pkt_len - offset, r_cast<const u_char*>(http_head));
		return;
	}
	cc first = http_head, last{};
	do {
		sstreambuf << nl << indent[i];
		last = std::strchr(first, '\r');
		std::copy(first, last, std::ostream_iterator<char>(sstreambuf));
		sstreambuf << "\\r\\n";
		first = last + 2;
	} while ((first - 2) != http_body);
	sstreambuf << nl << indent[i] << "\\r\\n" << nl;
	http_body += 4;
	std::size_t http_body_size = pkt_len - (offset + (http_body - http_head));
	if (http_body_size)
		print_data(sstreambuf, i, http_body_size, r_cast<const u_char*>(http_body));
}

template<>
void print_header<FTP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr) {
	/*sstreambuf << indent[i] << "File Transfer Protocol (FTP)" << nl;
	print_data(sstreambuf, i, pkt_len - offset, pointer_cast<const u_char *>(hdr, offset));*/
	//or
	sstreambuf << indent[i] << "File Transfer Protocol (FTP)" << nl << indent[i];
	const char *first = pointer_cast<decltype(first)>(hdr, offset);
	std::copy(first, first + pkt_len - offset - 2, std::ostream_iterator<char>(sstreambuf));
	sstreambuf << "\\r\\n" << nl; 
}

template <>
void print_header<ARP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr)
{
	const ARP_HEADER *arp_hdr = pointer_cast<decltype(arp_hdr)>(hdr, offset);
	sstreambuf << indent[i] << "Address Resolution Protocol (ARP)" 
		<< nl << indent[i] << "Hardware type: ";
	u_short field = ntohs(arp_hdr->h_type);
	if (field == ARP_HEADER::HARDWARE_TYPE::ETHERNET)
		sstreambuf << "Ethernet (" << field;
	else if (field == ARP_HEADER::HARDWARE_TYPE::EXPERIMENTAL_ETHERNET)
		sstreambuf << "Experimental Ethernet (" << field;
	else if (field == ARP_HEADER::HARDWARE_TYPE::AMATEUR_RADIO_AX25)
		sstreambuf << "Amateur Radio AX.25 (" << field;
	else if (field == ARP_HEADER::HARDWARE_TYPE::PROTEON_PRONET_TOKEN_RING)
		sstreambuf << "Proteon ProNET Token Ring (" << field;
	else if (field == ARP_HEADER::HARDWARE_TYPE::CHAOS)
		sstreambuf << "Chaos (" << field;
	else if (field == ARP_HEADER::HARDWARE_TYPE::IEEE_802_NETWORKS)
		sstreambuf << "IEEE 802 Networks (" << field;
	else if (field == ARP_HEADER::HARDWARE_TYPE::ARCNET)
		sstreambuf << "ARCNET (" << field;
	else
		sstreambuf << "UNKNOWN (" << field;
	field = ntohs(arp_hdr->proto);
	sstreambuf << ")" << nl << indent[i] << "Protocol type: ";
	if (field == PROTOCOL::IPv4)
		sstreambuf << "IPv4 (" << hexbase << field << decnobase << ")";
	else 
		sstreambuf << "UNKNOWN (" << hexbase << field << decnobase << ")";
	sstreambuf << nl << indent[i] << "Hardware size: " << s_cast<int>(arp_hdr->h_len)
		<< nl << indent[i] << "Protocol size: " << s_cast<int>(arp_hdr->p_len)
		<< nl << indent[i] << "Opcode: ";
	field = ntohs(arp_hdr->opcode);
	sstreambuf << (((field == 1) || (field == 3)) ? "request" : "reply");
	sstreambuf << " (" << field << ")" << nl << indent[i] << "Sender MAC address: ";
	print_addr(sstreambuf, arp_hdr->sha);
	sstreambuf << nl << indent[i] << "Sender IP address : ";
	print_addr(sstreambuf, arp_hdr->spa);
	sstreambuf << nl << indent[i] << "Target MAC address: ";
	print_addr(sstreambuf, arp_hdr->tha);
	sstreambuf << nl << indent[i] << "Target IP address: ";
	print_addr(sstreambuf, arp_hdr->tpa);
	//Ethernet requires that all packets be at least 60 bytes
	if ((pkt_len != (offset + ARP_HEADER::SIZE)) && (pkt_len <= 60U)) {
		sstreambuf << nl << indent[i] << "Padding: ";
		for (std::size_t j{}; j < pkt_len - (offset + ARP_HEADER::SIZE); ++j)
			sstreambuf << "00 ";
	}
	sstreambuf << nl;
}

template <>
void print_header<IGMPv2_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr) {
	const IGMPv2_HEADER *igmp_hdr = pointer_cast<decltype(igmp_hdr)>(hdr, offset);
	std::size_t field = igmp_hdr->type;
	//WARNING: ONLY IGMP VERSION 2!!!
	sstreambuf << indent[i] << "Internet Group Management Protocol Version 2 (IGMPv2)"
		<< nl << indent[i] << "Type: " << ((field == IGMPv2_HEADER::MESSAGE_TYPE::LEAVE_GROUP)
			? "Leave Group" : (field == IGMPv2_HEADER::MESSAGE_TYPE::MEMBERSHIP_QUERY)
			? "Membership Query" : "Membership Report") << " (" << hexbase << field << decnobase << ")"
		<< nl << indent[i] << "Max response time: " << (igmp_hdr->max_resp_time / 10.0) << " sec ("
		<< hexbase << s_cast<int>(igmp_hdr->max_resp_time) << decnobase << ")"
		<< nl << indent[i] << "Header checksum: " << hexbase << ntohs(igmp_hdr->checksum) << decnobase
		<< nl << indent[i] << "Multicast address: ";
	print_addr(sstreambuf, igmp_hdr->mult_addr);
	//Ethernet requires that all packets be at least 60 bytes
	if ((pkt_len != (offset + IGMPv2_HEADER::SIZE)) /*&& (pkt_len <= 60U)*/) {
		sstreambuf << nl << indent[i] << "Padding: ";
		for (std::size_t j{}; j < pkt_len - (offset + IGMPv2_HEADER::SIZE); ++j)
			sstreambuf << "00 ";
	}
	sstreambuf << nl;
}

template <>
void print_header<ICMP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr) {
	const ICMP_HEADER *icmp_hdr = pointer_cast<decltype(icmp_hdr)>(hdr, offset);
	sstreambuf << indent[i] << "Internet Control Message Protocol (ICMP)"
		<< nl << indent[i] << "Type: " << s_cast<int>(icmp_hdr->type);
	switch (icmp_hdr->type)
	{
	case ICMP_HEADER::TYPE::ECHO_REPLY:
	case ICMP_HEADER::TYPE::ECHO_REQUEST: {
		sstreambuf << " (Echo(ping) "
			<< ((icmp_hdr->type == ICMP_HEADER::TYPE::ECHO_REPLY) ? "reply)" : "request)")
			<< nl << indent[i] << "Code: " << s_cast<int>(icmp_hdr->code) 
			<< nl << indent[i] << "Header checksum: " << hexbase << ntohs(icmp_hdr->checksum) << decnobase
			<< nl << indent[i] << "Identifier (BE): " << ntohs(icmp_hdr->identifier) 
			<< " (" << hexbase << ntohs(icmp_hdr->identifier) << decnobase << ")"
			<< nl << indent[i] << "Identifier (LE): " << icmp_hdr->identifier 
			<< " (" << hexbase << icmp_hdr->identifier << decnobase << ")"
			<< nl << indent[i] << "Sequence number (BE): " << ntohs(icmp_hdr->seq_num) 
			<< " (" << hexbase << ntohs(icmp_hdr->seq_num) << decnobase << ")"
			<< nl << indent[i] << "Sequence number (LE): " << icmp_hdr->seq_num 
			<< " (" << hexbase <<  icmp_hdr->seq_num << decnobase << ")" << nl;
		std::size_t beg = offset + ICMP_HEADER::SIZE;
		if (pkt_len > beg)
			print_data(sstreambuf, i, pkt_len - beg, pointer_cast<const u_char*>(icmp_hdr, ICMP_HEADER::SIZE));
		break;
	}
	case ICMP_HEADER::TYPE::TIME_EXCEEDED:
		sstreambuf << " (Time-to-live exceeded)"
			<< nl << indent[i] << "Code: " << s_cast<int>(icmp_hdr->code)
			<< " (" << ((icmp_hdr->code == 0)
				? "Time-to-live exceeded in transit)"
				: "Fragment reassembly time exceeded)") 
			<< nl << indent[i] << "Header checksum: " << hexbase << ntohs(icmp_hdr->checksum) << decnobase
			<< nl << indent[i] << "Unused bytes: 4 bytes" << nl;
		print_header<IPv4_HEADER>(i + 1, pkt_len, offset + ICMP_HEADER::SIZE, hdr);
		break;
	default:
		sstreambuf << nl << indent[i] << "Code: " << s_cast<int>(icmp_hdr->code)
		<< nl << indent[i] << "Header checksum: " << hexbase << ntohs(icmp_hdr->checksum) << decnobase
		<< nl << indent[i] << "The rest of ICMP-header and/or Payload length: " 
			<< pkt_len - (offset + ICMP_HEADER::SIZE) << " bytes" << nl;
		break;
	}
}

template <>
void print_header<TCP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr) {
	const TCP_HEADER *tcp_hdr = pointer_cast<decltype(tcp_hdr)>(hdr, offset);
	std::size_t hdr_len = (ntohs(tcp_hdr->hdrlen_flags) >> 0xC) * 4U,
		src_port = ntohs(tcp_hdr->src_port), dest_port = ntohs(tcp_hdr->dest_port);
	sstreambuf << indent[i] << "Transmission Control Protocol (TCP)"
		<< nl << indent[i] << "Source port: " << src_port
		<< nl << indent[i] << "Destination port: " << dest_port
		<< nl << indent[i] << "Sequence number: " << ntohl(tcp_hdr->seq_num)
		<< nl << indent[i] << "Acknowledgment number: " << ntohl(tcp_hdr->ack_num)
		<< nl << indent[i] << "Header length: " << hdr_len << " bytes"
		<< nl << indent[i] << "Flags: " << std::bitset<12U>(ntohs(tcp_hdr->hdrlen_flags) & 0x0FFF)
		<< " (Reserved 3 bits, ECN-Nonce, CWR, ECN-Echo, URG, ACK, PSH, RST, SYN, FIN)"
		<< nl << indent[i] << "Window size value: " << ntohs(tcp_hdr->win_size) 
		<< nl << indent[i] << "Header checksum: " << hexbase << ntohs(tcp_hdr->checksum) << decnobase
		<< nl << indent[i] << "Urgent pointer: " << ntohs(tcp_hdr->urg_pointer) << nl;

	if (hdr_len > TCP_HEADER::SIZE)
		sstreambuf << indent[i] << "Options length: " << hdr_len - TCP_HEADER::SIZE << " bytes" << nl;
	//Keep-Alive
	if ((pkt_len - (offset + hdr_len)) == 1)
		print_data(sstreambuf, i, 1, pointer_cast<const u_char*>(hdr, offset + hdr_len));
	//Ethernet requires that all packets be at least 60 bytes
	else if ((pkt_len != (offset + hdr_len)) && (pkt_len <= 60U)) {
		sstreambuf << indent[i] << "Padding: ";
		for (std::size_t j{}; j < pkt_len - (offset + hdr_len); ++j)
			sstreambuf << "00 ";
		sstreambuf << nl;
	}
	//FTP
	else if ((pkt_len > (offset + hdr_len)) && ((src_port == PORT::FTP) || (dest_port == PORT::FTP)))
		print_header<FTP_HEADER>(i + 1, pkt_len, offset + hdr_len, hdr);
	//HTTP
	else if ((pkt_len > (offset + hdr_len)) && ((src_port == PORT::HTTP) || (dest_port == PORT::HTTP))
		&& std::strstr(pointer_cast<const char*>(hdr, offset + hdr_len), "HTTP"))
		print_header<HTTP_HEADER>(i + 1, pkt_len, offset + hdr_len, hdr);
	else if ((pkt_len > (offset + hdr_len)) && ((src_port == PORT::HTTP) || (dest_port == PORT::HTTP)))
		print_data(sstreambuf, i, pkt_len - (offset + hdr_len), pointer_cast<const u_char*>(hdr, offset + hdr_len));
	else if (pkt_len > (offset + hdr_len))
		sstreambuf << indent[i] << "Payload length: " << pkt_len - (offset + hdr_len) << " bytes" << nl;
}

template <>
void print_header<UDP_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr) {
	const UDP_HEADER *udp_hdr = pointer_cast<decltype(udp_hdr)>(hdr, offset);
	std::size_t src_port = ntohs(udp_hdr->src_port), dest_port = ntohs(udp_hdr->dest_port);
	sstreambuf << indent[i] << "User Datagram Protocol (UDP)"
		<< nl << indent[i] << "Source port: " << src_port
		<< nl << indent[i] << "Destination port: " << dest_port
		<< nl << indent[i] << "Length: " << ntohs(udp_hdr->total_len)
		<< nl << indent[i] << "Header checksum: " << hexbase << ntohs(udp_hdr->checksum) << decnobase;
	if ((dest_port == PORT::SSDP) || (src_port == PORT::SSDP)) {
		sstreambuf << nl << indent[i + 1] << "Simple Service Discovery Protocol (SSDP)" << nl;
		print_header<HTTP_HEADER>(i + 1, pkt_len, offset + UDP_HEADER::SIZE, hdr);
	}
	else
		sstreambuf << nl << indent[i] << "Payload length: "
			<< (pkt_len - (offset + UDP_HEADER::SIZE)) << " bytes" << nl;
}

template <>
void print_header<IPv4_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr) {
	const IPv4_HEADER *ip_hdr = pointer_cast<decltype(ip_hdr)>(hdr, offset);
	std::size_t hdr_len = (ip_hdr->ver_hdrlen & 0xF) * 4U;
	sstreambuf << indent[i] << "Internet Protocol Version 4 (IPv4)" 
		<< nl << indent[i] <<"Version: " << (ip_hdr->ver_hdrlen >> 0x4)
		<< nl << indent[i] <<"Header length: " << hdr_len << " bytes"
		<< nl << indent[i] << "Differentiated Services Field: " << std::bitset<8>(ip_hdr->tos)
		<< nl << indent[i] << "Total length: " << ntohs(ip_hdr->total_len);
	u_short field = ntohs(ip_hdr->id);
	sstreambuf << nl << indent[i] << "Identification: " <<hexbase << field << decnobase
		<< " (" << field << ")" << nl <<indent[i] << "Flags: ";
	std::bitset<3> flags(ntohs(ip_hdr->flags_offset) >> 0xD);
	sstreambuf << flags << " (Reserved bit, "
		<< ((flags[1]) ? "Don't fragment, " : "Fragmented, ")
		<< ((flags[2]) ? "More fragments)" : "No more fragments)")
		<< nl << indent[i] << "Fragment offset: " << (ntohs(ip_hdr->flags_offset) & 0x1FFF)
		<< nl << indent[i] << "Time to live: " << s_cast<int>(ip_hdr->ttl)
		<< nl << indent[i] << "Protocol: ";
	field = ip_hdr->proto;
	sstreambuf << ((field == PROTOCOL::ICMP) ? "ICMP ("
		: (field == PROTOCOL::TCP) ? "TCP ("
		: (field == PROTOCOL::UDP) ? "UDP ("
		: (field == PROTOCOL::IGMP) ? "IGMP ("
		: "UNKNOWN (");
	sstreambuf << field << ")" << nl << indent[i]
		<< "Header checksum: " << hexbase << ntohs(ip_hdr->checksum) << decnobase
		<< nl << indent[i] << "Source: ";
	print_addr(sstreambuf, ip_hdr->src);
	sstreambuf << nl << indent[i] << "Destination: ";
	print_addr(sstreambuf, ip_hdr->dest);
	sstreambuf << nl;

	if (hdr_len > IPv4_HEADER::SIZE)
		sstreambuf << indent[i] << "Options length: " << hdr_len - IPv4_HEADER::SIZE << " bytes" << nl;
	if (field == PROTOCOL::ICMP)
		print_header<ICMP_HEADER>(i + 1, pkt_len, offset + hdr_len, hdr);
	else if (field == PROTOCOL::TCP)
		print_header<TCP_HEADER>(i + 1, pkt_len, offset + hdr_len, hdr);
	else if (field == PROTOCOL::UDP)
		print_header<UDP_HEADER>(i + 1, pkt_len, offset + hdr_len, hdr);
	else if (field == PROTOCOL::IGMP)
		print_header<IGMPv2_HEADER>(i + 1, pkt_len, offset + hdr_len, hdr);
	else
		sstreambuf << indent[i] << "Payload length: " << (pkt_len - (offset + hdr_len)) << " bytes" << nl;
}

template <>
void print_header<IPv6_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr) {
	const IPv6_HEADER *ip_hdr = pointer_cast<decltype(ip_hdr)>(hdr, offset);
	std::size_t field = ntohl(ip_hdr->ver_traff_label);
	//TODO: проверка
	sstreambuf << indent[i] << "Internet Protocol Version 6 (IPv6)"
		<< nl << indent[i] << std::bitset<4U>(field >> 0x1C)
		<< ".... = Version: " << (field >> 0x1C);
	sstreambuf << nl << indent[i] << "...." << std::bitset<8U>(((field << 0x4) >> 0x18))
		<< ".................... = Traffic class: " << hexbase << ((field << 0x4) >> 0x18) << decnobase;
	sstreambuf << nl << indent[i] << "............"
		<< std::bitset<20U>(field & 0xFFFFF) << " = Flowlabel: " << hexbase << (field & 0xFFFFF) << decnobase
		<< nl << indent[i] << "Payload length: " << ntohs(ip_hdr->payload_len);
	field = ntohs(ip_hdr->next_hdr);
	sstreambuf << nl << indent[i] << "Next header: "
		<< ((field == PROTOCOL::ICMPv6) ? "ICMPv6" 
			: (field == PROTOCOL::TCP) ? "TCP"
			: (field == PROTOCOL::UDP) ? "UDP"
			: "UNKNOWN") << " (" << field << ")"
		<< nl << indent[i] << "Hop limit: " << s_cast<int>(ip_hdr->hop_limit)
		<< nl << indent[i] << "Source: ";
	print_addr(sstreambuf, ip_hdr->src);
	sstreambuf << nl << indent[i] << "Destination: ";
	print_addr(sstreambuf, ip_hdr->dest);
	sstreambuf << nl;
	if (pkt_len > (offset + IPv6_HEADER::SIZE))
		sstreambuf << indent[i] << "The rest of Extension Header and/or Payload length: "
			<< (pkt_len - (offset + IPv6_HEADER::SIZE)) << " bytes" << nl;
}

template <>
void print_header<ETHERNET_HEADER>(std::size_t i, std::size_t pkt_len, std::size_t offset, const u_char *hdr)
{
	const ETHERNET_HEADER *ether_hdr = pointer_cast<decltype(ether_hdr)>(hdr);
	sstreambuf << indent[i] << "Ethernet II" << nl << indent[i] << "Destination: ";
	print_addr(sstreambuf, ether_hdr->dest);
	sstreambuf << nl << indent[i] << "Source: ";
	print_addr(sstreambuf, ether_hdr->src);
	sstreambuf << nl << indent[i] << "Type: ";

	u_short proto = ntohs(ether_hdr->proto);
	switch (proto)
	{
	case PROTOCOL::IPv4:
		sstreambuf << "IPv4 (" << hexbase << proto << ")" << decnobase << nl;
		print_header<IPv4_HEADER>(i + 1, pkt_len, offset + ETHERNET_HEADER::SIZE, hdr);
		break;
	case PROTOCOL::IPv6:
		sstreambuf << "IPv6 (" << hexbase << proto << ")" << decnobase << nl;
		print_header<IPv6_HEADER>(i + 1, pkt_len, offset + ETHERNET_HEADER::SIZE, hdr);
		break;
	case PROTOCOL::ARP:
		sstreambuf << "ARP (" << hexbase << proto << ")" << decnobase << nl;
		print_header<ARP_HEADER>(i + 1, pkt_len, offset + ETHERNET_HEADER::SIZE, hdr);
		break;
	default:
		sstreambuf << "UNKNOWN (" << hexbase << proto << ")" << decnobase  
			<< nl << indent[i] << "Payload length: "
			<< (pkt_len - (offset + ETHERNET_HEADER::SIZE)) << " bytes" << nl;
		break;
	}
}

void print_packet(const u_char *pkt_data, std::size_t pkt_len) {
	print_header<ETHERNET_HEADER>(0U, pkt_len, 0U, pkt_data);
	capture_dump << sstreambuf.str();
	capture_dump.flush();
}