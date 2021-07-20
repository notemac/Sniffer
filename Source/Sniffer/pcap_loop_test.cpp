
////#define _XKEYCHECK_H
//#define WPCAP
//#define HAVE_REMOTE
//#include  "pragma_libs.h"
//#include <iostream>
//#include "pcap.h"
////#include <WinSock2.h>
//
//constexpr int MAX_PACKET_SIZE = 65536;
//constexpr int READ_TIMEOUT = 1000;//milliseconds
//
//template<typename result_type, typename source_type>
//result_type pointer_cast(source_type *p)
//{ return static_cast<result_type>(static_cast<void*>(p)); }
//
//void print_device_info(pcap_if *device);
//char *iptos(u_long in);
//void ip6tos(sockaddr *sockaddr, char *address, DWORD addrlen);
//void packet_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data);
//int main() {
//
//	//информация об адаптерах
//	pcap_if *all_devices{}, *device{};
//	char errbuf[PCAP_ERRBUF_SIZE]{};
//	/* Retrieve the device list from the local machine */
//	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr/* auth is not needed */, &all_devices, errbuf) == -1) {
//		std::cout << "Error in pcap_findalldevs_ex: " << errbuf << "\n";
//		std::cin.get();
//		return -1;
//	}
//	if (all_devices) {
//		int i{}, inum{};
//		/* Scan the list printing every entry */
//		for (device = all_devices; device; device = device->next, ++i) {
//			print_device_info(device);
//			std:: cout << "\n";
//		}
//		std::cout << "Enter the interface number (1-" << i << "): ";
//		std::cin >> inum;
//		if ((inum < 1) || (inum > i)) {
//			std::cout << "Interface number out of range.\n";
//			pcap_freealldevs(all_devices);
//			std::cin.get();
//			return -1;
//		}
//		/* Jump to the selected adapter */
//		for (device = all_devices, i = 1; i != inum; device = device->next, ++i);
//		/* Open the device */	
//		pcap *device_handle{};
//		if ((device_handle = pcap_open(device->name,// name of the device
//			MAX_PACKET_SIZE,// portion of the packet to capture
//							// 65536 guarantees that the whole packet will be captured on all the link layers
//			PCAP_OPENFLAG_PROMISCUOUS,// promiscuous mode
//			READ_TIMEOUT,
//			nullptr,// authentication on the remote machine
//			errbuf)) == nullptr) {
//			std::cout << "Unable to open the adapter. " << device->name
//				<< " is not supported by WinPcap\n";
//			pcap_freealldevs(all_devices);
//			std::cin.get();
//			return -1;
//		}
//		std::cout << "Listening on " << device->description << "\n";
//		/* At this point, we don't need any more the device list. Free it */
//		pcap_freealldevs(all_devices);
//		/* start the capture */
//		int res_cap_loop = pcap_loop(device_handle, 0, packet_handler, nullptr);
//
//		int test2 = res_cap_loop;
//		std::cout << "DEBUG";
//	}
//	else {
//		std::cout << "\nNo interfaces found! Make sure WinPcap is installed.\n";
//		std::cin.get();
//		return -1;
//	}
//	std::cin.get();
//	return 0;
//}
///* Print all the available information on the given interface */
//void print_device_info(pcap_if *device) {
//	//Name
//	std::cout << "- Name: " << device->name << "\n";
//	//Description
//	std::cout << "- Description: ";
//	(device->description)
//		? std::cout << device->description
//		: std::cout << "No description available";
//	std::cout << "\n";
//	//Loopback Address
//	std::cout << "- Loopback: " << ((device->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
//	std::cout << "\n";
//	//IP Addresses
//	for (pcap_addr *cur_addr = device->addresses; cur_addr; cur_addr = cur_addr->next) {
//		std::cout << "- Address Family: " << cur_addr->addr->sa_family << "\n";
//		switch (cur_addr->addr->sa_family)
//		{
//		case AF_INET:
//			std::cout << "- Address Family Name: AF_INET\n";
//			if (cur_addr->addr)
//				std::cout << "- Address: " << iptos((pointer_cast<sockaddr_in*>(cur_addr->addr))->sin_addr.s_addr) << "\n";
//			if (cur_addr->netmask)
//				std::cout << "- Netmask: " << iptos((pointer_cast<sockaddr_in*>(cur_addr->netmask))->sin_addr.s_addr) << "\n";
//			if (cur_addr->broadaddr)
//				std::cout << "- Broadcast Address: " << iptos((pointer_cast<sockaddr_in*>(cur_addr->broadaddr))->sin_addr.s_addr) << "\n";
//			if (cur_addr->dstaddr)
//				std::cout << "- Destination Address: " << iptos((pointer_cast<sockaddr_in*>(cur_addr->dstaddr))->sin_addr.s_addr) << "\n";
//			break;
//		case AF_INET6:
//			std::cout << "- Address Family Name: AF_INET6\n";
//			if (cur_addr->addr) {
//				char ip6str[NI_MAXHOST]{};
//				ip6tos(cur_addr->addr, ip6str, NI_MAXHOST);
//				std::cout << "- Address: " << ip6str << "\n";
//			}
//			break;
//		default:
//			std::cout << "- Address Family Name: Unknown\n";
//			break;
//		}
//	}
//}
///* From tcptraceroute, convert a numeric IP address to a string */
//char *iptos(u_long in) {
//	constexpr std::size_t IPTOSBUFFERS = 12;
//	static char output[IPTOSBUFFERS][3*4+3+1]{};
//	static short which{};
//	u_char *p{ pointer_cast<decltype(p)>(&in) };
//	which = (((which + 1) == IPTOSBUFFERS) ? 0 : (which + 1));
//	_snprintf_s(output[which], sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
//	return output[which];
//}
//
//void ip6tos(sockaddr *sockaddr, char *address, DWORD addrlen)
//{
//	if (getnameinfo(sockaddr,
//		sizeof(sockaddr_in6),
//		address,
//		addrlen,
//		nullptr,
//		0,
//		NI_NUMERICHOST) != 0) address[0] = '/0';
//}
//
///* Callback function invoked by libpcap for every incoming packet */
//void packet_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data) {
//	(void)(param);
//	(void)(pkt_data);
//
//	constexpr std::size_t TIMESTR_SIZE = 16;
//	char timestr[TIMESTR_SIZE]{};
//	time_t local_tv_sec{};
//	struct tm ltime {};
//	/* convert the timestamp to readable format */
//	local_tv_sec = header->ts.tv_sec;
//	localtime_s(&ltime, &local_tv_sec);
//	strftime(timestr, TIMESTR_SIZE, "%H:%M:%S", &ltime);
//	std::cout << "time: " << timestr << "." << header->ts.tv_usec << ", packet length: " << header->len << "\n";
//}