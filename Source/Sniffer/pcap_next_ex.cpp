#include "pragma_libs.h"
#include "pkt_struct.h"

//TODO: CODE REVIEW
//#include <WinSock2.h>

constexpr int MAX_PACKET_SIZE = 65536;
constexpr int READ_TIMEOUT = 1000;//milliseconds

template<typename pointer_to_device>
void print_devices_info(pointer_to_device device);
template<typename pointer_to_device, typename integral = int>
pointer_to_device get_device_by_number(pointer_to_device all_devices, integral num);
char *iptos(u_long ipv4_addr);
void ip6tos(sockaddr *sockaddr, char *address, DWORD addrlen);

int main() {	
	sstreambuf.sync_with_stdio(false);
	capture_dump.sync_with_stdio(false);

	pcap_if *all_devices{}, *device{};
	pcap *device_handle{};
	u_int netmask{};
	bpf_program fcode{};
	char packet_filter[100]{}, errbuf[PCAP_ERRBUF_SIZE]{};
	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr/* auth is not needed */, &all_devices, errbuf) == -1) {
		std::cout << "Unable to retrieve information about interfaces!!! Error info: " << errbuf;
		std::cin.get();
		return -1;
	}
	if (all_devices) {
		int choice{};
		while (true) {
			std::cout << nl << "1) List of devices" << nl
				<< "2) Filtering expression syntax" << nl
				<< "3) Capture packets" << nl
				<< "4) Exit" << nl
				<< ">> ";
			std::cin >> choice;
			switch (choice)
			{
			case 1:
				print_devices_info(all_devices);
				break;
			case 2:
				std::cout << "The syntax of the expression can be found on "
					<< "https://www.winpcap.org/docs/docs_412/html/group__language.html" << nl;
				break;
			case 3: {
				std::cout << "Enter the interface number (1,2,...): ";
				(std::cin >> choice).ignore(100, nl);
				device = get_device_by_number(all_devices, choice);
				if (!device) std::cout << "Incorrect number!!! Go in 'List of devies'...";
				else {
					/* Open the device */
					if ((device_handle = pcap_open(device->name,// name of the device
						MAX_PACKET_SIZE,// portion of the packet to capture
										// 65536 guarantees that the whole packet will be captured on all the link layers
						PCAP_OPENFLAG_PROMISCUOUS,// promiscuous mode
						READ_TIMEOUT,
						nullptr,// authentication on the remote machine
						errbuf)) != nullptr) {
						//Support only Ethernet
						//Check the link layer (Ethernet (10Mb, 100Mb, 1000Mb, and up)).
						if (pcap_datalink(device_handle) != DLT_EN10MB)
							std::cout << "Oh... This program works only on Ethernet newtworks. Choose the another interface...";
						else {
							char is{};
							std::cout << "Use filter(y/n)?: "; is = std::cin.get();
							std::cin.ignore(100, '\n');
							if (is == 'y') {
								std::cout << "Filtering expression: ";
								std::cin.getline(packet_filter, 100);
								(device->addresses)
									? netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr
									: netmask = 0xffffff;/* If the interface is without addresses we suppose to be in a C class network */
								//compile the filter
								if (pcap_compile(device_handle, &fcode, packet_filter, 1, netmask) < 0) {
									std::cout << "Unable to compile the packet filter. Check the syntax. Error info: "
										<< pcap_geterr(device_handle) << nl;
									pcap_close(device_handle);
									device = nullptr;
									device_handle = nullptr;
									break;
								}
								//set the filter
								if (pcap_setfilter(device_handle, &fcode) < 0) {
									std::cout << "Error setting the filter. Error info: " << pcap_geterr(device_handle) << nl;
									pcap_close(device_handle);
									device = nullptr;
									device_handle = nullptr;
									break;
								}
								sstreambuf <<  "filtering expression: " << packet_filter << nl;
							}

							std::cout << "Listening on " << device->description << "... (Press key 'b' to stop capturing)" << nl;
							/* Retrieve the packets */
							std::stringstream buf;
							pcap_pkthdr *pkt_header{};
							const u_char* pkt_data{};
							std::time_t local_tv_sec{};
							std::tm ltime{};
							//TODO: use 'chrono' ?
							//TODO: day month year
							local_tv_sec = std::time(nullptr);
							localtime_s(&ltime, &local_tv_sec);
							buf << ltime.tm_hour << '_' << ltime.tm_min
								<< '_' << ltime.tm_sec << '_' << GetTickCount() << ".txt";
							capture_dump.open(buf.str());

							if (capture_dump.is_open()) {
								while ((choice = pcap_next_ex(device_handle, &pkt_header, &pkt_data)) >= 0) {
									if (_kbhit()) {
										if (_getch() == 'b') {
											std::cout << "Capture stopping...";
											break;
										}
									}
									if (choice == 0) continue;/* Timeout elapsed */
									statistics.Update(pkt_header->len);
									/* convert the timestamp to readable format */
									local_tv_sec = pkt_header->ts.tv_sec;
									localtime_s(&ltime, &local_tv_sec);
									std::cout << "time: " << ltime.tm_hour << ':' << ltime.tm_min
										<< ':' << ltime.tm_sec << ',' << pkt_header->ts.tv_usec
										<< "  packet length: " << pkt_header->len << " bytes" << nl;
									sstreambuf << nl << "time: " << ltime.tm_hour << ':' << ltime.tm_min
										<< ':' << ltime.tm_sec << ',' << pkt_header->ts.tv_usec
										<< "  packet length: " << pkt_header->len << " bytes" << nl;
									print_packet(pkt_data, pkt_header->len);
									statistics.Update(pkt_header->len);
									sstreambuf.str(std::string{});	
								}
								if (choice < 0)
									std::cout << "Error reading the packets!!! Error info: " << pcap_geterr(device_handle);
							}
							else
								std::cout << "Unable to create the capture dump!!! Check the access permissions...";
						}
					}
					else {
						std::cout << "Unable to open the adapter. " << device->name
							<< " is not supported by WinPcap!!! Choose the another interface...";
					}
					statistics.Print(sstreambuf);
					capture_dump << sstreambuf.str();
					capture_dump.flush();
					statistics.Reset();
					sstreambuf.str(std::string{});
					pcap_freecode(&fcode);
					pcap_close(device_handle);
					capture_dump.close();
					device = nullptr;
					device_handle = nullptr;
				}
				std::cout << nl;
				break;
			}
			case 4:
				if (all_devices) pcap_freealldevs(all_devices);
				return 0;
			default:
				break;
			}
		}
	}
	else {
		std::cout << "\nNo interfaces found! Make sure WinPcap is installed.\n";
		std::cin.get();
		return -1;
	}
	return 0;
}


template<typename pointer_to_device, typename integral = int>
pointer_to_device get_device_by_number(pointer_to_device all_devices, integral num) {
	/* Jump to the selected adapter */
	integral i = 1;
	auto device = all_devices;
	for (; (i != num) && device; device = device->next, ++i);
	return device;
}

/* Print all the available information on the given interface */
template<typename pointer_to_device>
void print_devices_info(pointer_to_device all_devices) {
	std::size_t i{1};
	auto device = all_devices;
	for (; device; device = device->next, ++i) {
		//Name
		std::cout << i << ") " << device->name << nl;
		//Description
		std::cout << "- Description: " << ((device->description) 
			? device->description : "No description available") << nl;
		//Loopback Address
		std::cout << "- Loopback: " << ((device->flags & PCAP_IF_LOOPBACK) ? "yes" : "no") << nl;
		//IP Addresses
		for (pcap_addr *cur_addr = device->addresses; cur_addr; cur_addr = cur_addr->next) {
			std::cout << "- Address Family: " << cur_addr->addr->sa_family << nl;
			switch (cur_addr->addr->sa_family)
			{
			case AF_INET:
				std::cout << "- Address Family Name: AF_INET" << nl;
				if (cur_addr->addr)
					std::cout << "- Address: " << iptos((pointer_cast<sockaddr_in*>(cur_addr->addr))->sin_addr.s_addr) << nl;
				if (cur_addr->netmask)
					std::cout << "- Netmask: " << iptos((pointer_cast<sockaddr_in*>(cur_addr->netmask))->sin_addr.s_addr) << nl;
				if (cur_addr->broadaddr)
					std::cout << "- Broadcast Address: " << iptos((pointer_cast<sockaddr_in*>(cur_addr->broadaddr))->sin_addr.s_addr) << nl;
				if (cur_addr->dstaddr)
					std::cout << "- Destination Address: " << iptos((pointer_cast<sockaddr_in*>(cur_addr->dstaddr))->sin_addr.s_addr) << nl;
				break;
			case AF_INET6:
				std::cout << "- Address Family Name: AF_INET6" << nl;
				if (cur_addr->addr) {
					char ip6str[NI_MAXHOST]{};
					ip6tos(cur_addr->addr, ip6str, NI_MAXHOST);
					std::cout << "- Address: " << ip6str << nl;
				}
				break;
			default:
				std::cout << "- Address Family Name: Unknown" << nl;
				break;
			}
		}
		std::cout << nl;
	}
}

char *iptos(u_long ipv4_addr) {
	const std::size_t BUF_SIZE = 3 * 4 + 3 + 1;
	static char buf[BUF_SIZE]{};
	u_char *p = pointer_cast<decltype(p)>(&ipv4_addr);
	_snprintf_s(buf, BUF_SIZE, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return buf;
}

void ip6tos(sockaddr *sockaddr, char *address, DWORD addrlen)
{
	if (getnameinfo(sockaddr,
		sizeof(sockaddr_in6),
		address,
		addrlen,
		nullptr,
		0,
		NI_NUMERICHOST) != 0) address[0] = 0;
}
