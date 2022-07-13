#pragma warning(disable : 4996)
#include <iostream>
#include <sstream>
#include <cstdio>
#include <fstream>
#include <pcap.h>
using namespace std;

#define LINE_LEN 16
#define MAC_ADDRESS_LEN 6
#define IP_ADDRESS_LEN 4
#define ETHERNET_HEAD_LEN 14
#define IP_HEAD_LEN 20
#define SYN 0x002
#define SYN_ACK 0x012
#define ACK 0x010
#define FIN_ACK 0x011
#define RST 0x004
#define RST_ACK 0x014


struct pcap_pkthdr* pcap_header;
const u_char* packet;


struct ethernet_header {			 // struktura na ethernetovu hlavicku
	u_char dst[MAC_ADDRESS_LEN];
	u_char src[MAC_ADDRESS_LEN];                  
	u_short type;
};

struct ieee_header {				// struktura na ieee hlavicku			
	u_char dsap;
	u_char jump[5];						//prejte nepotrebne B k EtherType
	u_short ethertype;
};

struct ip_header {					// struktura na ip hlavicku
	u_char version;						// verzia IP
	u_char tos;							
	u_short length;						
	u_short id;							
	u_short offset;						
	u_char ttl;							
	u_char protocol;					
	u_short checksum;					
	u_char ip_src[IP_ADDRESS_LEN];			// zdrojova IP adresa
	u_char ip_dst[IP_ADDRESS_LEN];			// cielova IP adresa
};

struct tcp_header {					// struktura na tcp hlavicku
	u_short src_port;					// zdrojovy port
	u_short dst_port;					// cielovy port
	u_int32_t sequence;					
	u_int32_t acknowledgement;			
	u_char offset;						
	u_char flag;						
	u_short window;						
	u_short checksum;					
	u_short urgent_pointer;				
};

struct udp_header {					// struktura na tcp hlavicku
	u_short  src_port;
	u_short  dst_port;
	u_short  len;
	u_short  checksum;
};

struct icmp_header {				// struktura na icpm hlavicku
	u_char type;
	u_char code;
};

struct arp_header {					// struktura na arp hlavicku
	u_short hw_address;
	u_short protocol_address;
	u_char hw_addr_len;
	u_char protocol_address_len;
	u_short operation;
	u_char src_hw_address[MAC_ADDRESS_LEN];
	u_char src_protocol_address[IP_ADDRESS_LEN];
	u_char target_hw_address[MAC_ADDRESS_LEN];
	u_char target_protocol_address[IP_ADDRESS_LEN];
};



//....vymeni poradie dvoch byte-ou.......................................................
u_short swap_bytes(u_short x) {
	return x = (x >> 8) | ((x & 255) << 8);
}

//....vypis oboch MAC adries.............................................................
void print_MAC_addresses(const u_char* packet, FILE* file) {

	printf("MAC Source Address:      ");
	fprintf(file, "MAC Source Address:      ");
	for (int i = 6; i < MAC_ADDRESS_LEN * 2; i++) {
		printf("%.2x ", packet[i]);
		fprintf(file, "%.2x ", packet[i]);
	}
	printf("\nMAC Destination Address: ");
	fprintf(file, "\nMAC Destination Address: ");
	for (int i = 0; i < MAC_ADDRESS_LEN; i++){
		printf("%.2x ", packet[i]);
		fprintf(file, "%.2x ", packet[i]);
	}
}

//....vypis dlzky ramca w/ padding.......................................................
void print_start(const u_char* packet, FILE* file, int packet_count) {
	printf("Packet: %d\n", packet_count);				
	fprintf(file, "\nPacket: %d\n", packet_count);
	int len = pcap_header->len;
	printf("Packet size from pcap API:         %d B\n", len);
	fprintf(file, "Packet size from pcap API:         %d B\n", len);
	len += 4;
	if (len <= 64)len = 64;
	printf("Packet size carried by the medium: %d B\n", len);
	fprintf(file, "Packet size carried by the medium: %d B\n", len);
}

//....dva char do jedneho int..........................................................
int get_int(const u_char* array, int offset){
	return (int)(((int)array[offset]) << 8 | array[offset + 1]);

}


//....vypise cely packet v po bytoch, v riadku ich bude LINE_LEN.........................
void print_out_hex(const u_char* packet, FILE* file) {
	cout << endl;
	fprintf(file, "\n");
	for (u_int i = 0; (i < pcap_header->len); i++) {
		if ((i % LINE_LEN) == 0) {
			cout << endl;
			fprintf(file, "\n");
		}
		else if ((i % (LINE_LEN / 2)) == 0) {
			cout << " ";
			fprintf(file, " ");
		}
		printf("%.2x ", toupper(packet[i]));
		fprintf(file, "%.2x ", toupper(packet[i]));
	}
	cout << endl << "------------------------------------------------" << endl;
	fprintf(file, "\n------------------------------------------------\n");

}

//....zistenie nazvu packetu ktory otvorit...............................................
string get_input_file_name() {
	string file_name = "C:\\Users\\adamb\\OneDrive - Slovenská technická univerzita v Bratislave\\code\\C++\\PKS_zadanie1\\packets\\";
	string input_file_name;
	cout << "Enter a file to open (in format: trace/eth-number):" << endl;
	cin >> input_file_name;
	file_name.append(input_file_name);
	file_name.append(".pcap");
	return file_name;
}

//....vypis menu a vrati mosnost ktoru si vyberie........................................
int get_menu_choice() {
	string input;
	short control = 0;
	int menu_options[] = {0,1,2,3,4,5,6,7,8,9,10,11};
	cout << "- - - - - - - - - - - - - - - - -\n";
	cout << "Choose an option:\n";
	cout << " 1 - List all frames - 1, 2, 3\n";
	cout << " 2 - List HTTP - 4a\n";
	cout << " 3 - List HTTPS - 4b\n";
	cout << " 4 - List TELNET - 4c\n";
	cout << " 5 - List SSH - 4d\n";
	cout << " 6 - List FTP-CONTROL - 4e\n";
	cout << " 7 - List FTP-DATA - 4f\n";
	cout << " 8 - List TFTP - 4g\n";
	cout << " 9 - List ICMP - 4h\n";
	cout << "10 - List ARP pairs - 4i\n";
	cout << "11 - List LLDP - Implementation\n";
	cout << " 0 - END\n";
	cout << "- - - - - - - - - - - - - - - - -\n";
	cin >> input;
	cout << "------------------------------------------------" << endl;
	stringstream help(input);
	int num_input = 0;
	help >> num_input;

	for (int i = 0; i < sizeof(menu_options) / 4; i++) {
		if (num_input == i) {
			control = 1;
			break;
		}
	}
	if (control == 0) {
		cout << "Wrong input\n";
		return -1;
	}
	return num_input;
}

//....zistenie typ ramca (Ethernet II or IEEE)............................................
int get_frame_type(const u_char* packet, FILE* file, struct ethernet_header* ethernet, struct ieee_header* ieee, int to_print) {
	if (ethernet->type > 1500) {		//tak je to Ethernet II
	//	get_EthernetII(packet, ethernet->ethernet_type, file);
		if(to_print) {
			printf("Ethernet II\n");
			fprintf(file, "Ethernet II\n");
		}
		return 1;
	}else {										//tak je to IEEE
		ieee = (struct ieee_header*)(packet + ETHERNET_HEAD_LEN);
		if (to_print) {
			switch (ieee->dsap) {
			case 0xaa:					//170
				printf("IEEE 802.3 LLC + SNAP\n");
				fprintf(file, "IEEE 802.3 LLC + SNAP\n");
				return 2;
			case 0xff:					//255
				printf("IEEE 802.3 RAW\n");
				fprintf(file, "IEEE 802.3 RAW\n");
				return 3;
			default:
				printf("IEEE 802.3 LLC\n");
				fprintf(file, "IEEE 802.3 LLC\n");
				return 0;
			}
		}else {
			switch (ieee->dsap) {
			case 0xaa:					//IEEE 802.3 LLC + SNAP
				return 2;
			case 0xff:					//IEEE 802.3 RAW
				return 3;
			default:					//IEEE 802.3 LLC
				return 0;
			}
		}
	}
}

//....zo suboru s protokolmi zisti podla symbolu ci tam je, a podla if_print to vypise alebo nie
int get_protocol_name(FILE* print_out_file, FILE* protocol_file, u_short etherType_number, char symbol, int if_print) {
	int protocol_num = 0, was_found = 0;
	char c;
	rewind(protocol_file);
	while ((c = getc(protocol_file)) != EOF) { //citame az do konca suboru
		if (c == symbol) {
			c = getc(protocol_file);
			fscanf(protocol_file, " %d", &protocol_num);

			if (etherType_number == protocol_num) {
				was_found = 1;
				if (if_print) {
					c = getc(protocol_file);
					cout << endl;
					fprintf(print_out_file, "\n");
					while ((c = getc(protocol_file)) != '\n') {
						cout << c;
						fprintf(print_out_file, "%c", c);
					}
				} 
				break;
			}
		}
	}
	return protocol_num;
}

//....vypis IP adries pri IPv4 protokole.................................................
void print_ip_addr(FILE* print_out_file, struct ip_header* ip) {
	printf("\nIP Source address:       %d.%d.%d.%d\n", ip->ip_src[0], ip->ip_src[1], ip->ip_src[2], ip->ip_src[3]);
	printf("IP Destination address:  %d.%d.%d.%d", ip->ip_dst[0], ip->ip_dst[1], ip->ip_dst[2], ip->ip_dst[3]);
	fprintf(print_out_file, "\nIP Source address:       %d.%d.%d.%d\n", ip->ip_src[0], ip->ip_src[1], ip->ip_src[2], ip->ip_src[3]);
	fprintf(print_out_file, "IP Destination address:  %d.%d.%d.%d", ip->ip_dst[0], ip->ip_dst[1], ip->ip_dst[2], ip->ip_dst[3]);

}

//....vypisanie TCP portov...............................................................
void print_ports_tcp(FILE* print_out_file, struct tcp_header* tcp) {
	printf("\nSource Port:       %d\n", tcp->src_port);
	fprintf(print_out_file, "\nSource Port:       %d\n", tcp->src_port);
	printf("Destination Port:  %d", tcp->dst_port);
	fprintf(print_out_file, "Destination Port:  %d", tcp->dst_port);
}

//....vypisanie UDP portov...............................................................
void print_ports_udp(FILE * print_out_file, struct udp_header* udp) {
	printf("\nSource Port:       %d\n", udp->src_port);
	fprintf(print_out_file, "\nSource Port:       %d\n", udp->src_port);
	printf("Destination Port:  %d", udp->dst_port);
	fprintf(print_out_file, "Destination Port:  %d", udp->dst_port);
}

//.....bod 3, vsetky dst ip, a najcastejsia s poctom packetov............................
void print_list_of_ip_dst(FILE* print_out_file, int count_of_ip_dst, char** list_of_ip_dst, int* packets_transferred) {

	printf("\nIP addresses of receiving nodes:\n\n");
	fprintf(print_out_file, "\nIP addresses of receiving nodes:\n\n");
	for (int i = 0; count_of_ip_dst > i; i++) {
		printf("%s\n", *(list_of_ip_dst + i));
		fprintf(print_out_file, "%s\n", *(list_of_ip_dst + i));
	}
	printf("---------------");
	fprintf(print_out_file, "---------------");
	printf("\nAddress of node with the most recieved packets: \n");
	fprintf(print_out_file, "\nAddress of node with the most recieved packets: \n");

	int max = 0, index = -1;
	for (int i = 0; i < count_of_ip_dst; i++) {
		if (*(packets_transferred + i) > max) {
			max = *(packets_transferred + i);
			index = i;
		}
	}
	printf("\n%s       %d packets\n\n", *(list_of_ip_dst + index), *(packets_transferred + index));
	fprintf(print_out_file, "\n%s       %d packets\n\n", *(list_of_ip_dst + index), *(packets_transferred + index));
	printf("------------------------------------------------\n");
	fprintf(print_out_file, "------------------------------------------------\n");
	
}

int print_all_ipv4_base(const u_char* packet, FILE* print_out_file, FILE* protocol_file, int packet_count, struct ethernet_header* ethernet, struct ieee_header* ieee, struct ip_header* ip) {
	int int_dump;

	print_start(packet, print_out_file, packet_count);
	int_dump = get_frame_type(packet, print_out_file, ethernet, ieee, 1);	//return 1 je EthernetII, 0 je IEEE
	print_MAC_addresses(packet, print_out_file);
	int_dump = get_protocol_name(print_out_file, protocol_file, ethernet->type, '#', 1);
	print_ip_addr(print_out_file, ip);
	int_dump = get_protocol_name(print_out_file, protocol_file, ip->protocol, '~', 1);
	return int_dump;

}
void announce_communication(FILE* print_out_file, int symblol) {


}


//*****************************************************************************************************************************************************************************
//***********************************************************************************main**************************************************************************************

int main() {

	main_begining:
	struct ethernet_header* ethernet;
	struct ieee_header* ieee = NULL;
	struct ip_header* ip;
	struct tcp_header* tcp;
	struct udp_header* udp;
	struct arp_header* arp;
	struct icmp_header* icmp;
	pcap_t* pcap;


	FILE* print_all_out_file = NULL;
	FILE* protocol_file = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	int packet_count = 0, frame_type, protocol_number, ip_options = 0, return_value, num_input, int_dump;		//pomocne premenne
	int previous_src_port = 0, previous_dst_port = 0;




	//otvaranie subor na vypis a subor obsahujuci protokoly
	if ((print_all_out_file = fopen("print_all_out_file.txt", "a")) == NULL) {
		cout << "File print_all_out_file.txt didn't open" << endl;
		return 0;
	}
	else if ((protocol_file = fopen("protocols.txt", "r")) == NULL) {
		cout << "File protocols.txt didn't open" << endl;
		fclose(print_all_out_file);
		return 0;
	}

	//otvaranie packetu
	string file_name = get_input_file_name();
	if ((pcap = pcap_open_offline(file_name.c_str(), errbuf)) == NULL) {
		cout << "Packet did not open: " << errbuf << "\n";
		fclose(print_all_out_file);
		fclose(protocol_file);
		return 0;
	}

	num_input = get_menu_choice();
	//0 ak bol zvoleny END, -1 ak bol nespravny vstup
	if ((num_input == -1) || (num_input == 0)) {
		fclose(print_all_out_file);
		fclose(protocol_file);
		pcap_close(pcap);
		return 0;
	}

	if (num_input == 1) {						//zakladny vypis

		int count_of_ip_dst = 0, is_ip_listed;
		char** list_of_ip_dst = (char**)malloc(sizeof(char*));
		int* packets_transferred = (int*)malloc(sizeof(int));
		char* ip_dst_addr = NULL;

		fprintf(print_all_out_file, "List of all frames:\n");
		while (return_value = pcap_next_ex(pcap, &pcap_header, &packet) >= 0) {

			ethernet = (struct ethernet_header*)(packet);
			ip_options = 0;
			ethernet->type = swap_bytes(ethernet->type);
			packet_count++;	
			print_start(packet, print_all_out_file, packet_count);
			frame_type = get_frame_type(packet, print_all_out_file, ethernet, ieee, 1);	//return 1 je EthernetII, 0 a 2 a 3 ak je IEEE
			print_MAC_addresses(packet, print_all_out_file);

			if (frame_type == 1) {						//ak EthernetII
				protocol_number = get_protocol_name(print_all_out_file, protocol_file, ethernet->type, '#', 1);
				if (protocol_number == 2048) {				//IP
					ip = (struct ip_header*)(packet + ETHERNET_HEAD_LEN);
					print_ip_addr(print_all_out_file, ip);
					int_dump = get_protocol_name(print_all_out_file, protocol_file, ip->protocol, '~', 1);
					if (ip->version > 69)
						ip_options = ip->version - 69; //0x45
					ip_options = ip_options * 4;

					if (ip->protocol == 1) {				//ICMP
						icmp = (struct icmp_header*)(packet + ETHERNET_HEAD_LEN + IP_HEAD_LEN + ip_options);
						int_dump = get_protocol_name(print_all_out_file, protocol_file, icmp->type, '|', 1);
					}
					if (ip->protocol == 17) {				//UDP
						udp = (struct udp_header*)(packet + ETHERNET_HEAD_LEN + IP_HEAD_LEN + ip_options);
						udp->src_port = swap_bytes(udp->src_port);
						udp->dst_port = swap_bytes(udp->dst_port);
						//na vypisanie TFTP nie len s portom 69
						if ((udp->src_port == 69) || (udp->dst_port == 69) || (udp->src_port == previous_src_port) || (udp->dst_port == previous_dst_port) || (udp->src_port == previous_dst_port) || (udp->dst_port == previous_src_port)) {
							previous_src_port = udp->src_port;
							previous_dst_port = udp->dst_port;
							int_dump = get_protocol_name(print_all_out_file, protocol_file, 69, '+', 1);
							print_ports_udp(print_all_out_file, udp);
						}
					}
					if (ip->protocol == 6) {				//TCP
						int s_port, d_port;
						tcp = (struct tcp_header*)(packet + ETHERNET_HEAD_LEN + IP_HEAD_LEN + ip_options);
						tcp->src_port = swap_bytes(tcp->src_port);
						tcp->dst_port = swap_bytes(tcp->dst_port);
						s_port = get_protocol_name(print_all_out_file, protocol_file, tcp->src_port, '*', 1);	//vypise len protocol, ktory je v protocols.txt(jeden z nich)
						d_port = get_protocol_name(print_all_out_file, protocol_file, tcp->dst_port, '*', 1);
						print_ports_tcp(print_all_out_file, tcp);
					}

					ip_dst_addr = (char*)malloc(16 * sizeof(char));
					//zapisovanie IP adresy do char ako bit bit-e
					int byte = 0, divider = 100;
					for (int i = 0; i < 16; i++) {		
						if (divider == 0) {				//ked prejde jedno cele cislo v IP adrese
							byte++;
							divider = 100;
							if (byte == 4) {
								ip_dst_addr[i] = '\0';
								break;
							}
							ip_dst_addr[i] = '.';
							i++;
						}								//podmienka ak cislo je v adrese je < 100
						if (((ip->ip_dst[byte] / divider) % 10 == 0) && ((ip->ip_dst[byte] / 100) % 10 == 0) && divider > 1) {
							divider /= 10;
							i--;
						}else {
							ip_dst_addr[i] = ((ip->ip_dst[byte] / divider) % 10) + '0';
							divider /= 10;
						}
					}
					//zapisujem IP_dst(prijimajuce uzly) adresy do pola, a kolko krat prijali
					is_ip_listed = 0;
					if (count_of_ip_dst == 0) {			//ked je to prva IP na porovnanie tak sa len zapise
						*(list_of_ip_dst + count_of_ip_dst) = ip_dst_addr;
						*(packets_transferred + count_of_ip_dst) = 1;
						count_of_ip_dst++;
						is_ip_listed = 1;
					}
					else {								//prejde pole s IP a ak najde zhodu tak pripocita byte velkost
						for (int i = 0; i < count_of_ip_dst; i++) {
							if (strcmp(*(list_of_ip_dst + i), ip_dst_addr) == 0) {
								*(packets_transferred + i) += 1;
								is_ip_listed = 1;
							}
						}
					}
					if (is_ip_listed == 0) {		//ak ani jedno ^ tak pripise ip_dst_addr na koniec pola
						count_of_ip_dst++;
						list_of_ip_dst = (char**)realloc(list_of_ip_dst, count_of_ip_dst * sizeof(char*));
						packets_transferred = (int*)realloc(packets_transferred, count_of_ip_dst * sizeof(int));
						*(list_of_ip_dst + (count_of_ip_dst - 1)) = ip_dst_addr;
						*(packets_transferred + (count_of_ip_dst - 1)) = 1;
					}
				}
				else if (protocol_number == 2054) {			//ARP
					arp = (struct arp_header*)(packet + ETHERNET_HEAD_LEN);
					arp->operation = swap_bytes(arp->operation);
					protocol_number = get_protocol_name(print_all_out_file, protocol_file, arp->operation, '<', 1);
				}
			}
			else if (frame_type == 0) {					//ak IEEE 803.2 LLC
				ieee = (struct ieee_header*)(packet + ETHERNET_HEAD_LEN);
				protocol_number = get_protocol_name(print_all_out_file, protocol_file, ieee->dsap, '$', 1);
			}
			else if (frame_type == 2) {					//ak IEEE 803.2 LLC + SNAP
				ieee = (struct ieee_header*)(packet + ETHERNET_HEAD_LEN);
				ieee->ethertype = swap_bytes(ieee->ethertype);
				protocol_number = get_protocol_name(print_all_out_file, protocol_file, ieee->ethertype, '#', 1);
			}
			else if (frame_type == 3) {					//ak IEEE 803.2 RAW
			printf("\nIPX");
			fprintf(print_all_out_file, "\nIPX");
			}
			print_out_hex(packet, print_all_out_file);
		}
		print_list_of_ip_dst(print_all_out_file, count_of_ip_dst, list_of_ip_dst, packets_transferred);

		ieee = NULL;
		ip = NULL;
		ethernet = NULL;
		arp = NULL;
		free(list_of_ip_dst);
		free(packets_transferred);
		free(ip_dst_addr);
		pcap_close(pcap);
	}

	if (num_input >= 2 && num_input <= 9) {
		int menu_protocol_number, protocol_counter = 0, packet_count = 0, packet_count_done, incrementer = 0;
		//ktory protocol sa bude vypisovat	
		if (num_input >= 2 && num_input <= 7) {		//TCP vnorene
			switch (num_input) {
			case 7:		//FTP-DATA
				menu_protocol_number = 20;
				fprintf(print_all_out_file, "List of all FTP-DATA\n");
				break;
			case 6:		//FTP-CONTROL
				menu_protocol_number = 21;
				fprintf(print_all_out_file, "List of all FTP-CONTROL\n");
				break;
			case 5:		//SSH
				menu_protocol_number = 22;
				fprintf(print_all_out_file, "List of all SSH\n");
				break;
			case 4:		//TELNET
				menu_protocol_number = 23;
				fprintf(print_all_out_file, "List of all TELNET\n");
				break;
			case 3:		//HTTPS
				menu_protocol_number = 443;
				fprintf(print_all_out_file, "List of all HTTPS\n");
				break;
			case 2:		//HTTP
				menu_protocol_number = 80;
				fprintf(print_all_out_file, "List of all HTTP\n");
				break;
			}
		}

		u_char previous_flag = 0;
		int* com_packets = NULL; 
		int tcp_com_count = 0, tree_way_HS_done = 0, fin_attempt = 0, communication_terminated = 0;
		u_short tcp_s_port = 0, tcp_d_port = 0;

		//na zistenie protocol_count na vypisanie 1-10 -- (protocol_count-10)-protocol_count
		//a na zistenie uplnej tcp komunikacie
		while (return_value = pcap_next_ex(pcap, &pcap_header, &packet) >= 0) {
			ethernet = (struct ethernet_header*)(packet);
			ethernet->type = swap_bytes(ethernet->type);

			int int_dump;
			packet_count++;
			ip_options = 0;
			frame_type = get_frame_type(packet, print_all_out_file, ethernet, ieee, 0);	//return 1 je EthernetII, 0 je IEEE

			if (frame_type == 1) {						//ak EthernetII
				protocol_number = get_protocol_name(print_all_out_file, protocol_file, ethernet->type, '#', 0);
				if (protocol_number == 2048) {				//IP
					ip = (struct ip_header*)(packet + ETHERNET_HEAD_LEN);

					int_dump = get_protocol_name(print_all_out_file, protocol_file, ip->protocol, '~', 0);

					if (ip->version > 69) 
						ip_options = ip->version - 69; //0x45
					ip_options = ip_options * 4;

					switch (num_input) {
					case 9:
						if (ip->protocol == 1) {			//ICMP
							protocol_counter++;
						}
						break;
					case 8:
						if (ip->protocol == 17) {			//UDP
							protocol_counter++;
						}
						break;
					default:
						if (ip->protocol == 6) {					//TCP
							tcp = (struct tcp_header*)(packet + ETHERNET_HEAD_LEN + IP_HEAD_LEN + ip_options);
							tcp->src_port = swap_bytes(tcp->src_port);
							tcp->dst_port = swap_bytes(tcp->dst_port);
							if ((tcp->src_port == menu_protocol_number) || (tcp->dst_port == menu_protocol_number)) {
								protocol_counter++;

								if (communication_terminated == 0) {			//zistovanie komunikacii
									switch (tcp->flag) {
									case SYN:								 //SYN
										if ((previous_flag == 0) || (fin_attempt == 1) || (fin_attempt == 2) || (fin_attempt == 3)) {
											tcp_s_port = tcp->src_port;
											tcp_d_port = tcp->dst_port;
											tcp_com_count = 1;
											if ((fin_attempt == 1) || (fin_attempt == 2) || (fin_attempt == 3))
												free(com_packets);
											com_packets = (int*)malloc(sizeof(int));
											*(com_packets + 0) = packet_count;
											tree_way_HS_done = 0;
											fin_attempt = 0;
										}
										else if ((tcp_s_port == tcp->src_port && tcp_d_port == tcp->dst_port) || (tcp_s_port == tcp->dst_port && tcp_d_port == tcp->src_port)) {

										}
										previous_flag = tcp->flag;
										break;
									case SYN_ACK:							//SYN_ACK
										if (previous_flag == SYN && ((tcp_s_port == tcp->src_port && tcp_d_port == tcp->dst_port) || (tcp_s_port == tcp->dst_port && tcp_d_port == tcp->src_port))) {
											tcp_com_count++;
											com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
											*(com_packets + (tcp_com_count - 1)) = packet_count;
											previous_flag = tcp->flag;
										}
										else {
											tcp_com_count = 0;
											previous_flag = tcp->flag;
										//	free(com_packets);
										}
										
										break;
									case ACK:								//ACK
										if ((tcp_s_port == tcp->src_port && tcp_d_port == tcp->dst_port) || (tcp_s_port == tcp->dst_port && tcp_d_port == tcp->src_port)) {
											if (previous_flag == SYN_ACK) {
												tcp_com_count++;
												com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
												*(com_packets + (tcp_com_count - 1)) = packet_count;
												tree_way_HS_done = 1;
												previous_flag = tcp->flag;
											}
											else if (previous_flag == FIN_ACK) {
												previous_flag = tcp->flag;
												if (fin_attempt == 1) {
													fin_attempt = 2;
													tcp_com_count++;
													com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
													*(com_packets + (tcp_com_count - 1)) = packet_count;
												}
												else if (fin_attempt == 3) {
													tcp_com_count++;
													com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
													*(com_packets + (tcp_com_count - 1)) = packet_count;
													fin_attempt = 0;
													communication_terminated = 1;
												}
											}
											else {		
												previous_flag = tcp->flag;
												tcp_com_count++;
												com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
												*(com_packets + (tcp_com_count - 1)) = packet_count;
											}
										}
										else if (previous_flag == SYN_ACK) {
											previous_flag = tcp->flag;
											tcp_com_count = 0;
										//	free(com_packets);
										}
										break;
									case FIN_ACK:				//FIN_ACK
										if ((tcp_s_port == tcp->src_port && tcp_d_port == tcp->dst_port) || (tcp_s_port == tcp->dst_port && tcp_d_port == tcp->src_port)) {
											if (fin_attempt == 0) {
												tcp_com_count++;
												com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
												*(com_packets + (tcp_com_count - 1)) = packet_count;
												fin_attempt = 1;
												previous_flag = tcp->flag;
											}
											else if ((fin_attempt == 2) || (fin_attempt == 1)) {
												tcp_com_count++;
												com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
												*(com_packets + (tcp_com_count - 1)) = packet_count;
												fin_attempt = 3;
												previous_flag = tcp->flag;
											}
										}
										break;
									case RST:					//RST || RST_ACK
									case RST_ACK:
										if ((tcp_s_port == tcp->src_port && tcp_d_port == tcp->dst_port) || (tcp_s_port == tcp->dst_port && tcp_d_port == tcp->src_port)) {
											if ((tcp->flag == RST) || (tcp->flag == RST_ACK && previous_flag == ACK) || (tcp->flag == RST_ACK && fin_attempt == 2)) {
												tcp_com_count++;
												com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
												*(com_packets + (tcp_com_count - 1)) = packet_count;
												fin_attempt = 0;
												communication_terminated = 1;
											}
											previous_flag = tcp->flag;
										}
										break;
									default:								//else
										if (tree_way_HS_done && ((tcp_s_port == tcp->src_port && tcp_d_port == tcp->dst_port) || (tcp_s_port == tcp->dst_port && tcp_d_port == tcp->src_port))) {
											tcp_com_count++;
											com_packets = (int*)realloc(com_packets, tcp_com_count * sizeof(int));
											*(com_packets + (tcp_com_count - 1)) = packet_count;
											previous_flag = tcp->flag;
										}
										break;
									}
								}
							}
						}
					}
				}
			}
		}
		ip = NULL;
		arp = NULL;
		tcp = NULL;
		pcap_close(pcap);
		packet_count_done = packet_count;
		packet_count = 0;
		//znovu otvorenie
		if ((pcap = pcap_open_offline(file_name.c_str(), errbuf)) == NULL) {
			cout << "Packet did not open: " << errbuf << "\n";
			fclose(print_all_out_file);
			fclose(protocol_file);
			return 0;
		}
		//na vypis filtra

		int waiting = 0, icmp_com_count = 0, udp_com_count = 0, tcp_com_out_count = 0;
		int* echo_is_waiting = &waiting;

		while (return_value = pcap_next_ex(pcap, &pcap_header, &packet) >= 0) {

			ethernet = (struct ethernet_header*)(packet);
			ethernet->type = swap_bytes(ethernet->type);
			packet_count++;
			ip_options = 0;

			switch (num_input) {
			case 9:
			case 8:
				frame_type = get_frame_type(packet, print_all_out_file, ethernet, ieee, 0);
				if (frame_type == 1) {						//ak EthernetII
					protocol_number = get_protocol_name(print_all_out_file, protocol_file, ethernet->type, '#', 0);
					if (protocol_number == 2048) {				//IP
						ip = (struct ip_header*)(packet + ETHERNET_HEAD_LEN);
						int_dump = get_protocol_name(print_all_out_file, protocol_file, ip->protocol, '~', 0);
						if (ip->version > 69) { ip_options = ip->version - 69; } //0x45
						ip_options = ip_options * 4;
						switch (num_input) {
						case 9:									//ICMP
							if (ip->protocol == 1) {			//ICMP
								incrementer++;
								if ((incrementer <= 10) || (incrementer > (protocol_counter - 10))) {
									icmp = (struct icmp_header*)(packet + ETHERNET_HEAD_LEN + IP_HEAD_LEN + ip_options);
									if (icmp->type == 8) {
										icmp_com_count++;
										if (*echo_is_waiting == 0) (*echo_is_waiting) = 1;
										printf("~~~~~~~~~~~~~~~~~~~~~\nCommunication num. %d:\n~~~~~~~~~~~~~~~~~~~~~\n", icmp_com_count);
										fprintf(print_all_out_file, "~~~~~~~~~~~~~~~~~~~~~\nCommunication num. %d:\n~~~~~~~~~~~~~~~~~~~~~\n", icmp_com_count);
									}
									else if (icmp->type == 0)
										(*echo_is_waiting) = 0;
									else
										if (*echo_is_waiting == 1) (*echo_is_waiting) = 0;

									print_all_ipv4_base(packet, print_all_out_file, protocol_file, packet_count, ethernet, ieee, ip);
									int_dump = get_protocol_name(print_all_out_file, protocol_file, icmp->type, '|', 1);
									print_out_hex(packet, print_all_out_file);
								}
							}
							break;
						case 8:									//UDP
							if (ip->protocol == 17) {			//UDP
								udp = (struct udp_header*)(packet + ETHERNET_HEAD_LEN + IP_HEAD_LEN + ip_options);
								udp->src_port = swap_bytes(udp->src_port);
								udp->dst_port = swap_bytes(udp->dst_port);
								if ((udp->src_port == 69) || (udp->dst_port == 69) || (udp->src_port == previous_src_port) || (udp->dst_port == previous_dst_port) || (udp->src_port == previous_dst_port) || (udp->dst_port == previous_src_port)) {
									previous_src_port = udp->src_port;
									previous_dst_port = udp->dst_port;
									incrementer++;
									if ((incrementer <= 10) || (incrementer > (protocol_counter - 10))) {
										if ((udp->src_port == 69) || (udp->dst_port == 69)) {
											udp_com_count++;
											printf("~~~~~~~~~~~~~~~~~~~~~\nCommunication num. %d:\n~~~~~~~~~~~~~~~~~~~~~\n", udp_com_count);
											fprintf(print_all_out_file, "~~~~~~~~~~~~~~~~~~~~~\nCommunication num. %d:\n~~~~~~~~~~~~~~~~~~~~~\n", udp_com_count);
										}
										print_all_ipv4_base(packet, print_all_out_file, protocol_file, packet_count, ethernet, ieee, ip);
										int_dump = get_protocol_name(print_all_out_file, protocol_file, 69, '+', 1);
										print_ports_udp(print_all_out_file, udp);
										print_out_hex(packet, print_all_out_file);
									}
								}
							}
							break;
						}
					}
				}
				break;
			default:
				if (tcp_com_out_count == 0) {
					printf("~~~~~~~~~~~~~~~~~~~~~~~\nComplete communication:\n~~~~~~~~~~~~~~~~~~~~~~~\n", udp_com_count);
					fprintf(print_all_out_file, "~~~~~~~~~~~~~~~~~~~~~~~\nComplete communication:\n~~~~~~~~~~~~~~~~~~~~~~~\n", udp_com_count);
					tcp_com_out_count++;
				}

				//zapisane cisla packetov porovnam s cislom aktualneho packetu a ak sa rovnaju tak pokracujem
				int packet_is_in_array = 0;
				for (int i = 0; i <= tcp_com_count; i++) {
					if (com_packets != NULL && packet_count == *(com_packets + i))
						packet_is_in_array = 1;
				}
				if (packet_is_in_array == 0)
					continue;

				frame_type = get_frame_type(packet, print_all_out_file, ethernet, ieee, 0);
				if (frame_type == 1) {						//ak EthernetII
					protocol_number = get_protocol_name(print_all_out_file, protocol_file, ethernet->type, '#', 0);
					if (protocol_number == 2048) {				//IP
						ip = (struct ip_header*)(packet + ETHERNET_HEAD_LEN);
						int_dump = get_protocol_name(print_all_out_file, protocol_file, ip->protocol, '~', 0);
						if (ip->version > 69) { ip_options = ip->version - 69; } //0x45
						ip_options = ip_options * 4;

						if (ip->protocol == 6) {			//TCP
							tcp = (struct tcp_header*)(packet + ETHERNET_HEAD_LEN + IP_HEAD_LEN + ip_options);
							tcp->src_port = swap_bytes(tcp->src_port);
							tcp->dst_port = swap_bytes(tcp->dst_port);
							if ((tcp->src_port == menu_protocol_number) || (tcp->dst_port == menu_protocol_number)) {
								incrementer++;
								if ((incrementer <= 10) || (incrementer > (protocol_counter - 10))) {
									if (incrementer == 1) 
										announce_communication(print_all_out_file, 1);
									print_all_ipv4_base(packet, print_all_out_file, protocol_file, packet_count, ethernet, ieee, ip);
									int_dump = get_protocol_name(print_all_out_file, protocol_file, menu_protocol_number, '*', 1);
									print_ports_tcp(print_all_out_file, tcp);
									print_out_hex(packet, print_all_out_file);
									if (incrementer == 1)
										announce_communication(print_all_out_file, 1);
								}
							}
						}
					}
				}
				break;
			}	
		}
		ethernet = NULL;
		ip = NULL;
		tcp = NULL;
		udp = NULL;
		pcap_close(pcap);
	}




	if (num_input == 11) {

		fprintf(print_all_out_file, "List of all LLDP protocols:\n");
		int incrementer = 0;
		packet_count = 0;

		while (return_value = pcap_next_ex(pcap, &pcap_header, &packet) >= 0) {


			ethernet = (struct ethernet_header*)(packet);
			ethernet->type = swap_bytes(ethernet->type);
			packet_count++;
			frame_type = get_frame_type(packet, print_all_out_file, ethernet, ieee, 0);	//return 1 je EthernetII, 0 a 2 a 3 ak je IEEE
			if (frame_type == 1) {						//ak EthernetII
				protocol_number = get_protocol_name(print_all_out_file, protocol_file, ethernet->type, '#', 0);
				if (protocol_number == 35020) {			//ak LLDP

					print_start(packet, print_all_out_file, packet_count);
					int_dump = get_frame_type(packet, print_all_out_file, ethernet, ieee, 1);	//return 1 je EthernetII, 0 je IEEE
					print_MAC_addresses(packet, print_all_out_file);
					int_dump = get_protocol_name(print_all_out_file, protocol_file, ethernet->type, '#', 1);


					incrementer++;

					print_out_hex(packet, print_all_out_file);
				}
			}
		
			
		}
		fprintf(print_all_out_file, "\nNumber of LLDP packets : %d\n", incrementer);
		printf("\nNumber of LLDP packets : %d\n\n", incrementer);
	}





	char action;
	cout << "Do you want to analyze another packet? [Y/n]" << endl;
	cin >> action;
	switch (action) {
		case 'Y':
			fprintf(print_all_out_file, "\n\n***************************************************************\n**************************next Packet**************************\n***************************************************************\n\n");
			fclose(print_all_out_file);
			fclose(protocol_file);
			goto main_begining;
			break;
		case 'y':
			fprintf(print_all_out_file, "\n\n***************************************************************\n**************************next Packet**************************\n***************************************************************\n\n");
			fclose(print_all_out_file);
			fclose(protocol_file);
			goto main_begining;
			break;
		case 'n':
			break;
		case 'N':
			break;
		default:
			cout << "Wrong input\n";	
			break;
	}
	fprintf(print_all_out_file, "\n\n***************************************************************\n****************************END_END****************************\n***************************************************************\n\n");
	fclose(print_all_out_file);
	fclose(protocol_file);

	return 0;
}