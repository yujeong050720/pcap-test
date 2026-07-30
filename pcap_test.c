#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		struct libnet_ethernet_hdr* eth =
			(struct libnet_ethernet_hdr*)packet;

		struct libnet_ipv4_hdr* ip =
			(struct libnet_ipv4_hdr*)
			(packet + sizeof(struct libnet_ethernet_hdr));

		struct libnet_tcp_hdr* tcp =
			(struct libnet_tcp_hdr*)
			(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

		char *payload = (char *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
		int payloadLength = 20;

		printf(
			"src mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
			eth->ether_shost[0],
			eth->ether_shost[1],
			eth->ether_shost[2],
			eth->ether_shost[3],
			eth->ether_shost[4],
			eth->ether_shost[5]
		);

		printf(
			"dst mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
			eth->ether_dhost[0],
			eth->ether_dhost[1],
			eth->ether_dhost[2],
			eth->ether_dhost[3],
			eth->ether_dhost[4],
			eth->ether_dhost[5]
		);

		printf("src ip: %s\n", inet_ntoa(ip->ip_src));
		printf("dst ip: %s\n", inet_ntoa(ip->ip_dst));

		printf("src port: %u\n", ntohs(tcp->th_sport));
		printf("dst port: %u\n", ntohs(tcp->th_dport));

		printf(
			"payload: "
			"%02X %02X %02X %02X %02X "
			"%02X %02X %02X %02X %02X "
			"%02X %02X %02X %02X %02X "
			"%02X %02X %02X %02X %02X\n\n",
			payload[0] & 0xFF,
			payload[1] & 0xFF,
			payload[2] & 0xFF,
			payload[3] & 0xFF,
			payload[4] & 0xFF,
			payload[5] & 0xFF,
			payload[6] & 0xFF,
			payload[7] & 0xFF,
			payload[8] & 0xFF,
			payload[9] & 0xFF,
			payload[10] & 0xFF,
			payload[11] & 0xFF,
			payload[12] & 0xFF,
			payload[13] & 0xFF,
			payload[14] & 0xFF,
			payload[15] & 0xFF,
			payload[16] & 0xFF,
			payload[17] & 0xFF,
			payload[18] & 0xFF,
			payload[19] & 0xFF
		);

	}

	pcap_close(pcap);
}
