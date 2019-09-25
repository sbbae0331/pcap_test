#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
	printf("\n"); // refresh

    struct pcap_pkthdr* header;
    const u_char *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
	
	u_char *ptr = (u_char *)packet;

	// Ethernet Header: dst mac / src mac / IP Check (IPv4 (0x0800))
	u_char *etn_ptr = ptr;
	// dst mac
	printf("Destination MAC: ");
	for (int i = 0; i < 6; i++) printf("%02x:", *(ptr++)); printf("\n");
	// src mac
	printf("Source MAC: ");
	for (int i = 0; i < 6; i++) printf("%02x:", *(ptr++)); printf("\n");
	// IP Check (IPv4 (0x08 00))
	if (*(ptr++) == 0x08 && *(ptr++) == 0x00) printf("Type: IPv4\n");
	else continue;

	// IP Header: TCP Check / src ip / dst ip (TCP (6))
	u_char *ip_ptr = ptr = etn_ptr + 14; // (ethernet header length 14)
	int ip_header_len = (*(ip_ptr) & 0b00001111) * 4;
	int ip_total_len = *(ip_ptr+2) * 256 + *(ip_ptr+3);
	// TCP Check (TCP (6))
	if (*(ptr+=9) == 0x06) {
		printf("Protocol: TCP\n");
		// src ip
		ptr += 3;
		printf("Source IP: ");
		for (int i = 0; i < 4; i++) printf("%d.", *(ptr++)); printf("\n");
		// dst ip
		printf("Destination IP: ");
		for (int i = 0; i < 4; i++) printf("%d.", *(ptr++)); printf("\n");
	}
	else continue;

	// TCP Header: src port / dst port / Payload check (TCP Segment Len)
	u_char *tcp_ptr = ptr = ip_ptr + ip_header_len;
	int tcp_header_len = (*(ptr + 12) >> 4) * 4;
	// src port
	printf("Source Port: %d\n", *(ptr++) * 256 + *(ptr++));
	// dst port
	printf("Destination Port: %d\n", *(ptr++) * 256 + *(ptr++));
	// Payload check (TCP Segment Len)
	// TCP Payload Segment Size = IP total length - IP header length - TCP header len
 	int tcp_seg_size = ip_total_len - ip_header_len - tcp_header_len;


	// Payload hexa decimal value (32 bytes)
	u_char *payload_ptr = ptr = tcp_ptr + tcp_header_len;
	if (tcp_seg_size) {
		printf("Payload: ");
		for (int i = 0; i < 32; i++) printf("%02x ", *(ptr++)); 
		printf("\n");
	}
  }

  pcap_close(handle);
  return 0;
}
