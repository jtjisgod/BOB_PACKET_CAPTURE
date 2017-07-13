#include <pcap.h>
#include <stdio.h>

#define MAC_SIZE 18
#define ETHERNET_OFFSET 14
#define TCP_OFFSET 34
#define IP_SIZE 16
#define WORD 4 // In TCP, 1 WORD = 4 Bytes

#define SRC_MAC 12
#define DEST_MAC 6

char* getMac(u_char *packet, int i) {
	static char buf[MAC_SIZE] = "";
	snprintf(buf, MAC_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x", packet[--i], packet[--i], packet[--i], packet[--i], packet[--i], packet[--i]);
	return buf;

}

int isInternetProtocol(u_char *packet) {
	if(packet[12]==8 && packet[13]==0)	{ return 1; }
	return 0;
}

int isTCP(u_char *packet) {
	if(packet[ETHERNET_OFFSET + 9] == 6)	{ return 1; }
	return 0;
}

char* getSrcIP(u_char *packet) {
	static char buf[IP_SIZE] = "";
	int i = ETHERNET_OFFSET + 15;
	snprintf(buf, IP_SIZE, "%d.%d.%d.%d", packet[i--], packet[i--], packet[i--], packet[i--]);
	return buf;
}

char* getDestIP(u_char *packet) {
	static char buf[IP_SIZE] = "";
	int i = ETHERNET_OFFSET + 19;
	snprintf(buf, IP_SIZE, "%d.%d.%d.%d", packet[i--], packet[i--], packet[i--], packet[i--]);
	return buf;
}

int getSrcPort(u_char *packet)	{
	return packet[TCP_OFFSET+0] * 0x100 + packet[TCP_OFFSET+1];
}

int getDestPort(u_char *packet) {
	return packet[TCP_OFFSET+2] * 0x100 + packet[TCP_OFFSET+3];
}

int getData(u_char *packet, int size) {
	u_char n = packet[TCP_OFFSET+12] >> 4;
	int DATA_OFFSET = n * 4;
	return &(packet[TCP_OFFSET+DATA_OFFSET]);
}

int main(int argc, char *argv[])
{
	pcap_t *handle;					/* Session handle */
	char *dev;						/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char *packet;			/* The actual packet */

	dev = pcap_lookupdev(errbuf);

	/* Error 제어 { */
		if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf); net = 0; mask = 0; }
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle)); return(2); }
		if (pcap_setfilter(handle, &fp) == -1) { fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle)); return(2); }
	/*}*/

	while(1) {
	    pcap_next_ex(handle, &header, &packet);
		int i = 0;

		printf("\n -> Source Mac Address : %s", getMac(packet, SRC_MAC));
		printf("\n -> Destination Mac Address : %s", getMac(packet, DEST_MAC));

		// Ethernet Protocol 이라면
		if(!isInternetProtocol(packet))	{ continue; }

		printf("\n -> getSrcIP : %s", getSrcIP(packet));
		printf("\n -> getDestIP : %s", getDestIP(packet));

		if(!isTCP(packet)) { continue; }

		printf("\n -> getSrcPort : %d", getSrcPort(packet));
		printf("\n -> getDestPort : %d", getDestPort(packet));

		printf("\n -> DATA : %s", getData(packet, 12));

	}

	pcap_close(handle);

	printf("\n\n");

 	return(0);
}

// tcp.sport, tcp.dport / data
