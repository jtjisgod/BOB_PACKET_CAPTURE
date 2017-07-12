#include <pcap.h>
#include <stdio.h>

char* getSrcMac(u_char *packet) {
	static char buf[18] = "";
	int i = 6;
	snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", packet[--i], packet[--i], packet[--i], packet[--i], packet[--i], packet[--i]);
	return buf;
}

char* getDestMac(u_char *packet) {
	static char buf[18] = "";
	int i = 12;
	snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", packet[--i], packet[--i], packet[--i], packet[--i], packet[--i], packet[--i]);
	return buf;
}

int isInternetProtocol(u_char *packet) {
	if(packet[12]==8 && packet[13]==0)	{ return 1; }
	return 0;
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Error 제어 { */
	dev = pcap_lookupdev(errbuf);
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

		printf("\n -> getSrcMac : %s", getSrcMac(packet));
		printf("\n -> getDestMac : %s", getDestMac(packet));

		// Ethernet Protocol 이라면
		if(isInternetProtocol(packet))	{

		}
	}

	pcap_close(handle);

 	return(0);
}
