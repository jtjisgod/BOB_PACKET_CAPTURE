all: pcap_test
	gcc ./pcap_test.c -o pcap_test -lpcap

clean:
	rm -rf ./*.o ./pcap_test
