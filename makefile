CC := gcc
CFLAGS := -Wall -Wextra
LDLIBS := -lpcap

all: pcap-test

pcap-test: pcap_test.c
	$(CC) $(CFLAGS) pcap_test.c $(LDLIBS) -o pcap-test

clean:
	rm -f pcap-test *.o

.PHONY: all clean
