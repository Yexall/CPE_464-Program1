# CSC 357, Assignment 4
# Summer '24
# > -c = Converts to .o file which compiles w/ out linking; -g = Display debugging information;
# > -ansi = C version 1989; -pedantic = Adhere strictly to version of C being used; -std=c99 = Latest C version;

LIBS = -lpcap
CFLAGS = -g -Wall -Wextra -pedantic -std=gnu99 

all:  trace

# pcap: pcap.c pcap.h
# 	gcc $(CFLAGS) pcap.c -o pcap $(LIBS)
# #	valgrind --leak-check=full ./httpd

trace: trace.c checksum.c checksum.h
	gcc $(CFLAGS) trace.c checksum.c -o trace $(LIBS)
#	valgrind --leak-check=full ./httpd

clean:
	rm -f pcap trace checksum
