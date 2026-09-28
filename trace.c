/* 
 * Terminal Cmmds: cd - Enter file; cd .. - Exit file; ls - List all files; rm fileName - Remove file
 * Relevant Cmmds: ./trace FILENAME.pcap
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>

#pragma pack(1)

// ----- Structs ----- //
typedef enum {
    ARP,
    IP
} EthernetType;

typedef struct {
    uint8_t destMAC[6];
    uint8_t srcMAC[6];
    uint8_t typeValue[2];
    EthernetType etherType;
} EthernetHeader;

typedef struct {
    uint8_t opcode[2];
    uint8_t senderMAC[6];
    uint8_t senderIP[4];
    uint8_t targetMAC[6];
    uint8_t targetIP[4];
} ARPHeader;

typedef enum {
    ICMP,
    TCP,
    UDP
} ProtocolType;

typedef struct {
    uint8_t version[1];
    uint8_t headerLength[1];
    uint8_t TOS[1];
    uint8_t TTL[1];
    uint8_t protocol[1];
    ProtocolType protoType;
    uint8_t checksum[2];
    uint8_t senderIP [4];    
    uint8_t destIP[4];
} IPHeader;

typedef struct {
    uint8_t srcPort[2];
    uint8_t destPort[2];
    uint8_t seqNumber[4];
    uint8_t ackNumber[4];
    uint8_t dataOffset[1];
    uint8_t flag[1];
    uint8_t windowSize[2];
    uint8_t checksum[2];
} TCPHeader;

typedef struct {
    uint8_t srcPort[2];
    uint8_t destPort[2];
} UDPHeader;

// ----- Function Prototypes ----- //
void PrintEthernetHeader (const u_char *data, EthernetHeader *ethernet);
void PrintARPHeader (const u_char *data);
void PrintIPHeader (const u_char *data, IPHeader *ip);
void PrintICMPHeader (const u_char *data);
void PrintTCPHeader (const u_char *data);
void PrintUDPHeader (const u_char *data);

// ----- Macros ----- // 
// Ethernet Header //
#define ETHER_SIZE 14                               //Size of ethernet header
#define SRC_ADDR_START 6                            //Starting index for src address
#define ETHER_TYPE_START 12                         //Starting index for ethernet type
#define TYPE_ARP 2054                               //Decimal value for type: ARP
#define TYPE_IP 2048                                //Decimal value for type: IP
// ARP Header //
#define ARP_START 14                                //Starting index for ARP header
#define ARP_SIZE 46                                 //Size of ARP header (32 bytes) w/ ethernet header (14 bytes)
#define OPCODE_START 20                             //Starting index for opcode
#define S_MAC_START 22                              //Starting index for sender MAC
#define S_IP_START 28                               //Starting index for sender IP
#define T_MAC_START 32                              //Starting index for target MAC
#define T_IP_START 38                               //Starting index for target IP
// IP Header //
#define IP_START 14                                 //Starting index for IP header
#define TOS_START 15                                //Starting index for TOS subfield
#define TTL_START 22                                //Starting index for Time-To-Live
#define PROTOCOL_START 23                           //Starting index for protocol
#define PROTOCOL_ICMP 1                             //Decimal value for protocol: ICMP
#define PROTOCOL_TCP 6                              //Decimal value for protocol: TCP
#define PROTOCOL_UDP 17                             //Decimal value for protocol: UDP
#define IP_CHECKSUM_START 24                        //Starting index for checksum
#define IPS_IP_START 26                             //Starting index for IP's sender IP address
#define DEST_IP_START 30                            //Starting index for IP's dest IP address
// TCP Header //
#define TCP_START ipSize                            //Starting index for src port
#define TCP_DEST_PORT_START (TCP_START + 2)         //Starting index for dest port
#define SEQ_NUM_START (TCP_DEST_PORT_START + 2)     //Starting index for sequential number
#define ACK_NUM_START (SEQ_NUM_START + 4)           //Starting index for ACK number
#define DATA_OFFSET_START (ACK_NUM_START + 4)       //Starting index for data offset
#define SYN_FLAG_START (DATA_OFFSET_START + 1)      //Starting index for flags 
#define WINDOW_SIZE_START (SYN_FLAG_START + 1)      //Starting index for window size
#define TCP_CHECKSUM_START (WINDOW_SIZE_START + 2)  //Starting index for checksum
// UDP Header //
#define UDP_START ipSize                            //Starting index for src port
#define UDP_DEST_PORT_START (UDP_START + 2)         //Starting index for dest port
#define DNS_PORT 53                                 //Decimal value for DNS

// ----- Globals ----- // 
uint8_t ipSize = 74;                                //Max IP header (60) + ethernet header (14). Gets initialized again once header length is processed 

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("ERROR: Too many arguements passed\n");
        exit(1);
    }

    char buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcapFile;

    /// Reads and outputs packets from a pcap file ///
    // Open pcap file //
    pcapFile = pcap_open_offline(argv[1], buffer);
    if (pcapFile == NULL) {                     //Packet could not be opened
        printf("Error\n");
    } else {                                    //Packet successfully opened
        int8_t packetStatus;
        const u_char *data;
        struct pcap_pkthdr *header;

        // Read through each packet within the file //
        while ((packetStatus = pcap_next_ex(pcapFile, &header, &data)) > 0) {
            static uint16_t packetNumber = 1;
            EthernetHeader ethernet;
            IPHeader ip;

            printf("\nPacket number: %u  Packet Len: %u\n\n", packetNumber, header->len);
            PrintEthernetHeader(data, &ethernet);

            if (ethernet.etherType == ARP) {
                PrintARPHeader(data);

            } else if (ethernet.etherType == IP) {
                PrintIPHeader(data, &ip);

                if (ip.protoType == ICMP) {
                    PrintICMPHeader(data);

                } else if (ip.protoType == TCP) {
                    PrintTCPHeader(data);
                } else if (ip.protoType == UDP) {
                    PrintUDPHeader (data);
                }
            }

            ++packetNumber;
        }
        printf("\n");
        pcap_close(pcapFile);
    }
}

void PrintEthernetHeader (const u_char *data, EthernetHeader *ethernet) {
    uint16_t type;
    char *srcMAC, *destMAC;
    struct ether_addr macAddress;
    

    printf("\tEthernet Header\n");

    /// Assign EthernetHeader information to the corresponding data ///
    memcpy(ethernet->destMAC, data, 6);                         //Set dest address (6 bytes)
    memcpy(ethernet->srcMAC, data + SRC_ADDR_START, 6);         //Set src address (6 bytes)
    memcpy(ethernet->typeValue, data + ETHER_TYPE_START, 2);    //Set ether type (2 bytes)

    /// Print header information ///
    memcpy(&macAddress, ethernet->destMAC, 6);                  //Copy MAC array into ether_addr struct
    destMAC = ether_ntoa(&macAddress);                          //Convert struct to formatted MAC string 
    printf("\t\tDest MAC: %s\n", destMAC);

    memcpy(&macAddress, ethernet->srcMAC, 6);
    srcMAC = ether_ntoa(&macAddress);
    printf("\t\tSource MAC: %s\n", srcMAC);

    printf("\t\tType: ");
    type = ntohs(*(uint16_t*)ethernet->typeValue);
    switch (type) {
        case TYPE_ARP:
            printf("ARP\n");
            ethernet->etherType = ARP;
            break;
        case TYPE_IP:
            printf("IP\n");
                ethernet->etherType = IP;
            break;
        default:
            printf("ERROR: Unknown ethernet type\n");
            break;
    }
}

void PrintARPHeader (const u_char *data) {
    uint8_t opcode;
    char *senderMAC, *senderIP, *targetMAC, *targetIP;
    struct in_addr ipAddress;
    struct ether_addr macAddress;
    ARPHeader arp;
    

    printf("\n\tARP Header\n");

    /// Assign ARPHeader information to the corresponding data ///
    memcpy(arp.opcode, data + OPCODE_START, 2);     //Set opcode (2 bytes)
    memcpy(arp.senderMAC, data + S_MAC_START, 6);   //Set sender MAC (6 bytes)
    memcpy(arp.senderIP, data + S_IP_START, 4);     //Set sender IP (4 bytes)
    memcpy(arp.targetMAC, data + T_MAC_START, 6);   //Set target MAC (6 bytes)
    memcpy(arp.targetIP, data + T_IP_START, 6);     //Set target IP (6 bytes)

    /// Print header information ///
    printf("\t\tOpcode: ");
    opcode = ntohs(*(uint16_t*)arp.opcode);
    if (opcode == 1) {
        printf("Request\n");
    } else if (opcode == 2) {
        printf("Reply\n");
    }

    memcpy(&macAddress, arp.senderMAC, 6);          //Copy MAC array into ether_addr struct
    senderMAC = ether_ntoa(&macAddress);            //Convert struct to formatted MAC string
    printf("\t\tSender MAC: %s\n", senderMAC);

    memcpy(&ipAddress, arp.senderIP, 4);            //Copy IP array into in_addr struct
    senderIP = inet_ntoa(ipAddress);                //Convert struct to formatted IP string
    printf("\t\tSender IP: %s\n", senderIP);

    memcpy(&macAddress, arp.targetMAC, 6);
    targetMAC = ether_ntoa(&macAddress);
    printf("\t\tTarget MAC: %s\n", targetMAC);

    memcpy(&ipAddress, arp.targetIP, 4);
    targetIP = inet_ntoa(ipAddress);
    printf("\t\tTarget IP: %s\n", targetIP);
}

void PrintIPHeader (const u_char *data, IPHeader *ip) {
    char *senderIP, *destIP;
    struct in_addr ipAddress;

    printf("\n\tIP Header\n");

    /// Assign IPHeader information to the corresponding data ///
    memcpy(ip->version, data + IP_START, 1);                    //Set ip version (4 bits)
    memcpy(ip->headerLength, data + IP_START, 1);               //Set header length (4 bits)
    memcpy(ip->TOS, data + TOS_START, 1);                       //Set diff serv (6 bits) & ECN (2 bits)
    memcpy(ip->TTL, data + TTL_START, 1);                       //Set TTL (1 byte)
    memcpy(ip->protocol, data + PROTOCOL_START, 1);             //Set protocol (1 byte)
    //memcpy(ip->checksum, data + IP_CHECKSUM_START, 2);          //Set checksum (2 bytes)
    memcpy(ip->senderIP, data + IPS_IP_START, 4);               //Set sender address (4 bytes)
    memcpy(ip->destIP, data + DEST_IP_START, 4);                //Set dest address (4 bytes)

    /// Print header information ///
    uint8_t version = ip->version[0] >> 4;                      //IP version is upper 4 bits
    printf("\t\tIP Version: %u\n", version);
    uint8_t headerLength = (ip->headerLength[0] & 0x0F) * 4;    //Header length is lower 4 bits multiplied by 4
    printf("\t\tHeader Len (bytes): %u\n", headerLength);
    
    ipSize = IP_START + headerLength;                           //Recalculate IP size

    printf("\t\tTOS subfields:\n");
    uint8_t diffServ = ip->TOS[0] >> 2;                         //Diffserv is upper 6 bits
    printf("\t\t\tDiffserv bits: %u\n", diffServ);
    uint8_t ECN = ip->TOS[0] & 0x03;                            //ECN is lower 2 bits
    printf("\t\t\tECN bits: %u\n", ECN);

    printf("\t\tTTL: %u\n", ip->TTL[0]);

    printf("\t\tProtocol: ");
    switch (ip->protocol[0]) {
        case PROTOCOL_ICMP:
            printf("ICMP\n");
            ip->protoType = ICMP;
            break;
        case PROTOCOL_TCP:
            printf("TCP\n");
            ip->protoType = TCP;
            break;
        case PROTOCOL_UDP:
            printf("UDP\n");
            ip->protoType = UDP;
            break;
        default:
            printf("ERROR: Unknown protocol\n");
            break;
    }

    printf("\t\tChecksum:\n");

    memcpy(&ipAddress, ip->senderIP, 4);                        //Copy IP array into in_addr struct
    senderIP = inet_ntoa(ipAddress);                            //Convert struct to formatted IP string
    printf("\t\tSender IP: %s\n", senderIP);

    memcpy(&ipAddress, ip->destIP, 4);
    destIP = inet_ntoa(ipAddress);
    printf("\t\tDest IP: %s\n", destIP);
}

void PrintICMPHeader (const u_char *data) {
    printf("\n\tICMP Header\n");

    printf("\t\tType: ");
    if (data[ipSize] == 0) {
        printf("Reply\n");
    } else if (data[ipSize] == 8) {
        printf("Request\n");
    } else {
        printf("%u\n", data[ipSize]);
    }
}

void PrintTCPHeader (const u_char *data) {
    uint8_t dataOffset;
    uint16_t srcPort, destPort, windowSize;
    uint32_t seqNumber, ackNumber;
    TCPHeader tcp;

    printf("\n\tTCP Header\n");

    /// Assign TCPHeader information to the corresponding data ///
    memcpy(tcp.srcPort, data + TCP_START, 2);               //Set src port (2 bytes)
    memcpy(tcp.destPort, data + TCP_DEST_PORT_START, 2);    //Set dest port (2 bytes)
    memcpy(tcp.seqNumber, data + SEQ_NUM_START, 4);         //Set sequence number (4 bytes)
    memcpy(tcp.ackNumber, data + ACK_NUM_START, 4);         //Set ACK number (4 bytes)
    memcpy(tcp.dataOffset, data + DATA_OFFSET_START, 1);    //Set data offset (1 byte)
    memcpy(tcp.flag, data + SYN_FLAG_START, 1);             //Set flags (1 byte)
    memcpy(tcp.windowSize, data + WINDOW_SIZE_START, 2);    //Set window size (2 bytes)
    //memcpy(tcp.checksum, data + TCP_CHECKSUM_START, 2);   //Set checksum (2 bytes)

    /// Print header information ///
    srcPort = ntohs(*(uint16_t*)tcp.srcPort);
    printf("\t\tSource Port:  %u\n", srcPort);

    destPort = ntohs(*(uint16_t*)tcp.destPort);
    printf("\t\tDest Port:  %u\n", destPort);

    seqNumber = ntohl(*(uint32_t*)tcp.seqNumber);
    printf("\t\tSequence Number: %u\n", seqNumber);

    ackNumber = ntohl(*(uint32_t*)tcp.ackNumber);
    printf("\t\tACK Number: %u\n", ackNumber);

    dataOffset = (tcp.dataOffset[0] >> 4) * 4;              //Data offset is upper 4 bits multiplied by 4
    printf("\t\tData Offset (bytes): %u\n", dataOffset);

    printf("\t\tSYN Flag: ");
    if ((tcp.flag[0] & 0x02) == 0) {
        printf("No\n");
    } else {
        printf("Yes\n");
    }

    printf("\t\tRST Flag: ");
    if ((tcp.flag[0] & 0x04) == 0) {
        printf("No\n");
    } else {
        printf("Yes\n");
    }

    printf("\t\tFIN Flag: ");
    if ((tcp.flag[0] & 0x01) == 0) {
        printf("No\n");
    } else {
        printf("Yes\n");
    }

    printf("\t\tACK Flag: ");
    if ((tcp.flag[0] & 0x10) == 0) {
        printf("No\n");
    } else {
        printf("Yes\n");
    }

    windowSize = ntohs(*(uint16_t*)tcp.windowSize);
    printf("\t\tWindow Size:  %u\n", windowSize);

    printf("\t\tChecksum:\n");
}

void PrintUDPHeader (const u_char *data) {
    uint16_t srcPort, destPort;
    UDPHeader udp;

    printf("\n\tUDP Header\n");

    /// Assign TCPHeader information to the corresponding data ///
    memcpy(udp.srcPort, data + UDP_START, 2);               //Set src port (2 bytes)
    memcpy(udp.destPort, data + UDP_DEST_PORT_START, 2);    //Set dest port (2 bytes)

    /// Print header information ///
    srcPort = ntohs(*(uint16_t*)udp.srcPort);   
    if (srcPort == DNS_PORT) {
        printf("\t\tSource Port:  DNS\n");

    } else {
        printf("\t\tSource Port:  %u\n", srcPort);

    }

    destPort = ntohs(*(uint16_t*)udp.destPort);
    if (destPort == DNS_PORT) {
        printf("\t\tDest Port:  DNS\n");

    } else {
        printf("\t\tDest Port:  %u\n", destPort);

    }
}