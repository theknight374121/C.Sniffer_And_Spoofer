

 //---cat rawicmp.c---

// Run as root or SUID 0, just datagram no data/payload

#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <netinet/ip.h>

#include <netpacket/packet.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

// Packet length

#define PCKT_LEN 8192

// May create separate header file (.h) for all

// headers' structures

//Ethernet headers
struct etheader {
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short int type;
};

// IP header's structure

struct ipheader {

 unsigned char      iph_ihl:4, /* Little-endian */

                    iph_ver:4;

 unsigned char      iph_tos;

 unsigned short int iph_len;

 unsigned short int iph_ident;

 unsigned char      iph_flags:3;

 unsigned short int iph_offset:13;

 unsigned char      iph_ttl;

 unsigned char      iph_protocol;

 unsigned short int iph_chksum;

 unsigned int       iph_sourceip;

 unsigned int       iph_destip;

};

//Structure of ICMP header
struct icmpheader{
	unsigned char type;
	unsigned char code;
	unsigned int checksum;
};

// Simple checksum function, may use others such as Cyclic Redundancy Check, CRC

unsigned short csum(unsigned short *buf, int len)

{

        unsigned long sum;

        for(sum=0; len>0; len--)

                sum += *buf++;

        sum = (sum >> 16) + (sum &0xffff);

        sum += (sum >> 16);

        return (unsigned short)(~sum);

}

 

int main(int argc, char *argv[])

{

int sd;

// No data, just datagram

char buffer[PCKT_LEN];

// The size of the headers
struct etheader *eth = (struct etheader *)buffer;

struct ipheader *ip = (struct ipheader *) (buffer+sizeof(struct etheader));

struct icmpheader *icmp = (struct icmpheader *)(buffer +sizeof(struct etheader)+ sizeof(struct ipheader));

struct sockaddr_in sin, din;

int one = 1;

const int *val = &one;

memset(buffer, 0, PCKT_LEN);

if(argc != 2)

{

printf("- Invalid parameters!!!\n");

printf("- Usage: %s <source hostname/IP> <target hostname/IP>\n", argv[0]);

exit(-1);

}

 

sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

if(sd < 0)

{

   perror("socket() error");

   exit(-1);

}

else

printf("socket()-SOCK_RAW and icmp protocol is OK.\n");
//Initalizing all ethernet headers
eth->dst_mac[0]=0x08;
eth->dst_mac[1]=0x00;
eth->dst_mac[2]=0x27;
eth->dst_mac[3]=0x58;
eth->dst_mac[4]=0x1d;
eth->dst_mac[5]=0xfb;
eth->src_mac[0]=0x01;
eth->src_mac[1]=0x02;
eth->src_mac[2]=0x03;
eth->src_mac[3]=0x04;
eth->src_mac[4]=0x05;
eth->src_mac[5]=0x06;
eth->type=htons(0x0800);

//Giving the interface name.
struct ifreq ifr;
char if_name[]={"eth13"};
size_t if_name_len=strlen(if_name);
if (if_name_len<sizeof(ifr.ifr_name)) {
    memcpy(ifr.ifr_name,if_name,if_name_len);
    ifr.ifr_name[if_name_len]=0;
} else {
    printf("interface name is too long");
}
if (ioctl(sd,SIOCGIFINDEX,&ifr)==-1) {
    printf("%s",strerror(errno));
}
int ifindex=ifr.ifr_ifindex;
 


// The source is redundant, may be used later if needed
struct sockaddr_ll addr={0};
addr.sll_family=AF_PACKET;
addr.sll_ifindex=ifindex;
addr.sll_halen=ETHER_ADDR_LEN;
addr.sll_protocol=htons(ETH_P_IP);
memcpy(addr.sll_addr,eth->dst_mac,ETHER_ADDR_LEN);


// Address family
memset(&sin,0,sizeof(sin));

sin.sin_family = AF_INET;

din.sin_family = AF_INET;

// Source IP, can be any, modify as needed

sin.sin_addr.s_addr = inet_addr("10.0.2.5");

din.sin_addr.s_addr = inet_addr(argv[1]);

// IP structure

ip->iph_ihl = 5;

ip->iph_ver = 4;

ip->iph_tos = 16;

ip->iph_len = sizeof(struct ipheader) + sizeof(struct icmpheader);

ip->iph_ident = htons(54321);

ip->iph_offset = 0;

ip->iph_ttl = 64;

ip->iph_protocol = 1; // ICMP

ip->iph_chksum = 0; // Done by kernel

 

// Source IP, modify as needed, spoofed, we accept through command line argument

ip->iph_sourceip = inet_addr("10.0.2.5");

// Destination IP, modify as needed, but here we accept through command line argument

ip->iph_destip = inet_addr(argv[1]);

//Filling in the ICMP packet
icmp->type = 0 ;
icmp->code= 0;
icmp->checksum= 0; //Done by kernel

// IP checksum calculation

ip->iph_chksum = csum((unsigned short *) buffer, (sizeof(struct ipheader) + sizeof(struct icmpheader)));

// Inform the kernel do not fill up the headers' structure, we fabricated our own
/*
if(setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, "eth13", sizeof("eth13")) < 0)

{

    perror("setsockopt() error");

    exit(-1);

}

else

   printf("setsockopt() is OK\n");

 
*/

// sendto() loop, send every 2 second for 50 counts

unsigned int count;

for(count = 0; count < 20; count++)

{

if(sendto(sd, buffer, (sizeof(struct etheader)+ ip->iph_len), 0, (struct sockaddr*)&addr,sizeof(struct sockaddr_ll)) < 0)

// Verify

{

   perror("sendto() error");

   exit(-1);

}

else

   printf("Count #%u - sendto() is OK\n", count);

sleep(2);

}

close(sd);

return 0;

}
