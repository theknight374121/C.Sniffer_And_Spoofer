#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define PCKT_LEN 1024
unsigned char buffer[PCKT_LEN];

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct etheader{
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short int ether_type;
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};



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
	unsigned short int checksum;
	unsigned short int id;
	unsigned short int seq;
	//char *outpayload;
	//char *data = (buffer+sizeof(struct ipheader)+8);
	
};

struct sniff_icmp{
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short int icmp_checksum;
	unsigned short int icmp_id;
	unsigned short int icmp_seq;
	//char *outpayload;
	//char *data=(buffer+sizeof(struct ipheader)+8);
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

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	printf("Got the packet.\n");	

/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ips;              /* The IP header */
	const struct sniff_icmp *icmps;		/*The sniffed icmp header */
	const char *inpayload;  

	int size_ip;
	int size_payload;
	ethernet = (struct sniff_ethernet *)packet;
	/* define/compute ip header offset */
	ips = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ips)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	icmps = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
	
	//details about incoming payload.
	inpayload=(packet + SIZE_ETHERNET + size_ip + 8);
	size_payload = ntohs(ips->ip_len) - (size_ip + 8);
	//printf("%s",inpayload);
	
	if (icmps->icmp_type==8){
		
//
//Here is where spoofing starts
//


int sd;
sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_ICMP);
// The size of the headers
struct etheader *eth = (struct etheader *)buffer;

struct ipheader *ip = (struct ipheader *) (buffer+sizeof(struct etheader));

struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct etheader)+sizeof(struct ipheader));
//
//
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
 





//to capture destination and source ip addresses.
struct sockaddr_in sin;
char dststr[INET_ADDRSTRLEN];
char srcstr[INET_ADDRSTRLEN];

int one = 1;
const int *val = &one;

memset(buffer, 0, PCKT_LEN);



if(sd < 0)
{	
	perror("socket() error");
	exit(-1);
}

//initialize the ethernet header
//transfering shost to dst_mac
char macStr[18];
int counter;
snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
         ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);

sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth->dst_mac[0], &eth->dst_mac[1], &eth->dst_mac[2], &eth->dst_mac[3], &eth->dst_mac[4], &eth->dst_mac[5]);

//transfering dhost to src_mac
snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
         ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth->src_mac[0], &eth->src_mac[1], &eth->src_mac[2], &eth->src_mac[3], &eth->src_mac[4], &eth->src_mac[5]);

//transfering the ether type
eth->ether_type=htons(ntohs(ethernet->ether_type));

// The source is redundant, may be used later if needed
//setting up the ethernet requiremens
struct sockaddr_ll addr={0};
addr.sll_family=AF_PACKET;
addr.sll_ifindex=ifindex;
addr.sll_halen=ETHER_ADDR_LEN;
addr.sll_protocol=htons(ETH_P_IP);
memcpy(addr.sll_addr,eth->dst_mac,ETHER_ADDR_LEN);

//Stores the destination ip address into str
inet_ntop(AF_INET,&ips->ip_src,srcstr,INET_ADDRSTRLEN);
inet_ntop(AF_INET,&ips->ip_dst,dststr,INET_ADDRSTRLEN);

// IP structure

ip->iph_ihl = 5;

ip->iph_ver = 4;

ip->iph_tos = 16;

ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + size_payload);

ip->iph_ident = htons(54321);

ip->iph_offset = 0;

ip->iph_ttl = 64;

ip->iph_protocol = 1; // ICMP

ip->iph_chksum = 0; // Done by kernel

 
// Address family
sin.sin_family = AF_INET;
sin.sin_addr.s_addr = inet_addr(dststr);

// Source IP, modify as needed, spoofed, we accept through command line argument
ip->iph_sourceip = inet_addr(dststr);

// Destination IP, modify as needed, but here we accept through command line argument
ip->iph_destip = inet_addr(srcstr);

//Filling in the ICMP packet
icmp->type = 0 ;
icmp->code= 0;
icmp->id = htons(ntohs(icmps->icmp_id));
icmp->seq = htons(ntohs(icmps->icmp_seq));



//Filling up our payload
	char *outpayload;
	outpayload = buffer + sizeof(struct etheader)+sizeof(struct ipheader)+8;
	for (counter=0; counter<size_payload;counter++){
		*outpayload=*inpayload;
		inpayload++;
		outpayload++;
	}

	
icmp->checksum= csum((unsigned short *)(buffer +sizeof(struct etheader)+ sizeof(struct ipheader)), (sizeof(struct icmpheader)+size_payload));
// Inform the kernel do not fill up the headers' structure, we fabricated our own

// IP checksum calculation

ip->iph_chksum = csum((unsigned short *) (buffer+sizeof(struct etheader)), (sizeof(struct ipheader)+sizeof(struct icmpheader)+size_payload));

//set socket
if(setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, "eth13", sizeof("eth13")) < 0)
{
    perror("setsockopt() error");
    exit(-1);
}


unsigned int count=0;

if(sendto(sd, buffer, (sizeof(struct etheader)+ sizeof(struct ipheader)+sizeof(struct icmpheader)+size_payload), 0, (struct sockaddr*)&addr,sizeof(struct sockaddr_ll)) < 0)
{
   perror("sendto() error");
   exit(-1);
}
else{
printf("Forged and sent the packet\n");

}
close(sd);

} // If block closes here which decides if the package is an ICMP request package.
	
return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "icmp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;			/* number of packets to capture */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

