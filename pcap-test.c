#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct _Ethernet{
	unsigned char dst_MAC[6];
	unsigned char src_MAC[6];
	unsigned int Type;
}Ethernet;

typedef struct _IP_header{
	unsigned char VER;
	unsigned char HLEN;
	unsigned char DS;
	unsigned short Total_length;
	unsigned short ID;
	unsigned char Flags;
	unsigned int Frag_offset;
	unsigned short TTL;
	unsigned short Protocol;
	unsigned int Checksum;
	unsigned char src_IP[4];
	unsigned char dst_IP[4];
	unsigned char Option[40];
}IP_header;

typedef struct _TCP_header{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int Sequence_number;
	unsigned int Ack_number;
	unsigned char HLEN;
	unsigned char Reserved;
	unsigned char urg;
	unsigned char ack;
	unsigned char psh;
	unsigned char rst;
	unsigned char syn;
	unsigned char fin;
	unsigned short Window_size;
	unsigned short CheckSum;
	unsigned short Urgent_pointer;
	unsigned int option[10];
}TCP_header;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	int no=1;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		Ethernet neth;
		for(int i=0;i<6;i++){
			neth.dst_MAC[i]=packet[i];
		}
		for(int i=6;i<12;i++){
			neth.src_MAC[i-6]=packet[i];
		}
		neth.Type=packet[12]<<8|packet[13];
		if(neth.Type!=0x0800)
			continue;

		IP_header nIP;
		nIP.VER=packet[14]>>4&0XFF;
		nIP.HLEN=(packet[14]<<4&0xFF)>>4;
		nIP.DS=packet[15];
		nIP.Total_length=packet[16]<<8|packet[17];
		nIP.ID=packet[18]<<8|packet[19];
		nIP.Flags=packet[20]>>5;
		nIP.Frag_offset=(packet[20]&0x1F)<<13|packet[21];
		nIP.TTL=packet[22];
		nIP.Protocol=packet[23];
		nIP.Checksum=packet[24]<<8|packet[25];

		nIP.src_IP[0]=packet[26];
		nIP.src_IP[1]=packet[27];
		nIP.src_IP[2]=packet[28];
		nIP.src_IP[3]=packet[29];
	
		nIP.dst_IP[0]=packet[30];
		nIP.dst_IP[1]=packet[31];
		nIP.dst_IP[2]=packet[32];
		nIP.dst_IP[3]=packet[33];

		if(nIP.Protocol!=0x06)
			continue;

		TCP_header nTCP_header;
		nTCP_header.src_port=packet[34]<<8|packet[35];
		nTCP_header.dst_port=packet[36]<<8|packet[37];
		nTCP_header.Sequence_number=packet[38]<<24|packet[39]<<16|packet[40]<<8|packet[41];
		nTCP_header.Ack_number=packet[42]<<24|packet[43]<<16|packet[44]<<8|packet[45];
		nTCP_header.HLEN=packet[46]>>4;
		nTCP_header.Reserved=0;
		nTCP_header.urg=(packet[47]>>5)&0x01;
		nTCP_header.ack=(packet[47]>>4)&0x01;
		nTCP_header.psh=(packet[47]>>3)&0x01;
		nTCP_header.rst=(packet[47]>>2)&0x01;
		nTCP_header.syn=(packet[47]>>1)&0x01;
		nTCP_header.fin=(packet[47])&0x01;
		nTCP_header.Window_size=packet[48]<<8|packet[49];
		nTCP_header.CheckSum=packet[50]<<8|packet[51];
		nTCP_header.Urgent_pointer=packet[52]<<8|packet[53];

		int next=54;
		if(nTCP_header.HLEN*4>20){
			int len=nTCP_header.HLEN*4-20;
			for(int i=0;i<len;i++){
				nTCP_header.option[i]=packet[next++];
			}
		}
		printf("No: %d\n",no++);
		printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",neth.src_MAC[0],neth.src_MAC[1],neth.src_MAC[2],neth.src_MAC[3],neth.src_MAC[4],neth.src_MAC[5]);
		printf("Destication MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",neth.dst_MAC[0],neth.dst_MAC[1],neth.dst_MAC[2],neth.dst_MAC[3],neth.dst_MAC[4],neth.dst_MAC[5]);
		printf("Source IP : %d.%d.%d.%d\n",nIP.src_IP[0],nIP.src_IP[1],nIP.src_IP[2],nIP.src_IP[3]);

		printf("Destination IP : %d.%d.%d.%d\n",nIP.dst_IP[0],nIP.dst_IP[1],nIP.dst_IP[2],nIP.dst_IP[3]);
		printf("Source Port: %u\n",nTCP_header.src_port);
		printf("Destination Port: %u\n",nTCP_header.dst_port);
		printf("Payload(Hexa): ");
		for(int i=0;i<10;i++){
			if(next+i>=header->caplen){
				continue;
			}
			printf("%02x",packet[next+i]);
		}
		printf("\n");

	}

	pcap_close(pcap);
}
