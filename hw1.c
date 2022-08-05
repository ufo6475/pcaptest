#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>



typedef struct _packet_header{
	struct timeval time;
	unsigned int caplen;
	unsigned int len;
}packet_header;

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






int main(){

	char fname[256];
	FILE *fp=NULL;
	if((fp=fopen("./input.pcap","r"))==NULL){
		perror("Failed to open file");
	}
	unsigned char buffer;
	for(int i=0;i<24;i++){
		memset(&buffer,0,sizeof(buffer));
		fscanf(fp,"%c",&buffer);
		}
	int tmp=0;
	int pnum=1;
	while(!feof(fp)){

		//Get packet header
		long timesec=0;
		long timeusec=0;
		unsigned int caplen=0;
		unsigned int len=0;
		if(fread(&timesec,4,1,fp)!=1){
			break;
		}
		if(fread(&timeusec,4,1,fp)!=1){
			break;
		}
		if(fread(&caplen,4,1,fp)!=1){
			break;
		}
		if(fread(&len,4,1,fp)!=1){
			break;
		}
		packet_header nph;
		nph.time.tv_sec=timesec;
		nph.time.tv_usec=timeusec;
		nph.caplen=caplen;
		nph.len=len;
		
		struct tm *tm;
		tm=localtime(&nph.time.tv_sec);	

		//GET Ethernet
		unsigned char buffer[80000];
		if(fread(buffer,caplen,1,fp)!=1){
			break;
		}
		Ethernet neth;
		for(int i=0;i<6;i++){
			neth.dst_MAC[i]=buffer[i];
		}
		for(int i=6;i<12;i++){
			neth.src_MAC[i-6]=buffer[i];
		}
		neth.Type=buffer[12]<<8|buffer[13];
		

		//Get IP
		IP_header nIP;
		nIP.VER=buffer[14]>>4&0XFF;
		nIP.HLEN=(buffer[14]<<4&0xFF)>>4;
		nIP.DS=buffer[15];
		nIP.Total_length=buffer[16]<<8|buffer[17];
		nIP.ID=buffer[18]<<8|buffer[19];
		nIP.Flags=buffer[20]>>5;
		nIP.Frag_offset=(buffer[20]&0x1F)<<13|buffer[21];
		nIP.TTL=buffer[22];
		nIP.Protocol=buffer[23];
		nIP.Checksum=buffer[24]<<8|buffer[25];

		nIP.src_IP[0]=buffer[26];
		nIP.src_IP[1]=buffer[27];
		nIP.src_IP[2]=buffer[28];
		nIP.src_IP[3]=buffer[29];
	
		nIP.dst_IP[0]=buffer[30];
		nIP.dst_IP[1]=buffer[31];
		nIP.dst_IP[2]=buffer[32];
		nIP.dst_IP[3]=buffer[33];

		printf("No.: %d\n",pnum++);
		
		printf("Local time: %d/%d/%d %d:%d:%d.%06ld\n",tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,nph.time.tv_usec);
		
		printf("Captured length:%u, Actual length:%u, IP header length: %u, IP total length %u\n",nph.caplen,nph.len,nIP.HLEN*4,nIP.Total_length);
		if(neth.Type!=0x800){
			printf("Not IPv4\n\n");
			continue;
		}
		
		printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",neth.src_MAC[0],neth.src_MAC[1],neth.src_MAC[2],neth.src_MAC[3],neth.src_MAC[4],neth.src_MAC[5]);
		printf("Destication MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",neth.dst_MAC[0],neth.dst_MAC[1],neth.dst_MAC[2],neth.dst_MAC[3],neth.dst_MAC[4],neth.dst_MAC[5]);
		
		
		
		printf("Source IP : %d.%d.%d.%d\n",nIP.src_IP[0],nIP.src_IP[1],nIP.src_IP[2],nIP.src_IP[3]);

		printf("Destination IP : %d.%d.%d.%d\n",nIP.dst_IP[0],nIP.dst_IP[1],nIP.dst_IP[2],nIP.dst_IP[3]);


		if(nIP.Protocol==1){
			printf("Protocol: ICMP\n");
		}
		else if(nIP.Protocol==2){
			printf("Protocol: IGMP\n");
		}
		else if(nIP.Protocol==6){
			printf("Protocol: TCP\n");
		}
		else if(nIP.Protocol==17){
			printf("Protocol: UDP\n");
		}
		else if(nIP.Protocol==89){
			printf("Protocol: OSPF\n");
		}
		else{
			printf("Protocol: else\n");
		}
		
		printf("Identification: %d\n",nIP.ID);

		printf("Flags:0x%02X, ",nIP.Flags<<5);
		if(nIP.Flags==1)
			printf("More fragments\n");
		else if(nIP.Flags==2)
			printf("Don't framgent\n");
		else
			printf("\n");
			  
		printf("TTL: %d\n",nIP.TTL);
		printf("Type of service:0x%02X \n\n",nIP.DS);


	}

	fclose(fp);
}

