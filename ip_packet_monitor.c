/**
 * Program: IP Packet Monitor
 * Author: Kyle Luoma
 * Date: 16 January 2019
 * Version 0.2
 * 
 * Console output format derived from: Raw socket tutorial
 * https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
 * 
 **/


#include <stdio.h>
#include <time.h>
#include <stdlib.h>             /* Includes malloc() function */
#include <signal.h>             /* Includes SIG_IGN handler function  */
#include <string.h>             /* Includes memset() function */
#include <linux/if_ether.h>     /* Contains definitions of all protocols */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdbool.h>


void interruptHandler(int sig);
int  saveHeaderDataToFile(unsigned char *buffer, FILE *fp);
int  extractAndDisplayPacket(unsigned char *buffer, bool displayData);
void waitAndReceivePacket(unsigned char* buffer, int sock_r);
void getTimeString(char* timeStringBuffer);
FILE* createAndOpenFile();

bool EXIT_PROGRAM = false;

int main(int argc, char *argv[]) {
    
    /* --- Invoke interrupt handler to terminate program when ctrl-c entered by user --- */
    signal(SIGINT, interruptHandler);
    
    /* --- Program properties --- */
    bool printData = false;                     //Display data in octal form when printing packet data to console

    /* ---Create a file to save traffic--- */
    FILE *file;
    file = createAndOpenFile();
    
    int sock_r;
    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_r < 0) {
        printf("Error in socket\n");
        return -1;
    }
    
    /* ---Reception of the network packet--- */
    /* To receive data: */
    unsigned char *buffer = (unsigned char *) malloc(65536); 
    memset(buffer, 0, 65536);
    struct sockaddr saddr;
    int buflen, saddr_len = sizeof(saddr);
    
    /* Receive a network packet and copy in to buffer: */
    buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *) &saddr_len);
    if(buflen < 0) {
        printf("Error in reading recvfrom function\n");
        return -1;
    }
    printf("Capturing packets:");
    char inputChar;
    int packetSize;
    bool keepRunning = true;
    
    /* --- Packet capture loop, run until user terminates (ctrl-c) --- */
    while(keepRunning & !EXIT_PROGRAM) {
        fprintf(stdout, ".");
        waitAndReceivePacket(buffer, sock_r);
        //packetSize = extractAndDisplayPacket(buffer, printData);
        packetSize = saveHeaderDataToFile(buffer, file);
    }
    
    /* --- Release system resources: --- */
    fclose(file);
    free(buffer);
}

void /*unsigned char*/ waitAndReceivePacket(unsigned char* buffer, int sock_r) {
    /* ---Reception of the network packet--- */
    /* To receive data: */
    struct sockaddr saddr;
    int buflen, saddr_len = sizeof(saddr);
    
    /* Receive a network packet and copy in to buffer: */
    buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *) &saddr_len);
    if(buflen < 0) {
        printf("Error in reading recvfrom function\n");
    }
    return;
}

int saveHeaderDataToFile(unsigned char *buffer, FILE *fp) {
    char timeString[24];
    getTimeString(timeString);
    struct ethhdr *eth = (struct ethhdr*)(buffer);
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = ip->saddr;
    dest.sin_addr.s_addr = ip->daddr;
    
    /* eth_src_addr */
    fprintf(fp, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X,", 
            eth->h_source[0], 
            eth->h_source[1],
            eth->h_source[2],
            eth->h_source[3],
            eth->h_source[4],
            eth->h_source[5]
    );
    /* eth_dst_addr */
    fprintf(fp, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X,",
            eth->h_dest[0],
            eth->h_dest[1],
            eth->h_dest[2],
            eth->h_dest[3],
            eth->h_dest[4],
            eth->h_dest[5]
    );
    /* eth_prot */
    fprintf(fp, "%d,", eth->h_proto);
    /* IP_vers */
    fprintf(fp, "%d,", (unsigned int)ip->version);
    /* IHL bytes*/
    fprintf(fp, "%d,", ((unsigned int)ip->ihl)*4);
    /* type_svc */
    fprintf(fp, "%d,", (unsigned int)ip->tos);
    /* tot_len */
    fprintf(fp, "%d,", ip->tot_len);
    /* id */
    fprintf(fp, "%d,", ip->id);
    /* TTL */
    fprintf(fp, "%d,", ip->ttl);
    /* IP_prot */
    fprintf(fp, "%d,", (unsigned int)ip->protocol);
    /* hdr_chksm */
    fprintf(fp, "%d,", ip->check);
    /* src_ip */
    fprintf(fp, "%s,", inet_ntoa(source.sin_addr));
    /* dst_ip */
    fprintf(fp, "%s\n", inet_ntoa(dest.sin_addr));
    return ip->tot_len;
}


/**
 * Extract and display headers in the packet buffer.
 * Parameters: *buffer   - memory location of packet
 *             printData - make true to print packet data, false for only headers
 * Return: Total packet size in bytes as int.
 **/
int extractAndDisplayPacket(unsigned char *buffer, bool printData) {
    char timeString[24];
    getTimeString(timeString);
    /* ---Extract the ethernet header--- */
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    printf("\nEthernet Header\n");
    printf("\t|- Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
            eth->h_source[0], 
            eth->h_source[1],
            eth->h_source[2],
            eth->h_source[3],
            eth->h_source[4],
            eth->h_source[5]
    );
    printf("\t|- Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
            eth->h_dest[0],
            eth->h_dest[1],
            eth->h_dest[2],
            eth->h_dest[3],
            eth->h_dest[4],
            eth->h_dest[5]
    );
    printf("\t|- Protocol : %d\n", eth->h_proto);
    
    /* ---Extract the IP header--- */
    unsigned short iphdrlen;
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    printf("\nIP Header\n");
    printf("\t|- Version : %d\n", (unsigned int)ip->version);
    printf("\t|- Internet Header Length : %d DWORDS or %d Bytes\n", 
            (unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
    printf("\t|- Type of Service : %d\n", (unsigned int)ip->tos);
    printf("\t|- Total Length : %d Bytes\n", ip->tot_len);
    printf("\t|- Identification : &d\n", ip->id);
    printf("\t|- Time to Live : %d\n", ip->ttl);
    printf("\t|- Protocol : %d\n", (unsigned int)ip->protocol);
    printf("\t|- Header Checksum : %d\n", ip->check);
    printf("\t|- Source IP        : %s\n", inet_ntoa(source.sin_addr));
    printf("\t|- Destination   IP : %s\n", inet_ntoa(dest.sin_addr));
    printf("TIME: %s", timeString);
    
    int sizeOfHeaders = sizeof(struct ethhdr) + (ip->ihl * 4) + 20/*sizeof(struct tcphdr)*/;
    
    if(printData) {
        char *packetData = buffer + sizeOfHeaders;
        printf("\t|- Data : \n\t");
        int printedOnLine = 0;
        for(int i = 0; i < ip->tot_len - sizeOfHeaders; i++) {
            if(packetData[i]) {
                printf("\%.2X ", (unsigned char)packetData[i]);
                printedOnLine++;
                if(printedOnLine % 16 == 0) {
                    printf("\n\t");
                }
            }
        }
    }
    
    printf("\n");
    return ip->tot_len;
}

void interruptHandler(int sig) {
    char userResponse;
    signal(sig, SIG_IGN);
    printf("Confirm exit (y/n): ");
    userResponse = getchar();
    if(userResponse == 'y' || userResponse == 'Y') { 
        EXIT_PROGRAM = true; 
    } else {
        signal(SIGINT, interruptHandler);
    }
    getchar();
}

void getTimeString(char* timeStringBuffer) {
    time_t timeData;
    time(&timeData);
    struct tm *gmTime = gmtime(&timeData);
    
    snprintf(timeStringBuffer, 24, "Y%dM%dD%dH%dM%dS%d", 
        gmTime->tm_year + 1900, 
        gmTime->tm_mon + 1, 
        gmTime->tm_mday, 
        gmTime->tm_hour, 
        gmTime->tm_min, 
        gmTime->tm_sec);
}

FILE* createAndOpenFile() {
    /* ---Create a file to save traffic--- */
    char timeString[24];
    getTimeString(timeString);
    char fileName[29];
    sprintf(fileName, "%s%s", timeString, ".csv");
    FILE *file;
    file = fopen(fileName, "w");
    fprintf(file, "eth_src_addr,eth_dst_addr,eth_prot,IP_vers,IHL,type_svc,tot_len,id,TTL,IP_prot,hdr_chksm,src_ip,dst_ip\n");
    return file;
}