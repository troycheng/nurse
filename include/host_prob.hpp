#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>

#include "thread_pool.hpp"

#define MAX_SEND_THERAD 8
#define LOCAL_PORT 28724
#define SYN_SCAN  0
#define NULL_SCAN 1
#define FIN_SCAN  2
#define XMAS_SCAN 3
#define ACK_SCAN  4
#define UDP_SCAN  5

// Struct for calculate tcp header checksum
struct pseudo_header_tcp {
    unsigned int   src_addr;
    unsigned int   dst_addr;
    unsigned char  placeholder;
    unsigned char  protocol;
    unsigned short tcp_len;
    struct tcphdr  tcp;
};

// Class to store different types of ip & port
class host_addr {
    public:
        host_addr () : valid(false), port(0), _str("") {}

        host_addr (const std::string& i, uint16_t p) : valid(false), port(0), _str("") {
            this->fill(i, p);
        }

        bool fill(const std::string& i, uint16_t p) {
            memset(ip, 0, INET_ADDRSTRLEN);
            strncpy(ip, i.c_str(), (i.size() < INET_ADDRSTRLEN) ? i.size() : INET_ADDRSTRLEN-1);
            port = p;

            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(p);
            valid = (inet_pton(AF_INET, ip, &addr.sin_addr) > 0) ? true : false;

            return valid;
        }

        std::string to_str() {
            if (_str.empty()) {
                _str = (!valid) ? "" : std::string(ip) + ":" + std::to_string(port);
            }
            return _str;
        }

        bool                valid;
        uint16_t            port;
        char                ip[INET_ADDRSTRLEN];
        struct sockaddr_in  addr;

    private:
        std::string         _str;
};

// Class for sending syn packet & capture ack packet
class host_prob {
    public:
        host_prob(int, uint16_t);
        ~host_prob();

        int detect(const host_addr &);
        std::string capture();

        int get_recv_fd() { return this->recv_fd;}

    private:
        // util functions
        unsigned short calc_tcp_csum(uint16_t *, int);
        char* prep_tcp_packet(const host_addr &, const host_addr &, int);
        bool get_local_ip(char *, size_t);

        // functions for sending & capturing packet
        int create_detect_socket();
        int create_capture_socket();

    private:
        ThreadPool send_pool;
        host_addr  local_addr;
        int        recv_fd;
};

host_prob::host_prob(int send_thread_num = MAX_SEND_THERAD, uint16_t capture_port = LOCAL_PORT) : send_pool(send_thread_num) {
    char local_ip[INET_ADDRSTRLEN] = {'\0', };
    if (!get_local_ip(local_ip, INET_ADDRSTRLEN)) {
        throw std::runtime_error("Failed to get local ip");
    }

    local_addr.fill(std::string(local_ip), capture_port);

    recv_fd = create_capture_socket();
    if (recv_fd < 0) {
        throw std::runtime_error("Failed to create recv socket");
    }
}

host_prob::~host_prob() {
    if(this->recv_fd) close(recv_fd);
}

/*
 * Ref: http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
 * The checksum field is the 16 bit one's complement of the one's complement sum of all 16-bit words in the header and text.
 * If a segment contains an odd number of header and text octets to be checksummed, the last octet is padded on the right with
 * zeros to form a 16-bit word for checksum purposes. The pad is not transmitted as part of the segment. While computing the
 * checksum, the checksum field itself is replaced with zeros.
 * In other words, after appropriate padding, all 16-bit words are added using one's complement arithmetic. The sum is then
 * bitwise complemented and inserted as the checksum field.
 */
unsigned short host_prob::calc_tcp_csum(uint16_t *ptr, int pkt_len) {
    uint32_t csum = 0;

    //add 2 bytes / 16 bits at a time
    while (pkt_len > 1) {
        csum += *ptr++;
        pkt_len -= 2;
    }

    //add the last byte if present
    if (pkt_len == 1) {
        csum += *(uint8_t *)ptr;
    }

    //add the carries
    csum = (csum>>16) + (csum & 0xffff);
    csum = csum + (csum>>16);

    //return the one's compliment of calculated sum
    return((short)~csum);
}

char* host_prob::prep_tcp_packet(const host_addr &dst, const host_addr &src, int scan_type = SYN_SCAN) {
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    //Datagram to represent the packet
    char *datagram = (char*)calloc(4096,sizeof(char));

    //IP header
    ip_header = (struct iphdr *) datagram;

    //TCP header
    tcp_header = (struct tcphdr *) (datagram + sizeof (struct ip));

    //Fill in the IP Header
    ip_header->ihl      = 5;
    ip_header->version  = 4;
    ip_header->tos      = 0;
    ip_header->tot_len  = sizeof (struct iphdr) + sizeof (struct tcphdr);
    ip_header->id       = htons(9999); //to identify our packets easily on the wire in tcpdump
    ip_header->frag_off = htons(0);
    ip_header->ttl      = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check    = 0;
    ip_header->saddr    = inet_addr(src.ip);
    ip_header->daddr    = inet_addr(dst.ip);
    ip_header->check    = calc_tcp_csum((uint16_t *) datagram, ip_header->tot_len >> 1);

    //TCP Header
    tcp_header->source  = htons(src.port);
    tcp_header->dest    = htons(dst.port);
    tcp_header->seq     = htonl(888888); //to identify our packets easily on the wire in tcpdump
    tcp_header->ack_seq = 0;
    tcp_header->doff    = sizeof(struct tcphdr)/4;
    tcp_header->fin     = 0;
    tcp_header->syn     = 0;
    tcp_header->rst     = 0;
    tcp_header->psh     = 0;
    tcp_header->ack     = 0;
    tcp_header->urg     = 0;
    tcp_header->window  = htons(14600);
    tcp_header->check   = 0;
    tcp_header->urg_ptr = 0;

    //Set packet flag according scan_type
    switch(scan_type) {
        case SYN_SCAN:
            tcp_header->syn=1;
            break;
        case NULL_SCAN:
            break;
        case FIN_SCAN:
            tcp_header->fin=1;
            break;
        case XMAS_SCAN:
            tcp_header->fin=1;
            tcp_header->psh=1;
            tcp_header->urg=1;
            break;
        case ACK_SCAN:
            tcp_header->ack=1;  //this should be 1??
            break;
    }

    //Pseudo tcp header;
    struct pseudo_header_tcp psh;
    psh.src_addr    = inet_addr( src.ip );
    psh.dst_addr    = inet_addr( dst.ip );
    psh.placeholder = 0;
    psh.protocol    = IPPROTO_TCP;
    psh.tcp_len     = htons( sizeof(struct tcphdr) );

    memcpy(&psh.tcp , tcp_header , sizeof (struct tcphdr));

    //calculate the checksum of tcp header
    tcp_header->check = calc_tcp_csum((uint16_t*)&psh ,sizeof(struct pseudo_header_tcp));

    /*
    fprintf(stderr, "MESSAGE: Create packet to %s:%d with SYN:%d ACK:%d FIN:%d SEQ:%d\n",
       dst_ip, ntohs(tcp_header->dest),
       tcp_header->syn, tcp_header->ack, tcp_header->fin, ntohl(tcp_header->seq)
    );
    */
    return datagram;
}

bool host_prob::get_local_ip(char* ip, size_t len) {
    if (len < INET_ADDRSTRLEN) return false;

    char iface[8] = {'\0', };
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) {
        fprintf(stderr, "ERROR: open /proc/net/route failed\n");
        return false;
    }

    char dest[64] = {0, };
    while (!feof(f)) {
        if (fscanf(f, "%s %s %*[^\r\n]%*c", iface, dest) != 2) continue;
        if (strcmp(dest, "00000000") == 0) {
            fprintf(stderr, "DEBUG: Default iface is %s\n", iface);
            break;
        }
    }
    if (!strlen(iface)) {
        fprintf(stderr, "ERROR: didn't get default rout info, get local ip failed\n");
        return false;
    }

    struct ifaddrs * ifAddrStruct = NULL;
    struct ifaddrs * ifa          = NULL;
    void * tmpAddrPtr             = NULL;

    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr->sa_family == AF_INET) && (strcmp(ifa->ifa_name,iface) == 0)) {
            tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, tmpAddrPtr, ip, INET_ADDRSTRLEN);
        }
    }

    if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);

    return strlen(ip) ? true : false;
}

int host_prob::create_detect_socket() {
    int send_socket  = -1;
    int          one = 1;
    const int  * val = &one;
    if ((send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        return -1;
    }

    // set IP_HDRINCL to fill ip header by ourselves
    if (setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        return -1;
    }

    return send_socket;
}

int host_prob::detect(const host_addr &dst) {
    this->send_pool.enqueue([&] ()->int{
        // using thread_local to hold the socket for each thread
        static thread_local int send_fd = create_detect_socket();
        if (send_fd < 0) {
            fprintf(stderr, "ERROR: creaet send socket failed\n");
            return -1;
        }
        //fprintf(stderr, "DEBUG: using send socket %d\n", send_fd);

        char *packet = prep_tcp_packet(dst, this->local_addr);
        ssize_t bytes_sent = sendto(send_fd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
            (struct sockaddr *)&(dst.addr), sizeof(dst.addr)
        );
        free(packet);

        if (bytes_sent < 0) {
            fprintf(stderr, "ERROR: Send datagram to %s:%d failed\n", dst.ip, dst.port);
            return -3;
        }

        return 0;
    });

    return 0;
}

int host_prob::create_capture_socket() {
    // sudo tcpdump -dd -i eth0 'tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 and tcp[8:4] = 888889'
    // generate lsf code for packet which travel through device eth0
    static struct sock_filter tcp_filter [] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 11, 0, 0x000086dd },
        { 0x15, 0, 10, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 8, 0x00000006 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 6, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x50, 0, 0, 0x0000001b },
        { 0x45, 0, 3, 0x00000012 },
        { 0x40, 0, 0, 0x00000016 },
        { 0x15, 0, 1, 0x000d9039 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };

    // Because using lsf we need to create an ETH_PACKET capture socket
    // Because raw socket receive all packets flow through cur device
    // We need only one raw socket to deal with ack packets, so here use static variable
    static int recv_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (recv_socket < 0) {
        fprintf(stderr, "ERROR: Create recv socket failed\n");
        return -1;
    }

    // Set larger SO_RCVBUF so that it can hold more packets
    unsigned int optVal = 624640;
    unsigned int optLen = sizeof(optVal);
    if (setsockopt(recv_socket, SOL_SOCKET, SO_RCVBUF, &optVal, optLen) < 0) {
        fprintf(stderr, "ERROR: Cant't set recv buf for recv socket\n");
        return -1;
    }

    // Attach lsf filter
    struct sock_fprog filter;
    filter.len    = sizeof(tcp_filter)/sizeof(struct sock_filter);
    filter.filter = tcp_filter;
    if (setsockopt(recv_socket, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0) {
        fprintf(stderr, "ERROR: Can't set lsf filter for recv socket\n");
        return -1;
    }

    return recv_socket;
}

std::string host_prob::capture() {
    char recv_buf[ETH_FRAME_LEN];
    memset(recv_buf, 0, ETH_FRAME_LEN);

    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);
    ssize_t recv_len = recvfrom(this->recv_fd, recv_buf, ETH_FRAME_LEN, MSG_DONTWAIT, &saddr, &saddr_size);
    if (recv_len <= 0) {
        if (errno != EAGAIN || errno != EWOULDBLOCK) {
            fprintf(stderr, "ERROR: Revf from socket failed, %s\n", strerror(errno));
        }
        return "";
    }

    struct iphdr *iph = (struct iphdr*)(recv_buf + sizeof(struct ethhdr));
    unsigned short iph_len = (iph->ihl) * 4;
    if (iph_len < 20) {
        fprintf(stderr, "WARNING: Invalid IP header length: %u bytes\n", iph_len);
        return "";
    }

    if (iph->protocol == 6) {
        struct tcphdr *tcph = (struct tcphdr *)(recv_buf + iph_len + sizeof(struct ethhdr));

        struct in_addr source;
        source.s_addr = iph->saddr;

        char remote_ip[INET_ADDRSTRLEN] = {'\0',};
        int  remote_port = 0;
        inet_ntop(AF_INET, &source, remote_ip, INET_ADDRSTRLEN);
        remote_port = ntohs(tcph->source);

        if (tcph->syn == 1 && tcph->ack == 1 && iph->daddr == this->local_addr.addr.sin_addr.s_addr && tcph->dest == this->local_addr.addr.sin_port) {
            /*
            fprintf(stderr, "MESSAGE: Recv packet from %s:%d with SYN:%d ACK:%d FIN:%d RST:%d ACK_SEQ %d\n",
                remote_ip, remote_port,
                tcph->syn,
                tcph->ack,
                tcph->fin,
                tcph->rst,
                ntohl(tcph->ack_seq)
            );
            */
            return std::string(remote_ip) + ":" + std::to_string(remote_port);
        }
    }
    return "";
}
