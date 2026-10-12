/* tsn_calib.c — attacker-side calibration probe (Approach A).
 *
 * While a temporary mirror copies the R-tagged member stream onto the attacker
 * port, this captures ONE legitimate 802.1CB frame and prints its R-TAG
 * sequence number + capture time, so the injected sequence can be positioned
 * a known offset AHEAD of the live legitimate sequence.
 *
 * Handles untagged and 802.1Q-tagged framing (ring is untagged, but be safe).
 * Also extracts the inner application sequence (tsn_send payload: magic,seq,...)
 * as a cross-check.
 *
 * Output (one line, machine-readable):
 *   CALIB t_cap_ns=<ns> rtag_seq=<u16> app_seq=<u32> vlan=<0|1>
 *
 * Build: gcc -O2 -o tsn_calib tsn_calib.c
 * Run:   sudo ./tsn_calib <iface> [timeout_s]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>



/* IEEE 802.1CB R-TAG EtherType and application payload marker. */
#define RTAG 0xF1C1u
#define MAGIC 0x46524552u

/* Wall-clock timestamp used in the calibration record. */
static uint64_t ns_now(void){ struct timespec t; clock_gettime(CLOCK_REALTIME,&t);
    return (uint64_t)t.tv_sec*1000000000ull + t.tv_nsec; }

int main(int argc, char **argv){
    if(argc < 2){ fprintf(stderr,"usage: %s <iface> [timeout_s]\n",argv[0]); return 1; }
    const char *iface = argv[1];
    double tmo = (argc>2)? atof(argv[2]) : 8.0;

    /* Raw socket required to access the R-TAG at Ethernet level. */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd<0){
        perror("socket"); 
        return 1;
    }
    struct ifreq ifr; 
    memset(&ifr,0,sizeof ifr);
    strncpy(ifr.ifr_name,iface,IFNAMSIZ-1);

    if(ioctl(fd,SIOCGIFINDEX,&ifr)<0){
        perror("SIOCGIFINDEX");
        return 1;
    }
    /*Only capture the selected attacker interface*/
    struct sockaddr_ll sll;
    memset(&sll,0,sizeof sll);
    sll.sll_family=AF_PACKET;
    sll.sll_protocol=htons(ETH_P_ALL);
    sll.sll_ifindex=ifr.ifr_ifindex;

    if(bind(fd,(struct sockaddr*)&sll,sizeof sll)<0)
    { perror("bind"); return 1;
    }

    /* mirrored frames are addressed to the listener MAC, not this NIC */
    struct packet_mreq mr;
    memset(&mr,0,sizeof mr);
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;

    if(setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) < 0)
        perror("PACKET_MR_PROMISC");

    uint8_t p[2048];
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC,&t0);
    for(;;){
        /* Clock for the calibration timeout, */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC,&now);

        if((now.tv_sec-t0.tv_sec)+(now.tv_nsec-t0.tv_nsec)/1e9 >= tmo){
            fprintf(stderr,"[calib] timeout, no R-tagged frame seen\n");
            return 2; }

        struct pollfd pf={.fd=fd,.events=POLLIN};

        if(poll(&pf,1,200)<=0) continue;

        ssize_t n = recv(fd,p,sizeof p,0);

        if(n < 18) continue;

        /* here determine the R-TAG offset.*/
        int vlan = 0, rtag_off = 12;
        uint16_t et = (p[12]<<8)|p[13];

        if(et == 0x8100){ vlan = 1; 
            rtag_off = 16;
            et = (p[16]<<8)|p[17];
        }
        if(et != RTAG) continue;

        /* R-TAG mapping: first EtherType (2) reserved field(2), seq(2) start right after the 0xF1C1 ethertype */
        int seq_off = rtag_off + 2 + 2;        /* +ethertype2? no: et is 2 bytes at rtag_off */
        /* layout: [.. ethertype@rtag_off (2)] [reserved (2)] [seq (2)] */
        seq_off = rtag_off + 2 + 2;

        if(n < seq_off + 2) continue;

        uint16_t seq = (p[seq_off]<<8)|p[seq_off+1];
        /* inner: after seq comes inner ethertype(2) + IP(20) + UDP(8) + payload(magic4, app4) */
        int inner = seq_off + 2;               /* inner ethertype */
        uint32_t app = 0;
        int have_app = 0;
        int pay = inner + 2 + 20 + 8;           /* start of UDP payload */
        if(n >= pay + 8){
            uint32_t magic = 
            (p[pay]<<24)|
            (p[pay+1]<<16)|
            (p[pay+2]<<8)|
            p[pay+3];

            if(magic == MAGIC){ app = (p[pay+4]<<24)|(p[pay+5]<<16)|(p[pay+6]<<8)|p[pay+7]; have_app=1; }
        }
        /* one calibration frame is enough for the subsequent attacks*/
        printf("CALIB t_cap_ns=%llu rtag_seq=%u app_seq=%u vlan=%d have_app=%d\n",
               (unsigned long long)ns_now(), seq, app, vlan, have_app);
        return 0;
    }
}
