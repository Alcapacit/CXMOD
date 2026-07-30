/*
 * iface.c — Network interface enumeration and statistics
 * Reads from /proc/net/dev and /sys/class/net/
 */

#include "cxmod.h"

/* Parse /proc/net/dev for a single interface name */
static int read_if_stats(const char *name, cxmod_iface_t *iface)
{
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return CXMOD_ERR;

    char line[CXMOD_LINE_MAX];
    /* skip 2 header lines */
    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        char ifname[CXMOD_IFNAMSIZ];
        unsigned long long rx_b, rx_p, rx_e, rx_d, rx_f, rx_c, rx_fi, rx_m;
        unsigned long long tx_b, tx_p, tx_e, tx_d, tx_f, tx_c, tx_fi, tx_m;

        /* strip leading whitespace from interface name */
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *p = line;
        while (*p == ' ') p++;
        /* safe bounded copy */
        size_t nl = strlen(p);
        if (nl >= CXMOD_IFNAMSIZ) nl = CXMOD_IFNAMSIZ - 1;
        memcpy(ifname, p, nl);
        ifname[nl] = '\0';

        if (strcmp(ifname, name) != 0) continue;

        sscanf(colon + 1,
               "%llu %llu %llu %llu %llu %llu %llu %llu "
               "%llu %llu %llu %llu %llu %llu %llu %llu",
               &rx_b, &rx_p, &rx_e, &rx_d, &rx_f, &rx_c, &rx_fi, &rx_m,
               &tx_b, &tx_p, &tx_e, &tx_d, &tx_f, &tx_c, &tx_fi, &tx_m);

        iface->rx_bytes = (uint64_t)rx_b; iface->rx_pkts = (uint64_t)rx_p;
        iface->rx_errs  = (uint64_t)rx_e; iface->rx_drop = (uint64_t)rx_d;
        iface->tx_bytes = (uint64_t)tx_b; iface->tx_pkts = (uint64_t)tx_p;
        iface->tx_errs  = (uint64_t)tx_e; iface->tx_drop = (uint64_t)tx_d;
        /* rx_missed is not in /proc/net/dev; read from ethtool sysfs if available */
        iface->rx_missed = 0;

        fclose(f);
        return CXMOD_OK;
    }
    fclose(f);
    return CXMOD_ENODEV;
}

/* Read IP address from /proc/net/if_inet6 or via ioctl */
static void read_ip4(const char *name, cxmod_iface_t *iface)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { strcpy(iface->ip4, "N/A"); return; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in sa;
        memcpy(&sa, &ifr.ifr_addr, sizeof(sa));
        if (!inet_ntop(AF_INET, &sa.sin_addr, iface->ip4, sizeof(iface->ip4)))
            strcpy(iface->ip4, "?");
    } else {
        strcpy(iface->ip4, "N/A");
    }

    /* MAC address */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char *m = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        snprintf(iface->mac, sizeof(iface->mac),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 m[0], m[1], m[2], m[3], m[4], m[5]);
    } else {
        strcpy(iface->mac, "N/A");
    }

    /* Link status */
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0)
        iface->up = !!(ifr.ifr_flags & IFF_UP);

    /* MTU */
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
        iface->mtu = (uint32_t)ifr.ifr_mtu;

    close(fd);
}

/* Read speed from /sys/class/net/<iface>/speed */
static void read_speed(const char *name, cxmod_iface_t *iface)
{
    char path[CXMOD_PATH_MAX];
    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", name);
    uint64_t v = 0;
    if (proc_read_u64(path, &v) == CXMOD_OK && (int64_t)v > 0)
        iface->speed_mbps = (uint32_t)v;
    else
        iface->speed_mbps = 0;
}

int iface_get(const char *name, cxmod_iface_t *iface)
{
    memset(iface, 0, sizeof(*iface));
    strncpy(iface->name, name, CXMOD_IFNAMSIZ - 1);
    read_ip4(name, iface);
    read_speed(name, iface);
    return read_if_stats(name, iface);
}

int iface_list(cxmod_iface_t *ifaces, int max)
{
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return -1;

    char line[CXMOD_LINE_MAX];
    fgets(line, sizeof(line), f); /* header 1 */
    fgets(line, sizeof(line), f); /* header 2 */

    int n = 0;
    while (n < max && fgets(line, sizeof(line), f)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *p = line;
        while (*p == ' ') p++;
        iface_get(p, &ifaces[n]);
        n++;
    }
    fclose(f);
    return n;
}

static void fmt_bytes(uint64_t b, char *buf, size_t len)
{
    if      (b >= (uint64_t)1 << 30) snprintf(buf, len, "%.1f GiB", b / (double)(1<<30));
    else if (b >= (uint64_t)1 << 20) snprintf(buf, len, "%.1f MiB", b / (double)(1<<20));
    else if (b >= (uint64_t)1 << 10) snprintf(buf, len, "%.1f KiB", b / (double)(1<<10));
    else                              snprintf(buf, len, "%llu B", (unsigned long long)b);
}

void iface_print(const cxmod_iface_t *iface)
{
    char rx_s[32], tx_s[32];
    fmt_bytes(iface->rx_bytes, rx_s, sizeof(rx_s));
    fmt_bytes(iface->tx_bytes, tx_s, sizeof(tx_s));

    const char *state_col = iface->up ? COL_GREEN : COL_RED;
    const char *state_str = iface->up ? "UP" : "DOWN";

    printf("  %-12s ", iface->name);
    if (cxmod_color) printf("%s", state_col);
    printf("%-5s", state_str);
    if (cxmod_color) printf(COL_RESET);
    printf("  %-16s  %-19s", iface->ip4, iface->mac);
    if (iface->speed_mbps > 0)
        printf("  %5u Mb/s", iface->speed_mbps);
    else
        printf("  %5s", "---");
    printf("  MTU %-5u", iface->mtu);
    printf("  RX %-12s  TX %-12s", rx_s, tx_s);
    if (iface->rx_errs + iface->tx_errs > 0)
        printf(COL_RED "  errs %llu" COL_RESET,
               (unsigned long long)(iface->rx_errs + iface->tx_errs));
    if (iface->rx_drop + iface->tx_drop > 0)
        printf(COL_YELLOW "  drop %llu" COL_RESET,
               (unsigned long long)(iface->rx_drop + iface->tx_drop));
    putchar('\n');
}

void iface_print_all(const cxmod_iface_t *ifaces, int n)
{
    if (cxmod_color) printf(COL_BOLD);
    printf("  %-12s %-5s  %-16s  %-19s  %-9s  %-8s  %-13s  %-13s\n",
           "Interface", "State", "IPv4", "MAC",
           "Speed", "MTU", "RX", "TX");
    if (cxmod_color) printf(COL_RESET);
    for (int i = 0; i < n; i++) iface_print(&ifaces[i]);
}
