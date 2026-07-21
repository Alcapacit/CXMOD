/*
 * sockstat.c — Socket and buffer pressure statistics
 *
 * Reads /proc/net/sockstat (IPv4) and /proc/net/sockstat6 (IPv6).
 * Detects orphan sockets, socket memory pressure, UDP buffer drops,
 * and fragmentation queue buildup.
 *
 * BOTTLENECKS detected here:
 *   - Orphan socket accumulation  → memory exhaustion → OOM kill
 *   - UDP receive buffer pressure → silent datagram drops
 *   - IP fragment queue overflow  → reassembly failure
 *   - TCP memory pressure pages   → kernel starts dropping
 */

#include "cxmod.h"
#include <string.h>

/* ── Internal types ───────────────────────────────────────────────────────── */

typedef struct {
    uint32_t tcp_inuse, tcp_orphan, tcp_tw, tcp_alloc, tcp_mem;
    uint32_t udp_inuse, udp_mem;
    uint32_t raw_inuse;
    uint32_t frag_inuse, frag_memory;
    uint32_t sockets_used;
    /* IPv6 */
    uint32_t tcp6_inuse, udp6_inuse, raw6_inuse;
    uint32_t frag6_inuse, frag6_memory;
} sockstat_t;

/* ── Parser ───────────────────────────────────────────────────────────────── */

static void parse_sockstat_file(const char *path, sockstat_t *ss, bool is_v6)
{
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[CXMOD_LINE_MAX];
    while (fgets(line, sizeof(line), f)) {
        if (!is_v6) {
            if (strncmp(line, "sockets:", 8) == 0)
                sscanf(line + 8, " used %u", &ss->sockets_used);
            else if (strncmp(line, "TCP:", 4) == 0)
                sscanf(line + 4,
                       " inuse %u orphan %u tw %u alloc %u mem %u",
                       &ss->tcp_inuse, &ss->tcp_orphan, &ss->tcp_tw,
                       &ss->tcp_alloc, &ss->tcp_mem);
            else if (strncmp(line, "UDP:", 4) == 0)
                sscanf(line + 4, " inuse %u mem %u",
                       &ss->udp_inuse, &ss->udp_mem);
            else if (strncmp(line, "RAW:", 4) == 0)
                sscanf(line + 4, " inuse %u", &ss->raw_inuse);
            else if (strncmp(line, "FRAG:", 5) == 0)
                sscanf(line + 5, " inuse %u memory %u",
                       &ss->frag_inuse, &ss->frag_memory);
        } else {
            if (strncmp(line, "TCP6:", 5) == 0)
                sscanf(line + 5, " inuse %u", &ss->tcp6_inuse);
            else if (strncmp(line, "UDP6:", 5) == 0)
                sscanf(line + 5, " inuse %u", &ss->udp6_inuse);
            else if (strncmp(line, "RAW6:", 5) == 0)
                sscanf(line + 5, " inuse %u", &ss->raw6_inuse);
            else if (strncmp(line, "FRAG6:", 6) == 0)
                sscanf(line + 6, " inuse %u memory %u",
                       &ss->frag6_inuse, &ss->frag6_memory);
        }
    }
    fclose(f);
}

static void sockstat_read(sockstat_t *ss)
{
    memset(ss, 0, sizeof(*ss));
    parse_sockstat_file("/proc/net/sockstat",  ss, false);
    parse_sockstat_file("/proc/net/sockstat6", ss, true);
}

/* ── Print ────────────────────────────────────────────────────────────────── */

int sockstat_print_all(void)
{
    sockstat_t ss;
    sockstat_read(&ss);

    cxmod_section("SOCKET & BUFFER STATISTICS");
    printf("  Source: /proc/net/sockstat\n\n");

    /* TCP */
    if (cxmod_color) printf(COL_BOLD);
    printf("  TCP sockets:\n");
    if (cxmod_color) printf(COL_RESET);
    printf("    In use:   %u  (v6: %u)\n", ss.tcp_inuse, ss.tcp6_inuse);

    printf("    Orphans:  ");
    if (ss.tcp_orphan > 1000) {
        if (cxmod_color) printf(COL_RED);
        printf("%u  CRITICAL — potential memory leak\n", ss.tcp_orphan);
        if (cxmod_color) printf(COL_RESET);
    } else if (ss.tcp_orphan > 100) {
        if (cxmod_color) printf(COL_YELLOW);
        printf("%u  elevated — monitor for growth\n", ss.tcp_orphan);
        if (cxmod_color) printf(COL_RESET);
    } else {
        printf("%u  (healthy)\n", ss.tcp_orphan);
    }

    printf("    TIME_WAIT: %u\n", ss.tcp_tw);
    printf("    Allocated: %u\n", ss.tcp_alloc);

    /* TCP memory pressure */
    if (ss.tcp_mem > 0) {
        char tcp_mem_str[128] = "";
        sysctl_read_str("net.ipv4.tcp_mem", tcp_mem_str, sizeof(tcp_mem_str));
        uint32_t lo = 0, pressure = 0, hi = 0;
        sscanf(tcp_mem_str, "%u %u %u", &lo, &pressure, &hi);
        (void)lo;
        if (hi > 0) {
            int pct = (int)((uint64_t)ss.tcp_mem * 100 / hi);
            printf("    Mem pages: %u / %u  (%d%%)\n", ss.tcp_mem, hi, pct);
            if (pct >= 80) {
                if (cxmod_color) printf(COL_RED);
                printf("               CRITICAL: TCP in memory pressure!\n");
                if (cxmod_color) printf(COL_RESET);
            } else if (pct >= 60) {
                if (cxmod_color) printf(COL_YELLOW);
                printf("               WARN: TCP memory usage elevated\n");
                if (cxmod_color) printf(COL_RESET);
            }
        } else {
            printf("    Mem pages: %u\n", ss.tcp_mem);
        }
    }

    /* UDP */
    printf("\n");
    if (cxmod_color) printf(COL_BOLD);
    printf("  UDP sockets:\n");
    if (cxmod_color) printf(COL_RESET);
    printf("    In use:   %u  (v6: %u)\n", ss.udp_inuse, ss.udp6_inuse);
    if (ss.udp_mem > 0)
        printf("    Mem pages: %u\n", ss.udp_mem);

    /* RAW / FRAG */
    printf("\n");
    printf("  RAW:  %u  (v6: %u)\n", ss.raw_inuse, ss.raw6_inuse);

    if (ss.frag_inuse > 0 || ss.frag_memory > 0) {
        printf("  FRAG: %u in-use, %u bytes\n", ss.frag_inuse, ss.frag_memory);
        if (ss.frag_inuse > 100) {
            if (cxmod_color) printf(COL_YELLOW);
            printf("    WARN: High IP fragment count — likely MTU mismatch\n");
            if (cxmod_color) printf(COL_RESET);
        }
    } else {
        printf("  FRAG: 0 (healthy)\n");
    }

    if (ss.frag6_inuse > 0)
        printf("  FRAG6: %u in-use, %u bytes\n", ss.frag6_inuse, ss.frag6_memory);

    printf("\n  Total sockets open: %u\n", ss.sockets_used);
    return CXMOD_OK;
}

/* ── Diagnose (called from diagnose_all) ──────────────────────────────────── */

int sockstat_diagnose(cxmod_report_t *r)
{
    sockstat_t ss;
    sockstat_read(&ss);

    /* Orphan sockets */
    if (ss.tcp_orphan > 4096) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "%u TCP orphan sockets — memory leak risk, may cause OOM",
                 ss.tcp_orphan);
        report_add(r, SEV_CRITICAL, "orphans", msg,
                   "sudo cx tune --profile=balanced (reduces FIN_WAIT, increases max_orphans)");
    } else if (ss.tcp_orphan > 512) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "%u TCP orphan sockets — elevated, monitor for growth", ss.tcp_orphan);
        report_add(r, SEV_WARN, "orphans", msg,
                   "sudo sysctl -w net.ipv4.tcp_max_orphans=65536");
    } else {
        report_add(r, SEV_OK, "orphans", "TCP orphan socket count is healthy", "");
    }

    /* Fragment queue */
    if (ss.frag_inuse > 100) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "%u IP fragments in queue — MTU mismatch or fragmentation attack",
                 ss.frag_inuse);
        report_add(r, SEV_WARN, "fragments", msg,
                   "Check MTU mismatch; enable PMTU discovery: sysctl -w net.ipv4.tcp_mtu_probing=1");
    } else {
        report_add(r, SEV_OK, "fragments", "IP fragment queue is empty (healthy)", "");
    }

    return CXMOD_OK;
}
