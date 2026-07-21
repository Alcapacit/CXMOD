/*
 * conntrack.c — Connection tracking table analysis and overflow prevention
 *
 * BOTTLENECK: nf_conntrack table fills silently → "nf_conntrack: table full,
 * dropping packet" — one of the most common production Linux networking failures.
 * Root cause: default nf_conntrack_max is too small for busy servers.
 *
 * This module reads the live table, computes pressure, applies fixes.
 */

#include "cxmod.h"
#include <string.h>

/* ── conntrack table pressure ─────────────────────────────────────────────── */

int conntrack_read(cxmod_conntrack_t *ct)
{
    memset(ct, 0, sizeof(*ct));

    uint64_t count = 0, max = 0;
    int rc1 = proc_read_u64("/proc/sys/net/netfilter/nf_conntrack_count", &count);
    int rc2 = proc_read_u64("/proc/sys/net/netfilter/nf_conntrack_max",   &max);

    if (rc1 != CXMOD_OK || rc2 != CXMOD_OK) {
        /* conntrack may not be loaded */
        ct->count = 0; ct->max = 0; ct->used_pct = 0;
        ct->overflow_risk = false;
        return CXMOD_ENOFILE;
    }

    ct->count     = (uint32_t)count;
    ct->max       = (uint32_t)max;
    ct->used_pct  = (max > 0) ? (uint32_t)(count * 100 / max) : 0;
    ct->overflow_risk = (ct->used_pct >= 70);
    return CXMOD_OK;
}

int conntrack_print(const cxmod_conntrack_t *ct)
{
    cxmod_section("CONNTRACK TABLE");
    if (ct->max == 0) {
        cxmod_info("nf_conntrack module not loaded (conntrack not in use)");
        return CXMOD_OK;
    }

    print_bar("Connections", ct->count, ct->max, 40,
              ct->used_pct >= 80 ? COL_RED :
              ct->used_pct >= 60 ? COL_YELLOW : COL_GREEN);

    printf("  Count: %u  Max: %u  Used: %u%%\n",
           ct->count, ct->max, ct->used_pct);

    if (ct->used_pct >= 80) {
        if (cxmod_color) printf(COL_RED);
        printf("  CRITICAL: conntrack table near full — packets will be dropped!\n");
        if (cxmod_color) printf(COL_RESET);
        printf("  FIX: cxmod conntrack --fix\n");
    } else if (ct->used_pct >= 60) {
        if (cxmod_color) printf(COL_YELLOW);
        printf("  WARNING: conntrack usage >60%% — monitor closely\n");
        if (cxmod_color) printf(COL_RESET);
    } else {
        if (cxmod_color) printf(COL_GREEN);
        printf("  OK: conntrack usage is healthy\n");
        if (cxmod_color) printf(COL_RESET);
    }

    /* Read hashsize */
    uint64_t hashsize = 0;
    proc_read_u64("/proc/sys/net/netfilter/nf_conntrack_buckets", &hashsize);
    if (hashsize > 0)
        printf("  Hash buckets: %llu\n", (unsigned long long)hashsize);

    /* Timeouts — show current TCP established timeout */
    uint64_t tcp_estab = 0;
    if (proc_read_u64("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
                      &tcp_estab) == CXMOD_OK)
        printf("  TCP established timeout: %llu s\n", (unsigned long long)tcp_estab);

    return CXMOD_OK;
}

/*
 * conntrack_fix — scale up conntrack table to handle high traffic
 *
 * Formula:
 *   new_max   = RAM_MB * 1000 / 8   (generous: ~125 entries per MiB)
 *   hashsize  = new_max / 4          (kernel recommendation)
 *   tcp_estab = 1200 s               (reduce from default 432000 — 5 days!)
 *   tcp_close = 10 s                 (aggressive cleanup)
 */
int conntrack_fix(bool dry_run)
{
    cxmod_section("CONNTRACK FIX");

    /* Estimate RAM */
    uint64_t mem_kb = 0;
    FILE *mf = fopen("/proc/meminfo", "r");
    if (mf) {
        char line[128];
        while (fgets(line, sizeof(line), mf)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                sscanf(line + 9, "%llu", (unsigned long long *)&mem_kb);
                break;
            }
        }
        fclose(mf);
    }
    uint64_t mem_mb   = mem_kb / 1024;
    if (mem_mb == 0) mem_mb = 1024; /* fallback 1 GB */
    /*
     * Formula: ~64 bytes per conntrack entry.
     * Reserve at most 12.5% of RAM for the conntrack table.
     * Cap at 2M entries (sufficient for any realistic server load).
     * Floor at 65536 entries (minimum useful for busy systems).
     */
    uint64_t new_max = mem_mb * 1024 * 1024 / 8 / 64; /* 12.5% of RAM / 64 bytes */
    if (new_max < 65536)   new_max = 65536;
    if (new_max > 2097152) new_max = 2097152; /* hard cap: 2M entries */
    uint64_t hashsize = new_max / 4;

    printf("  Detected RAM: %llu MiB\n", (unsigned long long)mem_mb);
    printf("  New nf_conntrack_max:     %llu\n", (unsigned long long)new_max);
    printf("  New nf_conntrack_buckets: %llu\n", (unsigned long long)hashsize);
    printf("  New TCP established timeout: 1200 s (was 432000)\n");
    printf("  New TCP close timeout:        10 s\n");
    printf("  New TCP time-wait timeout:    10 s\n\n");

    if (!is_root() && !dry_run) {
        if (cxmod_color) printf(COL_RED);
        printf("  Need root. Re-run: sudo cx conntrack --fix\n");
        if (cxmod_color) printf(COL_RESET);
        return CXMOD_EPERM;
    }

    int errs = 0;
    #define APPLY(key, val) do { \
        int _rc = sysctl_write(key, val); \
        if (_rc == CXMOD_OK || _rc == CXMOD_ENOFILE) \
            cxmod_ok(key " = " val); \
        else { cxmod_warn("Failed to set " key); errs++; } \
    } while(0)

    #define APPLY_U(key, u) do { \
        char _b[32]; snprintf(_b,sizeof(_b),"%llu",(unsigned long long)(u)); \
        int _rc = sysctl_write(key, _b); \
        if (_rc == CXMOD_OK || _rc == CXMOD_ENOFILE) \
            cxmod_ok(key " = %llu", (unsigned long long)(u)); \
        else { cxmod_warn("Failed to set " key); errs++; } \
    } while(0)

    APPLY_U("net.netfilter.nf_conntrack_max", new_max);
    APPLY_U("net.netfilter.nf_conntrack_buckets", hashsize);
    APPLY("net.netfilter.nf_conntrack_tcp_timeout_established", "1200");
    APPLY("net.netfilter.nf_conntrack_tcp_timeout_close",       "10");
    APPLY("net.netfilter.nf_conntrack_tcp_timeout_time_wait",   "10");
    APPLY("net.netfilter.nf_conntrack_tcp_timeout_fin_wait",    "30");
    APPLY("net.netfilter.nf_conntrack_udp_timeout",             "30");
    APPLY("net.netfilter.nf_conntrack_udp_timeout_stream",      "180");
    APPLY("net.netfilter.nf_conntrack_generic_timeout",         "120");

    return errs ? CXMOD_ERR : CXMOD_OK;
}

/* ── Connection state counts from /proc/net/tcp ───────────────────────────── */

static void count_states_file(const char *path, cxmod_connstates_t *cs)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[CXMOD_LINE_MAX];
    fgets(line, sizeof(line), f); /* header */
    while (fgets(line, sizeof(line), f)) {
        unsigned int state;
        if (sscanf(line, "%*s %*s %*s %x", &state) != 1) continue;
        switch (state) {
        case 0x01: cs->established++; break;
        case 0x02: cs->syn_sent++;    break;
        case 0x03: cs->syn_recv++;    break;
        case 0x04: cs->fin_wait1++;   break;
        case 0x05: cs->fin_wait2++;   break;
        case 0x06: cs->time_wait++;   break;
        case 0x08: cs->close_wait++;  break;
        case 0x09: cs->last_ack++;    break;
        case 0x0A: cs->listen++;      break;
        case 0x0B: cs->closing++;     break;
        }
        cs->total++;
    }
    fclose(f);
}

int connstates_read(cxmod_connstates_t *cs)
{
    memset(cs, 0, sizeof(*cs));
    count_states_file("/proc/net/tcp",  cs);
    count_states_file("/proc/net/tcp6", cs);
    return CXMOD_OK;
}

void connstates_print(const cxmod_connstates_t *cs)
{
    cxmod_section("TCP CONNECTION STATES");
    printf("  Total sockets:    %u\n\n", cs->total);

    struct { const char *name; uint32_t count; const char *col; } rows[] = {
        { "ESTABLISHED",  cs->established, COL_GREEN  },
        { "LISTEN",       cs->listen,      COL_BLUE   },
        { "TIME_WAIT",    cs->time_wait,   COL_YELLOW },
        { "CLOSE_WAIT",   cs->close_wait,  COL_YELLOW },
        { "SYN_RECV",     cs->syn_recv,    cs->syn_recv > 100 ? COL_RED : COL_CYAN },
        { "SYN_SENT",     cs->syn_sent,    COL_CYAN   },
        { "FIN_WAIT1",    cs->fin_wait1,   COL_GRAY   },
        { "FIN_WAIT2",    cs->fin_wait2,   COL_GRAY   },
        { "LAST_ACK",     cs->last_ack,    COL_GRAY   },
        { "CLOSING",      cs->closing,     COL_GRAY   },
    };

    uint32_t max_count = 1;
    for (size_t i = 0; i < sizeof(rows)/sizeof(rows[0]); i++)
        if (rows[i].count > max_count) max_count = rows[i].count;

    for (size_t i = 0; i < sizeof(rows)/sizeof(rows[0]); i++)
        if (rows[i].count > 0)
            print_bar(rows[i].name, rows[i].count, max_count, 30, rows[i].col);

    if (cs->syn_recv > 100) {
        printf("\n");
        if (cxmod_color) printf(COL_RED);
        printf("  ALERT: %u SYN_RECV sockets — possible SYN flood!\n", cs->syn_recv);
        printf("  FIX: ensure net.ipv4.tcp_syncookies=1 and increase "
               "net.ipv4.tcp_max_syn_backlog\n");
        if (cxmod_color) printf(COL_RESET);
    }

    if (cs->time_wait > 10000) {
        printf("\n");
        if (cxmod_color) printf(COL_YELLOW);
        printf("  WARN: %u TIME_WAIT sockets — possible port exhaustion\n",
               cs->time_wait);
        printf("  FIX: cxmod tune --profile=balanced  (enables tw_reuse, "
               "reduces fin_timeout)\n");
        if (cxmod_color) printf(COL_RESET);
    }
}
