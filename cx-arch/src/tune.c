/*
 * tune.c — TCP/IP kernel stack tuning via /proc/sys
 *
 * BOTTLENECK: Linux defaults are designed for the kernel team's 28.8k modems
 * of the 1990s.  Default rmem/wmem of 212 KiB caps throughput at ~17 Mbit/s
 * on a 10ms RTT link — 98% below a 1 Gbit NIC's capacity.
 *
 * BDP formula: optimal_buffer = bandwidth_bps * rtt_sec
 * Example: 1 Gbit/s * 10ms = 1,250,000 bytes = 1.25 MiB min buffer
 * Linux default: 212 KiB → leaves 83% of link bandwidth unused.
 *
 * This module applies named profiles that fix all major defaults.
 */

#include "cxmod.h"
#include <string.h>

/* ── Parameter table ──────────────────────────────────────────────────────── */

typedef struct {
    const char *key;
    const char *values[PROFILE_COUNT]; /* indexed by cxmod_profile_t */
} tune_param_t;

/*
 * Profile order: BALANCED, HIGH_THROUGHPUT, LOW_LATENCY, SATELLITE, HARDENED
 *
 * Key decisions:
 *   rmem/wmem_max:  BDP-sized for each workload
 *   tcp_rmem/wmem:  min/default/max triple
 *   BBR:            for high-throughput and satellite (high-BDP, tolerates loss)
 *   CUBIC:          for balanced and low-latency
 *   tcp_fastopen=3: client+server TFO (saves one RTT on reconnects)
 *   tw_reuse=1:     recycle TIME_WAIT sockets (safe for outgoing connections)
 *   fin_timeout:    reduce from 60s default — frees ports faster
 *   syncookies=1:   always; SYN flood protection with no downside
 *   timestamps=0:   (hardened only) prevents uptime fingerprinting
 *   rp_filter=1:    strict reverse-path — blocks spoofed packets
 */

static const tune_param_t PARAMS[] = {
/* key                                    BALANCED         HIGH_THROUGHPUT   LOW_LATENCY      SATELLITE        HARDENED  */
{"net.core.rmem_max",                   {"33554432",       "134217728",       "16777216",      "268435456",     "8388608"     }},
{"net.core.wmem_max",                   {"33554432",       "134217728",       "16777216",      "268435456",     "8388608"     }},
{"net.core.rmem_default",               {"1048576",        "4194304",         "262144",        "16777216",      "262144"      }},
{"net.core.wmem_default",               {"1048576",        "4194304",         "262144",        "16777216",      "262144"      }},
{"net.core.netdev_max_backlog",         {"50000",          "300000",          "10000",         "300000",        "5000"        }},
{"net.core.somaxconn",                  {"4096",           "65535",           "4096",          "65535",         "1024"        }},
{"net.core.optmem_max",                 {"65536",          "65536",           "65536",         "65536",         "65536"       }},
{"net.ipv4.tcp_rmem",                   {"4096 1048576 33554432",
                                                           "4096 4194304 134217728",
                                                                              "4096 262144 16777216",
                                                                                               "4096 16777216 268435456",
                                                                                                                "4096 87380 8388608"  }},
{"net.ipv4.tcp_wmem",                   {"4096 1048576 33554432",
                                                           "4096 4194304 134217728",
                                                                              "4096 262144 16777216",
                                                                                               "4096 16777216 268435456",
                                                                                                                "4096 87380 8388608"  }},
{"net.ipv4.tcp_mem",                    {"786432 1048576 26214400",
                                                           "786432 1048576 104857600",
                                                                              "786432 1048576 16777216",
                                                                                               "786432 1048576 268435456",
                                                                                                                "786432 1048576 8388608"  }},
{"net.ipv4.tcp_congestion_control",     {"cubic",          "bbr",             "cubic",         "bbr",           "cubic"       }},
{"net.ipv4.tcp_window_scaling",         {"1",              "1",               "1",             "1",             "1"           }},
{"net.ipv4.tcp_timestamps",             {"1",              "1",               "1",             "1",             "0"           }},
{"net.ipv4.tcp_sack",                   {"1",              "1",               "1",             "1",             "1"           }},
{"net.ipv4.tcp_dsack",                  {"1",              "1",               "1",             "1",             "1"           }},
{"net.ipv4.tcp_ecn",                    {"1",              "1",               "1",             "0",             "0"           }},
{"net.ipv4.tcp_fastopen",               {"3",              "3",               "3",             "0",             "0"           }},
{"net.ipv4.tcp_slow_start_after_idle",  {"0",              "0",               "0",             "0",             "1"           }},
{"net.ipv4.tcp_no_metrics_save",        {"1",              "1",               "1",             "1",             "1"           }},
{"net.ipv4.tcp_tw_reuse",               {"1",              "1",               "1",             "1",             "0"           }},
{"net.ipv4.tcp_fin_timeout",            {"30",             "15",              "10",            "60",            "30"          }},
{"net.ipv4.tcp_keepalive_time",         {"300",            "300",             "60",            "600",           "1800"        }},
{"net.ipv4.tcp_keepalive_intvl",        {"30",             "30",              "10",            "60",            "15"          }},
{"net.ipv4.tcp_keepalive_probes",       {"5",              "5",               "3",             "5",             "5"           }},
{"net.ipv4.tcp_max_syn_backlog",        {"16384",          "65536",           "8192",          "65536",         "4096"        }},
{"net.ipv4.tcp_max_tw_buckets",         {"1440000",        "2000000",         "720000",        "2000000",       "1440000"     }},
{"net.ipv4.tcp_max_orphans",            {"65536",          "131072",          "32768",         "131072",        "32768"       }},
{"net.ipv4.tcp_syncookies",             {"1",              "1",               "1",             "1",             "1"           }},
{"net.ipv4.tcp_syn_retries",            {"6",              "6",               "3",             "6",             "3"           }},
{"net.ipv4.tcp_synack_retries",         {"5",              "5",               "2",             "5",             "2"           }},
{"net.ipv4.ip_local_port_range",        {"10240 65535",    "1024 65535",      "10240 65535",   "1024 65535",    "32768 60999" }},
{"net.ipv4.ip_local_reserved_ports",   {"",               "",                "",              "",              ""            }},
{"net.ipv4.conf.all.rp_filter",         {"1",              "1",               "1",             "1",             "1"           }},
{"net.ipv4.conf.default.rp_filter",     {"1",              "1",               "1",             "1",             "1"           }},
{"net.ipv4.icmp_echo_ignore_broadcasts",{"1",              "1",               "1",             "1",             "1"           }},
{"net.ipv4.icmp_ignore_bogus_error_responses",{"1",        "1",               "1",             "1",             "1"          }},
{"net.ipv4.tcp_mtu_probing",            {"1",              "1",               "0",             "1",             "0"           }},
{"net.ipv4.tcp_base_mss",               {"1024",           "1024",            "1024",          "512",           "1024"        }},
{NULL, {NULL,NULL,NULL,NULL,NULL}}
};

static const char *PROFILE_NAMES[] = {
    "balanced", "high_throughput", "low_latency", "satellite", "hardened"
};
static const char *PROFILE_DESCS[] = {
    "General-purpose web/app servers — sensible defaults for any Linux server",
    "Bulk transfers, CDN, file servers — maximise throughput, use BBR",
    "Real-time: gaming, VoIP, interactive SSH — minimise latency",
    "High-RTT WAN links (>100ms) — satellite, intercontinental, huge BDP",
    "Security-hardened: reduce attack surface, strict RP filter, no TFO",
};

const char *profile_name(cxmod_profile_t p) { return PROFILE_NAMES[p]; }
const char *profile_desc(cxmod_profile_t p) { return PROFILE_DESCS[p]; }

/* ── Apply a profile ──────────────────────────────────────────────────────── */

int tune_apply_profile(cxmod_profile_t profile, bool dry_run)
{
    if (profile < 0 || profile >= PROFILE_COUNT) return CXMOD_ERR;

    cxmod_section("APPLYING PROFILE");
    printf("  Profile:     %s\n", PROFILE_NAMES[profile]);
    printf("  Description: %s\n", PROFILE_DESCS[profile]);
    printf("  Dry-run:     %s\n\n", dry_run ? "YES (no changes made)" : "NO (writing to /proc/sys)");

    if (!is_root() && !dry_run) {
        if (cxmod_color) printf(COL_RED);
        printf("  Need root. Re-run: sudo cx tune --profile=%s\n",
               PROFILE_NAMES[profile]);
        if (cxmod_color) printf(COL_RESET);
        return CXMOD_EPERM;
    }

    int applied = 0, errors = 0, skipped = 0;

    for (int i = 0; PARAMS[i].key != NULL; i++) {
        const char *val = PARAMS[i].values[profile];
        if (!val || val[0] == '\0') { skipped++; continue; }

        if (dry_run) {
            printf("  sysctl -w %s=\"%s\"\n", PARAMS[i].key, val);
            applied++;
            continue;
        }

        int rc = sysctl_write(PARAMS[i].key, val);
        if (rc == CXMOD_OK) {
            if (cxmod_verbose)
                cxmod_ok("%-52s = %s", PARAMS[i].key, val);
            applied++;
        } else if (rc == CXMOD_ENOFILE) {
            if (cxmod_verbose)
                cxmod_info("%-52s N/A (kernel param not present)", PARAMS[i].key);
            skipped++;
        } else if (rc == CXMOD_EPERM) {
            cxmod_warn("%-52s PERMISSION DENIED", PARAMS[i].key);
            errors++;
        } else {
            cxmod_warn("%-52s ERROR", PARAMS[i].key);
            errors++;
        }
    }

    printf("\n");
    if (!dry_run) {
        if (errors == 0) {
            cxmod_ok("Applied %d parameters (%d skipped, not available on this kernel)",
                     applied, skipped);
        } else {
            cxmod_warn("Applied %d parameters, %d errors, %d skipped",
                       applied, errors, skipped);
        }
    } else {
        printf("  [DRY-RUN] Would apply %d parameters\n", applied);
    }
    return errors ? CXMOD_ERR : CXMOD_OK;
}

/* ── Single parameter ─────────────────────────────────────────────────────── */

int tune_set_param(const char *key, const char *value, bool dry_run)
{
    if (dry_run) {
        printf("  [DRY-RUN] sysctl -w %s=\"%s\"\n", key, value);
        return CXMOD_OK;
    }
    if (!is_root()) return CXMOD_EPERM;

    int rc = sysctl_write(key, value);
    if (rc == CXMOD_OK)     cxmod_ok("%s = %s", key, value);
    else if (rc == CXMOD_ENOFILE) cxmod_warn("%s: parameter not available", key);
    else if (rc == CXMOD_EPERM)   cxmod_warn("%s: permission denied", key);
    else                          cxmod_warn("%s: write failed", key);
    return rc;
}

/* ── Print current values ─────────────────────────────────────────────────── */

int tune_print_current(void)
{
    cxmod_section("CURRENT KERNEL VALUES");

    static const char *keys[] = {
        "net.core.rmem_max",
        "net.core.wmem_max",
        "net.core.somaxconn",
        "net.core.netdev_max_backlog",
        "net.ipv4.tcp_rmem",
        "net.ipv4.tcp_wmem",
        "net.ipv4.tcp_congestion_control",
        "net.ipv4.tcp_window_scaling",
        "net.ipv4.tcp_sack",
        "net.ipv4.tcp_timestamps",
        "net.ipv4.tcp_ecn",
        "net.ipv4.tcp_fastopen",
        "net.ipv4.tcp_tw_reuse",
        "net.ipv4.tcp_fin_timeout",
        "net.ipv4.tcp_keepalive_time",
        "net.ipv4.tcp_max_syn_backlog",
        "net.ipv4.tcp_max_tw_buckets",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.ip_local_port_range",
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.rp_filter",
        NULL
    };

    for (int i = 0; keys[i]; i++) {
        char val[256];
        int rc = sysctl_read_str(keys[i], val, sizeof(val));
        if (rc == CXMOD_OK)
            printf("  %-48s = %s\n", keys[i], val);
        else if (rc == CXMOD_ENOFILE)
            printf("  %-48s   N/A\n", keys[i]);
    }
    return CXMOD_OK;
}

/* ── BDP buffer calculator ────────────────────────────────────────────────── */

int tune_bdp_calc(uint64_t bandwidth_mbps, double rtt_ms)
{
    cxmod_section("BDP BUFFER CALCULATOR");

    uint64_t bw_bps  = bandwidth_mbps * 1000000ULL;
    double   rtt_sec = rtt_ms / 1000.0;
    uint64_t bdp     = (uint64_t)(bw_bps * rtt_sec / 8.0);  /* bytes */
    uint64_t rec_buf = bdp * 2;  /* 2× BDP headroom */
    if (rec_buf < 4 * 1024 * 1024) rec_buf = 4 * 1024 * 1024; /* min 4 MiB */

    uint64_t cur_rmem = 0, cur_wmem = 0;
    sysctl_read_u64("net.core.rmem_max", &cur_rmem);
    sysctl_read_u64("net.core.wmem_max", &cur_wmem);

    printf("  Input:\n");
    printf("    Bandwidth:    %llu Mbit/s\n",  (unsigned long long)bandwidth_mbps);
    printf("    RTT:          %.1f ms\n",       rtt_ms);
    printf("\n");
    printf("  Result:\n");
    printf("    BDP:          %llu bytes  (%.1f MiB)\n",
           (unsigned long long)bdp, bdp / (1024.0*1024.0));
    printf("    Recommended buffer (2×BDP): %llu bytes  (%.1f MiB)\n",
           (unsigned long long)rec_buf, rec_buf / (1024.0*1024.0));
    printf("    Current rmem_max:            %llu bytes  (%.1f MiB)\n",
           (unsigned long long)cur_rmem, cur_rmem / (1024.0*1024.0));
    printf("    Current wmem_max:            %llu bytes  (%.1f MiB)\n",
           (unsigned long long)cur_wmem, cur_wmem / (1024.0*1024.0));
    printf("\n");

    bool needs_increase = (cur_rmem < rec_buf || cur_wmem < rec_buf);

    if (needs_increase) {
        if (cxmod_color) printf(COL_YELLOW);
        printf("  Buffers are TOO SMALL for this link.\n");
        printf("  Theoretical max throughput with current buffers: %.1f Mbit/s\n",
               (double)cur_rmem * 8.0 / (rtt_ms / 1000.0) / 1000000.0);
        printf("  Throughput lost: %.0f%%\n",
               100.0 * (1.0 - (double)cur_rmem / (double)rec_buf));
        if (cxmod_color) printf(COL_RESET);
        printf("\n  Run these commands:\n");
        printf("    sysctl -w net.core.rmem_max=%llu\n", (unsigned long long)rec_buf);
        printf("    sysctl -w net.core.wmem_max=%llu\n", (unsigned long long)rec_buf);
        printf("    sysctl -w net.ipv4.tcp_rmem='4096 %llu %llu'\n",
               (unsigned long long)(rec_buf/8), (unsigned long long)rec_buf);
        printf("    sysctl -w net.ipv4.tcp_wmem='4096 %llu %llu'\n",
               (unsigned long long)(rec_buf/8), (unsigned long long)rec_buf);
        printf("\n  Or: sudo cx tune --profile=high_throughput\n");
    } else {
        if (cxmod_color) printf(COL_GREEN);
        printf("  Buffers are sufficient for this link.\n");
        if (cxmod_color) printf(COL_RESET);
    }

    return CXMOD_OK;
}

/* ── Auto-BDP: detect from live interface speeds ──────────────────────────── */

int tune_auto_bdp(bool dry_run)
{
    cxmod_section("AUTO BDP DETECTION");
    printf("  Detecting interface speeds from /sys/class/net/*/speed ...\n\n");

    cxmod_iface_t ifaces[CXMOD_MAX_IFS];
    int n = iface_list(ifaces, CXMOD_MAX_IFS);

    uint32_t fastest = 0;
    const char *fastest_name = "eth0";

    for (int i = 0; i < n; i++) {
        if (!ifaces[i].up) continue;
        if (strcmp(ifaces[i].name, "lo") == 0) continue;
        if (ifaces[i].speed_mbps > fastest) {
            fastest = ifaces[i].speed_mbps;
            fastest_name = ifaces[i].name;
        }
        if (ifaces[i].speed_mbps > 0)
            printf("  %-14s  %u Mbit/s\n", ifaces[i].name, ifaces[i].speed_mbps);
        else
            printf("  %-14s  (speed not reported by driver)\n", ifaces[i].name);
    }

    if (fastest == 0) {
        cxmod_warn("Could not detect interface speed. Use: cxmod tune --bdp <Mbit> <ms>");
        return CXMOD_ERR;
    }

    printf("\n  Fastest interface: %s (%u Mbit/s)\n", fastest_name, fastest);

    /* Use 20ms RTT as conservative default (typical DC LAN is 1-5ms) */
    double rtt_ms = 20.0;
    printf("  Assumed RTT: %.0f ms  (override with: cxmod tune --bdp %u <your_rtt_ms>)\n\n",
           rtt_ms, fastest);

    (void)dry_run;
    return tune_bdp_calc((uint64_t)fastest, rtt_ms);
}
