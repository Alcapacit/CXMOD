/*
 * persist.c — Persist tuning to /etc/sysctl.d/90-cxmod.conf
 *
 * Linux sysctl settings written to /proc/sys reset on reboot.
 * This module writes the applied profile to the sysctl.d drop-in
 * directory so settings survive across reboots.
 *
 * Files managed:
 *   /etc/sysctl.d/90-cxmod.conf  — primary (modern systems)
 *   /etc/sysctl.conf              — fallback (older distros)
 *
 * The 90-cxmod.conf is named with '90' so it loads AFTER distro defaults
 * (typically 10-*.conf) but before user customizations (99-*.conf).
 */

#include "cxmod.h"
#include <time.h>
#include <string.h>

#define SYSCTL_D_PATH  "/etc/sysctl.d/90-cxmod.conf"
#define SYSCTL_CONF    "/etc/sysctl.conf"

/* ── Parameter table (same layout as tune.c — kept in sync) ─────────────── */
/* Imported via extern (both compile units include cxmod.h) */

static const struct { const char *key; const char *vals[5]; } PERSIST_PARAMS[] = {
/* BALANCED  HIGH_TPUT  LOW_LAT  SATELLITE  HARDENED */
{"net.core.rmem_max",
 {"33554432","134217728","16777216","268435456","8388608"}},
{"net.core.wmem_max",
 {"33554432","134217728","16777216","268435456","8388608"}},
{"net.core.rmem_default",
 {"1048576","4194304","262144","16777216","262144"}},
{"net.core.wmem_default",
 {"1048576","4194304","262144","16777216","262144"}},
{"net.core.netdev_max_backlog",
 {"50000","300000","10000","300000","5000"}},
{"net.core.somaxconn",
 {"4096","65535","4096","65535","1024"}},
{"net.ipv4.tcp_rmem",
 {"4096 1048576 33554432","4096 4194304 134217728",
  "4096 262144 16777216","4096 16777216 268435456","4096 87380 8388608"}},
{"net.ipv4.tcp_wmem",
 {"4096 1048576 33554432","4096 4194304 134217728",
  "4096 262144 16777216","4096 16777216 268435456","4096 87380 8388608"}},
{"net.ipv4.tcp_congestion_control",
 {"cubic","bbr","cubic","bbr","cubic"}},
{"net.ipv4.tcp_window_scaling",  {"1","1","1","1","1"}},
{"net.ipv4.tcp_timestamps",      {"1","1","1","1","0"}},
{"net.ipv4.tcp_sack",            {"1","1","1","1","1"}},
{"net.ipv4.tcp_ecn",             {"1","1","1","0","0"}},
{"net.ipv4.tcp_fastopen",        {"3","3","3","0","0"}},
{"net.ipv4.tcp_slow_start_after_idle",{"0","0","0","0","1"}},
{"net.ipv4.tcp_tw_reuse",        {"1","1","1","1","0"}},
{"net.ipv4.tcp_fin_timeout",     {"30","15","10","60","30"}},
{"net.ipv4.tcp_keepalive_time",  {"300","300","60","600","1800"}},
{"net.ipv4.tcp_keepalive_intvl", {"30","30","10","60","15"}},
{"net.ipv4.tcp_keepalive_probes",{"5","5","3","5","5"}},
{"net.ipv4.tcp_max_syn_backlog", {"16384","65536","8192","65536","4096"}},
{"net.ipv4.tcp_max_tw_buckets",  {"1440000","2000000","720000","2000000","1440000"}},
{"net.ipv4.tcp_syncookies",      {"1","1","1","1","1"}},
{"net.ipv4.tcp_syn_retries",     {"6","6","3","6","3"}},
{"net.ipv4.tcp_synack_retries",  {"5","5","2","5","2"}},
{"net.ipv4.ip_local_port_range", {"10240 65535","1024 65535","10240 65535","1024 65535","32768 60999"}},
{"net.ipv4.conf.all.rp_filter",  {"1","1","1","1","1"}},
{"net.ipv4.conf.default.rp_filter",{"1","1","1","1","1"}},
{"net.ipv4.icmp_echo_ignore_broadcasts",{"1","1","1","1","1"}},
{"net.ipv4.icmp_ignore_bogus_error_responses",{"1","1","1","1","1"}},
{"net.ipv4.tcp_mtu_probing",     {"1","1","0","1","0"}},
/* IPv6 */
{"net.ipv6.conf.all.use_tempaddr",     {"2","2","2","2","2"}},
{"net.ipv6.conf.default.use_tempaddr", {"2","2","2","2","2"}},
{"net.ipv6.conf.all.accept_redirects", {"0","0","0","0","0"}},
{NULL, {NULL,NULL,NULL,NULL,NULL}}
};

static const char *PROFILE_NAMES[5] = {
    "balanced","high_throughput","low_latency","satellite","hardened"
};

int persist_write(cxmod_profile_t profile, const char *path)
{
    if (!path) path = SYSCTL_D_PATH;

    if (!is_root()) {
        cxmod_warn("Need root to write %s", path);
        return CXMOD_EPERM;
    }

    /* Create backup if file exists */
    char bak[CXMOD_PATH_MAX];
    snprintf(bak, sizeof(bak), "%s.bak", path);
    FILE *src = fopen(path, "r");
    if (src) {
        FILE *dst = fopen(bak, "w");
        if (dst) {
            char buf[CXMOD_LINE_MAX];
            while (fgets(buf, sizeof(buf), src)) fputs(buf, dst);
            fclose(dst);
        }
        fclose(src);
        cxmod_info("Existing config backed up to %s", bak);
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        cxmod_warn("Cannot write %s: %s", path, strerror(errno));
        return CXMOD_ERR;
    }

    time_t now = time(NULL);
    char ts[64];
    struct tm *tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    fprintf(f,
        "# CXMOD — Connection eXperience MODule\n"
        "# Profile: %s\n"
        "# Generated: %s\n"
        "# Managed by: cx v" CXMOD_VERSION "\n"
        "#\n"
        "# DO NOT EDIT MANUALLY — managed by cxmod persist\n"
        "# To change: sudo cx tune --profile=<name> && sudo cx persist\n"
        "# To remove: sudo rm %s && sudo sysctl --system\n"
        "#\n\n",
        PROFILE_NAMES[profile], ts, path);

    fprintf(f, "# === Core socket buffers ===\n");
    for (int i = 0; PERSIST_PARAMS[i].key; i++) {
        const char *val = PERSIST_PARAMS[i].vals[profile];
        if (!val || val[0] == '\0') continue;
        fprintf(f, "%s = %s\n", PERSIST_PARAMS[i].key, val);

        /* Add section headers */
        if (i == 5)  fprintf(f, "\n# === TCP stack ===\n");
        if (i == 13) fprintf(f, "\n# === TCP connection management ===\n");
        if (i == 20) fprintf(f, "\n# === TCP limits ===\n");
        if (i == 24) fprintf(f, "\n# === Network security ===\n");
    }

    fprintf(f, "\n# End of CXMOD configuration\n");
    fclose(f);

    cxmod_ok("Written to %s", path);
    printf("\n  Apply now (without reboot):\n");
    printf("    sudo sysctl --system\n");
    printf("    -- or --\n");
    printf("    sudo sysctl -p %s\n\n", path);

    return CXMOD_OK;
}

int persist_show(void)
{
    cxmod_section("PERSISTENT SYSCTL CONFIGURATION");

    /* Check if our file exists */
    FILE *f = fopen(SYSCTL_D_PATH, "r");
    if (!f) {
        cxmod_info("No CXMOD persistent config found at %s", SYSCTL_D_PATH);
        printf("  To create one: sudo cx persist --profile=balanced\n");
        return CXMOD_OK;
    }

    printf("  File: %s\n\n", SYSCTL_D_PATH);
    char line[CXMOD_LINE_MAX];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') {
            if (cxmod_color) printf(COL_GRAY);
            fputs(line, stdout);
            if (cxmod_color) printf(COL_RESET);
        } else {
            fputs(line, stdout);
        }
    }
    fclose(f);
    return CXMOD_OK;
}

int persist_remove(void)
{
    if (!is_root()) {
        cxmod_warn("Need root to remove %s", SYSCTL_D_PATH);
        return CXMOD_EPERM;
    }
    if (unlink(SYSCTL_D_PATH) == 0) {
        cxmod_ok("Removed %s", SYSCTL_D_PATH);
        printf("  Run `sudo sysctl --system` to reload remaining configuration\n");
    } else if (errno == ENOENT) {
        cxmod_info("No file to remove at %s", SYSCTL_D_PATH);
    } else {
        cxmod_warn("Failed to remove %s: %s", SYSCTL_D_PATH, strerror(errno));
        return CXMOD_ERR;
    }
    return CXMOD_OK;
}
