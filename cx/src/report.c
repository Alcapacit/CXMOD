/*
 * report.c — Generate full text/JSON diagnostic reports
 *
 * `cxmod report` produces a comprehensive, timestamped diagnostic
 * report to stdout or a file, suitable for:
 *   - Attaching to bug reports / ops tickets
 *   - Automated monitoring scripts (JSON mode)
 *   - Baseline documentation before major changes
 *   - Before/after comparison of tuning runs
 */

#include "cxmod.h"
#include <time.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

static void print_separator(FILE *f)
{
    fprintf(f, "%s\n",
        "================================================================================");
}

static void section_header(FILE *f, const char *title)
{
    fprintf(f, "\n");
    print_separator(f);
    fprintf(f, "  %s\n", title);
    print_separator(f);
    fprintf(f, "\n");
}

static void write_system_info(FILE *f)
{
    section_header(f, "SYSTEM INFORMATION");

    struct utsname uts;
    if (uname(&uts) == 0) {
        fprintf(f, "  Hostname:       %s\n",  uts.nodename);
        fprintf(f, "  Kernel:         %s %s\n", uts.sysname, uts.release);
        fprintf(f, "  Architecture:   %s\n",  uts.machine);
    }

    /* CPU count */
    int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int ncpus_conf = (int)sysconf(_SC_NPROCESSORS_CONF);
    fprintf(f, "  CPUs online:    %d / %d configured\n", ncpus, ncpus_conf);

    /* Memory */
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        uint64_t total_mb = (uint64_t)si.totalram * si.mem_unit / (1024*1024);
        uint64_t free_mb  = (uint64_t)si.freeram  * si.mem_unit / (1024*1024);
        uint64_t avail_mb = (uint64_t)(si.freeram + si.bufferram) * si.mem_unit / (1024*1024);
        fprintf(f, "  RAM:            %llu MiB total, %llu MiB free, %llu MiB available\n",
                (unsigned long long)total_mb, (unsigned long long)free_mb,
                (unsigned long long)avail_mb);
        fprintf(f, "  Uptime:         %lu days %lu hours\n",
                si.uptime / 86400, (si.uptime % 86400) / 3600);
        fprintf(f, "  Load average:   %.2f  %.2f  %.2f\n",
                si.loads[0] / 65536.0, si.loads[1] / 65536.0, si.loads[2] / 65536.0);
    }

    /* kernel version for tuning context */
    char osrelease[128] = "unknown";
    proc_read_line("/proc/sys/kernel/osrelease", osrelease, sizeof(osrelease));
    fprintf(f, "  OS Release:     %s\n", osrelease);

    /* hostname */
    char hostname[128] = "";
    gethostname(hostname, sizeof(hostname));
    fprintf(f, "\n");
}

static void write_interfaces(FILE *f)
{
    section_header(f, "NETWORK INTERFACES");
    cxmod_iface_t ifaces[CXMOD_MAX_IFS];
    int n = iface_list(ifaces, CXMOD_MAX_IFS);

    fprintf(f, "  %-14s %-7s %-16s %-19s %-10s %-6s %-14s %-14s\n",
            "Interface", "State", "IPv4", "MAC", "Speed", "MTU", "RX", "TX");

    for (int i = 0; i < n; i++) {
        const cxmod_iface_t *iface = &ifaces[i];
        char rx_s[24], tx_s[24];

        /* Format bytes */
        #define FMT_B(b, buf, blen) do { \
            if ((b) >= (uint64_t)1<<30) snprintf(buf, blen, "%.1f GiB", (b)/(double)(1<<30)); \
            else if ((b) >= (uint64_t)1<<20) snprintf(buf, blen, "%.1f MiB", (b)/(double)(1<<20)); \
            else snprintf(buf, blen, "%llu KiB", (unsigned long long)((b)>>10)); \
        } while(0)

        FMT_B(iface->rx_bytes, rx_s, sizeof(rx_s));
        FMT_B(iface->tx_bytes, tx_s, sizeof(tx_s));

        char speed_s[16];
        if (iface->speed_mbps > 0)
            snprintf(speed_s, sizeof(speed_s), "%u Mb/s", iface->speed_mbps);
        else
            snprintf(speed_s, sizeof(speed_s), "N/A");

        fprintf(f, "  %-14s %-7s %-16s %-19s %-10s %-6u %-14s %-14s",
                iface->name, iface->up ? "UP" : "DOWN",
                iface->ip4, iface->mac, speed_s, iface->mtu, rx_s, tx_s);

        if (iface->rx_drop + iface->tx_drop > 0)
            fprintf(f, " [DROPS: rx=%llu tx=%llu]",
                    (unsigned long long)iface->rx_drop,
                    (unsigned long long)iface->tx_drop);
        if (iface->rx_errs + iface->tx_errs > 0)
            fprintf(f, " [ERRS: rx=%llu tx=%llu]",
                    (unsigned long long)iface->rx_errs,
                    (unsigned long long)iface->tx_errs);
        fprintf(f, "\n");
    }
}

static void write_sysctl_snapshot(FILE *f)
{
    section_header(f, "KERNEL PARAMETERS (sysctl snapshot)");

    static const char *keys[] = {
        "net.core.rmem_max",
        "net.core.wmem_max",
        "net.core.rmem_default",
        "net.core.wmem_default",
        "net.core.somaxconn",
        "net.core.netdev_max_backlog",
        "net.ipv4.tcp_rmem",
        "net.ipv4.tcp_wmem",
        "net.ipv4.tcp_mem",
        "net.ipv4.tcp_congestion_control",
        "net.ipv4.tcp_window_scaling",
        "net.ipv4.tcp_timestamps",
        "net.ipv4.tcp_sack",
        "net.ipv4.tcp_ecn",
        "net.ipv4.tcp_fastopen",
        "net.ipv4.tcp_slow_start_after_idle",
        "net.ipv4.tcp_tw_reuse",
        "net.ipv4.tcp_fin_timeout",
        "net.ipv4.tcp_keepalive_time",
        "net.ipv4.tcp_keepalive_intvl",
        "net.ipv4.tcp_keepalive_probes",
        "net.ipv4.tcp_max_syn_backlog",
        "net.ipv4.tcp_max_tw_buckets",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.tcp_syn_retries",
        "net.ipv4.tcp_synack_retries",
        "net.ipv4.tcp_max_orphans",
        "net.ipv4.ip_local_port_range",
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.tcp_mtu_probing",
        "net.netfilter.nf_conntrack_max",
        "net.netfilter.nf_conntrack_count",
        "net.netfilter.nf_conntrack_tcp_timeout_established",
        "net.core.rps_sock_flow_entries",
        NULL
    };

    for (int i = 0; keys[i]; i++) {
        char val[256];
        int rc = sysctl_read_str(keys[i], val, sizeof(val));
        if (rc == CXMOD_OK)
            fprintf(f, "  %-52s = %s\n", keys[i], val);
        else
            fprintf(f, "  %-52s   N/A\n", keys[i]);
    }
}

static void write_proto_stats(FILE *f)
{
    section_header(f, "PROTOCOL STATISTICS");
    cxmod_tcpstat_t st;
    proto_read_snmp(&st);

    double retrans_pct = 0;
    proto_retrans_rate(&st, &retrans_pct);

    fprintf(f, "  TCP segments in/out:      %llu / %llu\n",
            (unsigned long long)st.tcp_in_segs, (unsigned long long)st.tcp_out_segs);
    fprintf(f, "  TCP retransmits:          %llu (%.3f%%)\n",
            (unsigned long long)st.tcp_retrans, retrans_pct);
    fprintf(f, "  TCP errors:               %llu\n", (unsigned long long)st.tcp_in_errs);
    fprintf(f, "  TCP resets:               %llu\n", (unsigned long long)st.tcp_estab_resets);
    fprintf(f, "  TCP SYN cookies sent:     %llu\n", (unsigned long long)st.tcp_syn_cookies_sent);
    fprintf(f, "  TCP active opens:         %llu\n", (unsigned long long)st.tcp_active_opens);
    fprintf(f, "  UDP datagrams in/out:     %llu / %llu\n",
            (unsigned long long)st.udp_in_dgrams, (unsigned long long)st.udp_out_dgrams);
    fprintf(f, "  UDP errors:               %llu\n", (unsigned long long)st.udp_in_errs);
    fprintf(f, "  UDP no-port drops:        %llu\n", (unsigned long long)st.udp_no_ports);
}

static void write_conntrack(FILE *f)
{
    section_header(f, "CONNECTION TRACKING");
    cxmod_conntrack_t ct;
    if (conntrack_read(&ct) != CXMOD_OK || ct.max == 0) {
        fprintf(f, "  nf_conntrack not loaded\n");
        return;
    }
    fprintf(f, "  Count: %u  Max: %u  Used: %u%%\n",
            ct.count, ct.max, ct.used_pct);

    cxmod_connstates_t cs;
    connstates_read(&cs);
    fprintf(f, "  TCP states:\n");
    fprintf(f, "    ESTABLISHED: %-8u  LISTEN: %-8u  TIME_WAIT: %-8u\n",
            cs.established, cs.listen, cs.time_wait);
    fprintf(f, "    SYN_RECV:    %-8u  CLOSE_WAIT: %-8u  LAST_ACK: %-8u\n",
            cs.syn_recv, cs.close_wait, cs.last_ack);
    fprintf(f, "    TOTAL: %u\n", cs.total);
}

static void write_findings(FILE *f, const cxmod_report_t *r)
{
    section_header(f, "DIAGNOSTIC FINDINGS");

    for (int i = 0; i < r->count; i++) {
        const cxmod_finding_t *finding = &r->findings[i];
        fprintf(f, "  [%-4s] %-16s %s\n",
                sev_str(finding->severity), finding->subsystem, finding->message);
        if (finding->fix[0])
            fprintf(f, "         FIX: %s\n", finding->fix);
    }

    fprintf(f, "\n  Total: %d findings  |  Critical: %d  |  Warnings: %d\n",
            r->count, r->critical, r->warnings);
}

static void write_json_report(FILE *f, const cxmod_report_t *r)
{
    struct utsname uts; uname(&uts);
    time_t now = time(NULL);
    char ts[64];
    struct tm *tm = gmtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);

    fprintf(f, "{\n");
    fprintf(f, "  \"cxmod_version\": \"" CXMOD_VERSION "\",\n");
    fprintf(f, "  \"timestamp\": \"%s\",\n", ts);
    fprintf(f, "  \"hostname\": \"%s\",\n", uts.nodename);
    fprintf(f, "  \"kernel\": \"%s %s\",\n", uts.sysname, uts.release);
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_findings\": %d,\n", r->count);
    fprintf(f, "    \"critical\": %d,\n", r->critical);
    fprintf(f, "    \"warnings\": %d\n", r->warnings);
    fprintf(f, "  },\n");
    fprintf(f, "  \"findings\": [\n");

    for (int i = 0; i < r->count; i++) {
        const cxmod_finding_t *finding = &r->findings[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"severity\": \"%s\",\n", sev_str(finding->severity));
        fprintf(f, "      \"subsystem\": \"%s\",\n", finding->subsystem);
        fprintf(f, "      \"message\": \"%s\",\n", finding->message);
        fprintf(f, "      \"fix\": \"%s\"\n", finding->fix);
        fprintf(f, "    }%s\n", (i < r->count - 1) ? "," : "");
    }
    fprintf(f, "  ],\n");

    /* sysctl snapshot */
    fprintf(f, "  \"sysctl\": {\n");
    static const char *jkeys[] = {
        "net.core.rmem_max", "net.core.wmem_max",
        "net.ipv4.tcp_congestion_control", "net.ipv4.tcp_tw_reuse",
        "net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_max_syn_backlog",
        "net.ipv4.tcp_syncookies", "net.ipv4.ip_local_port_range",
        "net.netfilter.nf_conntrack_max", "net.netfilter.nf_conntrack_count",
        NULL
    };
    for (int i = 0; jkeys[i]; i++) {
        char val[256]; val[0] = '\0';
        sysctl_read_str(jkeys[i], val, sizeof(val));
        /* Escape quotes in val */
        fprintf(f, "    \"%s\": \"%s\"%s\n",
                jkeys[i], val, jkeys[i+1] ? "," : "");
    }
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
}

int report_generate(const char *output_path, bool json_mode)
{
    FILE *f = stdout;
    bool opened = false;

    if (output_path) {
        f = fopen(output_path, "w");
        if (!f) {
            cxmod_warn("Cannot open %s: %s", output_path, strerror(errno));
            return CXMOD_ERR;
        }
        opened = true;
    }

    /* Run full diagnostics */
    cxmod_report_t report;
    diagnose_all(&report);
    /* Add sockstat findings */
    sockstat_diagnose(&report);

    if (json_mode) {
        write_json_report(f, &report);
        if (opened) { fclose(f); cxmod_ok("JSON report written to %s", output_path); }
        return report.critical > 0 ? 1 : 0;
    }

    /* Text report */
    time_t now = time(NULL);
    char ts[64];
    struct tm *tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S %Z", tm);

    print_separator(f);
    fprintf(f, "  CXMOD v" CXMOD_VERSION " — Diagnostic Report\n");
    fprintf(f, "  Generated: %s\n", ts);
    print_separator(f);

    write_system_info(f);
    write_interfaces(f);
    write_sysctl_snapshot(f);
    write_proto_stats(f);
    write_conntrack(f);
    write_findings(f, &report);

    print_separator(f);
    fprintf(f, "  End of CXMOD report\n");
    print_separator(f);
    fprintf(f, "\n");

    if (opened) {
        fclose(f);
        cxmod_ok("Report written to %s", output_path);
    }

    return report.critical > 0 ? 1 : 0;
}

