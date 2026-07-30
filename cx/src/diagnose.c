/*
 * diagnose.c — Full network health diagnostic report
 *
 * Checks all major Linux networking bottlenecks and reports
 * findings with severity levels and actionable fix commands.
 */

#include "cxmod.h"
#include <string.h>

/* ── Buffer diagnostics ───────────────────────────────────────────────────── */

int diagnose_buffers(cxmod_report_t *r)
{
    uint64_t rmem = 0, wmem = 0, somaxconn = 0, backlog = 0;
    sysctl_read_u64("net.core.rmem_max",           &rmem);
    sysctl_read_u64("net.core.wmem_max",           &wmem);
    sysctl_read_u64("net.core.somaxconn",          &somaxconn);
    sysctl_read_u64("net.core.netdev_max_backlog", &backlog);

    /* 4 MiB is minimum for 1 Gbit/s * 20ms RTT */
    if (rmem < 4 * 1024 * 1024) {
        char msg[256], fix[256];
        snprintf(msg, sizeof(msg),
                 "rmem_max=%llu bytes (%.0f KiB) — starves 1G links at >17ms RTT",
                 (unsigned long long)rmem, rmem/1024.0);
        snprintf(fix, sizeof(fix),
                 "sudo cx tune --profile=balanced   (sets rmem_max=32MiB)");
        report_add(r, SEV_CRITICAL, "buffers", msg, fix);
    } else if (rmem < 32 * 1024 * 1024) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "rmem_max=%llu bytes (%.0f MiB) — sub-optimal for 10G/high-RTT links",
                 (unsigned long long)rmem, rmem/(1024.0*1024));
        report_add(r, SEV_WARN, "buffers", msg,
                   "sudo cx tune --profile=high_throughput");
    } else {
        report_add(r, SEV_OK, "buffers",
                   "Socket buffers are adequately sized", "");
    }

    if (somaxconn < 1024)
        report_add(r, SEV_WARN, "somaxconn",
                   "net.core.somaxconn is low — accept() backlog may overflow under spikes",
                   "sudo cx tune --profile=balanced");
    else
        report_add(r, SEV_OK, "somaxconn", "Accept backlog is sufficient", "");

    if (backlog < 10000)
        report_add(r, SEV_WARN, "netdev_backlog",
                   "netdev_max_backlog is low — kernel rx ring may drop bursts",
                   "sudo sysctl -w net.core.netdev_max_backlog=50000");
    else
        report_add(r, SEV_OK, "netdev_backlog", "Netdev backlog is sufficient", "");

    return CXMOD_OK;
}

/* ── conntrack ────────────────────────────────────────────────────────────── */

int diagnose_conntrack(cxmod_report_t *r)
{
    cxmod_conntrack_t ct;
    int rc = conntrack_read(&ct);
    if (rc == CXMOD_ENOFILE) {
        report_add(r, SEV_INFO, "conntrack",
                   "nf_conntrack not loaded — no connection tracking active", "");
        return CXMOD_OK;
    }

    if (ct.used_pct >= 80) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "conntrack table %u%% full (%u/%u) — packets will be DROPPED",
                 ct.used_pct, ct.count, ct.max);
        report_add(r, SEV_CRITICAL, "conntrack", msg,
                   "sudo cx conntrack --fix");
    } else if (ct.used_pct >= 60) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "conntrack table %u%% full (%u/%u) — increase before overflow",
                 ct.used_pct, ct.count, ct.max);
        report_add(r, SEV_WARN, "conntrack", msg,
                   "sudo cx conntrack --fix");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "conntrack %u%% (%u/%u) — healthy", ct.used_pct, ct.count, ct.max);
        report_add(r, SEV_OK, "conntrack", msg, "");
    }

    /* Check TCP established timeout (default 432000 = 5 days — insane) */
    uint64_t tcp_estab = 0;
    if (proc_read_u64("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
                      &tcp_estab) == CXMOD_OK && tcp_estab > 86400) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "tcp_timeout_established=%llus (default 432000=5 days) — "
                 "keeps dead connections, wastes table space",
                 (unsigned long long)tcp_estab);
        report_add(r, SEV_WARN, "ct_timeout", msg,
                   "sudo cx conntrack --fix  (sets to 1200s)");
    }

    return CXMOD_OK;
}

/* ── TIME_WAIT ────────────────────────────────────────────────────────────── */

int diagnose_timewait(cxmod_report_t *r)
{
    cxmod_connstates_t cs;
    connstates_read(&cs);

    uint64_t tw_reuse = 0, fin_timeout = 0;
    sysctl_read_u64("net.ipv4.tcp_tw_reuse",  &tw_reuse);
    sysctl_read_u64("net.ipv4.tcp_fin_timeout", &fin_timeout);

    char port_range[64] = "32768 60999";
    sysctl_read_str("net.ipv4.ip_local_port_range", port_range, sizeof(port_range));
    unsigned int lo = 32768, hi = 60999;
    sscanf(port_range, "%u %u", &lo, &hi);
    uint32_t available_ports = hi - lo;

    /* TIME_WAIT exhaustion: if TW sockets > 50% of available local ports */
    if (cs.time_wait > available_ports / 2) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "%u TIME_WAIT sockets vs %u available ports — "
                 "outbound connections will fail with EADDRINUSE",
                 cs.time_wait, available_ports);
        report_add(r, SEV_CRITICAL, "timewait", msg,
                   "sudo cx tune --profile=balanced  (tw_reuse=1, widen port range)");
    } else if (cs.time_wait > 10000) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "%u TIME_WAIT sockets — monitor; %u ports available",
                 cs.time_wait, available_ports);
        report_add(r, SEV_WARN, "timewait", msg,
                   "sudo cx tune --profile=balanced");
    } else {
        report_add(r, SEV_OK, "timewait", "TIME_WAIT count is healthy", "");
    }

    if (!tw_reuse)
        report_add(r, SEV_WARN, "tw_reuse",
                   "tcp_tw_reuse=0 — TIME_WAIT sockets cannot be reused for new connections",
                   "sudo sysctl -w net.ipv4.tcp_tw_reuse=1");
    else
        report_add(r, SEV_OK, "tw_reuse", "tcp_tw_reuse enabled", "");

    if (fin_timeout > 60)
        report_add(r, SEV_WARN, "fin_timeout",
                   "tcp_fin_timeout > 60s — slow socket cleanup on high-traffic servers",
                   "sudo sysctl -w net.ipv4.tcp_fin_timeout=15");
    else
        report_add(r, SEV_OK, "fin_timeout", "tcp_fin_timeout is reasonable", "");

    if (available_ports < 30000) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Only %u local ports available (%u-%u) — exhaustion risk",
                 available_ports, lo, hi);
        report_add(r, SEV_WARN, "port_range", msg,
                   "sudo sysctl -w net.ipv4.ip_local_port_range='1024 65535'");
    } else {
        report_add(r, SEV_OK, "port_range", "Local port range is adequate", "");
    }

    return CXMOD_OK;
}

/* ── IRQ balance ──────────────────────────────────────────────────────────── */

int diagnose_irq(cxmod_report_t *r)
{
    int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus <= 1) {
        report_add(r, SEV_INFO, "irq", "Single-CPU system — IRQ balance N/A", "");
        return CXMOD_OK;
    }

    /* Check for IRQs all pinned to CPU 0 */
    FILE *f = fopen("/proc/interrupts", "r");
    if (!f) return CXMOD_OK;

    char line[CXMOD_LINE_MAX];
    fgets(line, sizeof(line), f); /* header */

    uint64_t cpu0_total = 0, other_total = 0;
    int nic_irqs = 0;

    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "eth") && !strstr(line, "ens") &&
            !strstr(line, "enp") && !strstr(line, "em")  &&
            !strstr(line, "virtio") && !strstr(line, "TxRx") &&
            !strstr(line, "mlx") && !strstr(line, "ixgbe")) continue;

        char *p = line;
        while (*p && *p != ':') p++;
        if (*p) p++;

        uint64_t counts[64]; int nc = 0;
        while (*p && nc < 64) {
            char *end;
            counts[nc] = strtoull(p, &end, 10);
            if (end == p) break;
            nc++; p = end;
            while (*p == ' ') p++;
        }
        if (nc < 2) { nic_irqs++; continue; }

        cpu0_total += counts[0];
        for (int i = 1; i < nc && i < ncpus; i++) other_total += counts[i];
        nic_irqs++;
    }
    fclose(f);

    if (nic_irqs == 0) {
        report_add(r, SEV_INFO, "irq", "No NIC IRQs detected", "");
        return CXMOD_OK;
    }

    if (other_total == 0 && cpu0_total > 0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "ALL %d NIC IRQs land on CPU 0 — single-CPU bottleneck "
                 "on %d-CPU system", nic_irqs, ncpus);
        report_add(r, SEV_CRITICAL, "irq", msg,
                   "sudo cx irq --balance  then  sudo cx irq --rps");
    } else {
        uint64_t total = cpu0_total + other_total;
        int cpu0_pct = total > 0 ? (int)(cpu0_total * 100 / total) : 0;
        if (cpu0_pct > 80) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "CPU 0 handles %d%% of NIC IRQs — imbalanced on %d-CPU system",
                     cpu0_pct, ncpus);
            report_add(r, SEV_WARN, "irq", msg,
                       "sudo cx irq --balance");
        } else {
            report_add(r, SEV_OK, "irq", "NIC IRQs are spread across CPUs", "");
        }
    }

    /* Check RPS */
    uint64_t rps = 0;
    proc_read_u64("/proc/sys/net/core/rps_sock_flow_entries", &rps);
    if (rps == 0)
        report_add(r, SEV_WARN, "rps",
                   "RPS not configured — receive processing on single CPU",
                   "sudo cx irq --rps");
    else
        report_add(r, SEV_OK, "rps", "RPS configured", "");

    return CXMOD_OK;
}

/* ── SYN backlog ──────────────────────────────────────────────────────────── */

int diagnose_synbacklog(cxmod_report_t *r)
{
    uint64_t backlog = 0, syncookies = 0;
    sysctl_read_u64("net.ipv4.tcp_max_syn_backlog", &backlog);
    sysctl_read_u64("net.ipv4.tcp_syncookies",      &syncookies);

    if (!syncookies) {
        report_add(r, SEV_CRITICAL, "syncookies",
                   "tcp_syncookies=0 — SYN flood will exhaust backlog and drop connections",
                   "sudo sysctl -w net.ipv4.tcp_syncookies=1");
    } else {
        report_add(r, SEV_OK, "syncookies", "SYN cookies enabled (SYN flood protection)", "");
    }

    if (backlog < 1024) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "tcp_max_syn_backlog=%llu — traffic spikes will drop new connections",
                 (unsigned long long)backlog);
        report_add(r, SEV_WARN, "syn_backlog", msg,
                   "sudo sysctl -w net.ipv4.tcp_max_syn_backlog=16384");
    } else {
        report_add(r, SEV_OK, "syn_backlog", "SYN backlog is adequate", "");
    }

    return CXMOD_OK;
}

/* ── Retransmit rate ──────────────────────────────────────────────────────── */

int diagnose_retransmit(cxmod_report_t *r)
{
    cxmod_tcpstat_t st;
    proto_read_snmp(&st);

    double pct = 0;
    proto_retrans_rate(&st, &pct);

    if (pct >= 3.0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "TCP retransmit rate=%.2f%% — severe congestion or packet loss", pct);
        report_add(r, SEV_CRITICAL, "retransmit", msg,
                   "Check link quality; consider BBR: sudo cx tune --profile=high_throughput");
    } else if (pct >= 1.0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "TCP retransmit rate=%.2f%% — elevated; investigate congestion", pct);
        report_add(r, SEV_WARN, "retransmit", msg,
                   "sudo cx tune --profile=balanced  (enables ECN, BBR-capable)");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "TCP retransmit rate=%.3f%% — healthy", pct);
        report_add(r, SEV_OK, "retransmit", msg, "");
    }

    if (st.udp_in_errs > 1000) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "UDP receive errors=%llu — buffer overflow or CPU overrun",
                 (unsigned long long)st.udp_in_errs);
        report_add(r, SEV_WARN, "udp_errs", msg,
                   "Increase net.core.rmem_max; check application receive loop speed");
    }

    return CXMOD_OK;
}

/* ── Interface drops ──────────────────────────────────────────────────────── */

int diagnose_drops(cxmod_report_t *r, const cxmod_iface_t *ifaces, int n)
{
    for (int i = 0; i < n; i++) {
        const cxmod_iface_t *iface = &ifaces[i];
        if (strcmp(iface->name, "lo") == 0) continue;
        if (!iface->up) continue;

        uint64_t total_drop = iface->rx_drop + iface->tx_drop;
        uint64_t total_err  = iface->rx_errs + iface->tx_errs;
        uint64_t total_pkts = iface->rx_pkts + iface->tx_pkts;

        if (total_drop > 0 && total_pkts > 0) {
            double drop_pct = (double)total_drop / (double)total_pkts * 100.0;
            if (drop_pct >= 0.1) {
                char msg[256], fix[256];
                snprintf(msg, sizeof(msg),
                         "%s: %llu drops (%.2f%% of packets)",
                         iface->name, (unsigned long long)total_drop, drop_pct);
                snprintf(fix, sizeof(fix),
                         "Increase netdev_max_backlog and rmem_max; check NIC ring buffer size");
                report_add(r, drop_pct >= 1.0 ? SEV_CRITICAL : SEV_WARN,
                           "if_drops", msg, fix);
            }
        }

        if (total_err > 0) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "%s: %llu hardware errors — possible cable/NIC fault",
                     iface->name, (unsigned long long)total_err);
            report_add(r, SEV_WARN, "if_errors", msg,
                       "Check cable, SFP, NIC firmware; run ethtool -S for counters");
        }
    }
    return CXMOD_OK;
}

/* ── MTU consistency ──────────────────────────────────────────────────────── */

int diagnose_mtu(cxmod_report_t *r, const cxmod_iface_t *ifaces, int n)
{
    /* Detect mixed MTU across physical interfaces (sign of misconfiguration) */
    uint32_t first_mtu = 0;
    const char *first_name = NULL;

    for (int i = 0; i < n; i++) {
        const cxmod_iface_t *iface = &ifaces[i];
        if (!iface->up) continue;
        if (strcmp(iface->name, "lo") == 0) continue;
        if (iface->mtu == 0) continue;

        /* Jumbo frames flag */
        if (iface->mtu >= 9000) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "%s: jumbo frames enabled (MTU %u) — ensure all path devices match",
                     iface->name, iface->mtu);
            report_add(r, SEV_INFO, "mtu", msg,
                       "Verify all switches/routers on the path support the same MTU");
        }

        if (first_mtu == 0) {
            first_mtu  = iface->mtu;
            first_name = iface->name;
            continue;
        }

        if (iface->mtu != first_mtu && iface->mtu != 65536) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "MTU mismatch: %s=%u vs %s=%u — causes fragmentation",
                     first_name, first_mtu, iface->name, iface->mtu);
            report_add(r, SEV_WARN, "mtu", msg,
                       "Set matching MTU: ip link set <iface> mtu 1500");
        }
    }

    if (first_mtu > 0 && first_mtu != 9000)
        report_add(r, SEV_OK, "mtu", "MTU consistent across interfaces", "");

    return CXMOD_OK;
}

/* ── Memory pressure ──────────────────────────────────────────────────────── */

int diagnose_memory(cxmod_report_t *r)
{
    /* Check tcp_mem — kernel starts throttling at tcp_mem[1] (pressure threshold) */
    char tcp_mem_str[128] = "";
    sysctl_read_str("net.ipv4.tcp_mem", tcp_mem_str, sizeof(tcp_mem_str));
    uint32_t lo = 0, pressure = 0, hi = 0;
    if (sscanf(tcp_mem_str, "%u %u %u", &lo, &pressure, &hi) == 3 && hi > 0) {
        /* Read current from /proc/net/sockstat */
        char sockstat_line[CXMOD_LINE_MAX];
        uint32_t tcp_mem_pages = 0;
        FILE *f = fopen("/proc/net/sockstat", "r");
        if (f) {
            while (fgets(sockstat_line, sizeof(sockstat_line), f)) {
                if (strncmp(sockstat_line, "TCP:", 4) == 0) {
                    uint32_t in, orp, tw, alloc, mem;
                    if (sscanf(sockstat_line + 4,
                                " inuse %u orphan %u tw %u alloc %u mem %u",
                                &in, &orp, &tw, &alloc, &mem) == 5)
                        tcp_mem_pages = mem;
                }
            }
            fclose(f);
        }
        if (tcp_mem_pages > 0) {
            int pct = (int)((uint64_t)tcp_mem_pages * 100 / hi);
            if (pct >= 80) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "TCP memory at %d%% of limit (%u/%u pages) — in pressure mode",
                         pct, tcp_mem_pages, hi);
                report_add(r, SEV_CRITICAL, "tcp_mem", msg,
                           "sudo cx tune --profile=balanced (increases tcp_mem ceiling)");
            } else if (pct >= 50) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "TCP memory at %d%% of limit — elevated, approaching pressure threshold",
                         pct);
                report_add(r, SEV_WARN, "tcp_mem", msg,
                           "Monitor with: cxmod sockstat");
            } else {
                report_add(r, SEV_OK, "tcp_mem", "TCP socket memory usage is healthy", "");
            }
        }
    }
    return CXMOD_OK;
}

/* ── File descriptor limits ───────────────────────────────────────────────── */

int diagnose_filedescs(cxmod_report_t *r)
{
    /* /proc/sys/fs/file-nr: allocated / unused / max */
    char line[CXMOD_LINE_MAX];
    if (proc_read_line("/proc/sys/fs/file-nr", line, sizeof(line)) != CXMOD_OK)
        return CXMOD_ENOFILE;

    uint64_t alloc = 0, unused = 0, max_fd = 0;
    if (sscanf(line, "%llu %llu %llu",
               (unsigned long long *)&alloc,
               (unsigned long long *)&unused,
               (unsigned long long *)&max_fd) != 3)
        return CXMOD_ERR;

    uint64_t used = (alloc > unused) ? alloc - unused : 0;
    int pct = (max_fd > 0) ? (int)(used * 100 / max_fd) : 0;

    if (pct >= 90) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "File descriptors: %llu / %llu used (%d%%) — critical, processes will fail to open files",
                 (unsigned long long)used, (unsigned long long)max_fd, pct);
        report_add(r, SEV_CRITICAL, "file_nr", msg,
                   "sudo sysctl -w fs.file-max=2097152  (then add to /etc/sysctl.d/)");
    } else if (pct >= 75) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "File descriptors: %llu / %llu used (%d%%) — approaching limit",
                 (unsigned long long)used, (unsigned long long)max_fd, pct);
        report_add(r, SEV_WARN, "file_nr", msg,
                   "sudo sysctl -w fs.file-max=1048576");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "File descriptors: %llu / %llu used (%d%%) — healthy",
                 (unsigned long long)used, (unsigned long long)max_fd, pct);
        report_add(r, SEV_OK, "file_nr", msg, "");
    }

    return CXMOD_OK;
}

/* ── CPU softirq saturation ───────────────────────────────────────────────── */

int diagnose_softirq(cxmod_report_t *r)
{
    /*
     * Read /proc/softirqs and check whether NET_RX and NET_TX interrupts
     * are concentrated on a single CPU while others have near-zero counts.
     * This catches the case where IRQ balancing was done but RPS was not
     * enabled, leaving softirq processing still on CPU 0.
     */
    FILE *f = fopen("/proc/softirqs", "r");
    if (!f) return CXMOD_OK; /* not critical if missing */

    int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus <= 1) { fclose(f); return CXMOD_OK; }

    char line[CXMOD_LINE_MAX];
    fgets(line, sizeof(line), f); /* header */

    uint64_t net_rx_cpu0 = 0, net_rx_rest = 0;
    uint64_t net_tx_cpu0 = 0, net_tx_rest = 0;
    bool found_rx = false, found_tx = false;

    while (fgets(line, sizeof(line), f)) {
        bool is_rx = (strncmp(line, "  NET_RX:", 9) == 0 ||
                      strncmp(line, "NET_RX:",   7) == 0);
        bool is_tx = (strncmp(line, "  NET_TX:", 9) == 0 ||
                      strncmp(line, "NET_TX:",   7) == 0);
        if (!is_rx && !is_tx) continue;

        char *p = strchr(line, ':');
        if (!p) continue;
        p++;

        uint64_t counts[256]; int nc = 0;
        while (*p && nc < 256) {
            char *end;
            counts[nc] = strtoull(p, &end, 10);
            if (end == p) break;
            nc++; p = end;
            while (*p == ' ') p++;
        }
        if (nc < 2) continue;

        uint64_t c0 = counts[0], rest = 0;
        for (int i = 1; i < nc && i < ncpus; i++) rest += counts[i];

        if (is_rx) { net_rx_cpu0 = c0; net_rx_rest = rest; found_rx = true; }
        if (is_tx) { net_tx_cpu0 = c0; net_tx_rest = rest; found_tx = true; }
    }
    fclose(f);

    if (!found_rx && !found_tx) return CXMOD_OK;

    /* Flag if CPU 0 handles >80% of NET_RX on a multi-CPU system */
    uint64_t total_rx = net_rx_cpu0 + net_rx_rest;
    if (found_rx && total_rx > 10000 && net_rx_rest == 0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "NET_RX softirq: ALL %llu interrupts on CPU 0 — "
                 "network receive is single-threaded",
                 (unsigned long long)net_rx_cpu0);
        report_add(r, SEV_CRITICAL, "softirq", msg,
                   "sudo cx irq --rps   (enables RPS to fan out across all CPUs)");
    } else if (found_rx && total_rx > 10000) {
        int cpu0_pct = (int)(net_rx_cpu0 * 100 / total_rx);
        if (cpu0_pct > 80) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "NET_RX softirq: CPU 0 handles %d%% of receive processing "
                     "on %d-CPU system", cpu0_pct, ncpus);
            report_add(r, SEV_WARN, "softirq", msg,
                       "sudo cx irq --rps");
        } else {
            report_add(r, SEV_OK, "softirq",
                       "NET_RX softirq spread across CPUs", "");
        }
    }

    (void)net_tx_cpu0; (void)net_tx_rest; (void)found_tx;
    return CXMOD_OK;
}

/* ── NIC ring buffer fill ─────────────────────────────────────────────────── */

int diagnose_ringbuf(cxmod_report_t *r)
{
    /*
     * Check NIC ring buffer sizes via ethtool -g.  A ring that is at its
     * minimum size (e.g. 256 RX slots on a busy 10G NIC) will drop packets
     * in hardware before the kernel even sees them — these drops appear as
     * missed_errors in /proc/net/dev but are easy to miss.
     */
    char ethtool[CXMOD_PATH_MAX];
    if (find_tool("ethtool", ethtool, sizeof(ethtool)) != CXMOD_OK)
        return CXMOD_OK; /* ethtool absent — skip silently */

    DIR *d = opendir("/sys/class/net");
    if (!d) return CXMOD_OK;

    int warnings = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        if (strcmp(ent->d_name, "lo") == 0) continue;
        if (!iface_name_safe(ent->d_name)) continue;

        char cmd[CXMOD_PATH_MAX];
        snprintf(cmd, sizeof(cmd), "%s -g %s 2>/dev/null", ethtool, ent->d_name);
        FILE *f = popen(cmd, "r");
        if (!f) continue;

        char line[CXMOD_LINE_MAX];
        uint32_t max_rx = 0, cur_rx = 0;
        bool in_max = false, in_cur = false;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Pre-set maximums:"))  { in_max = true;  in_cur = false; continue; }
            if (strstr(line, "Current hardware"))   { in_cur = true;  in_max = false; continue; }
            if (strstr(line, "RX:")) {
                uint32_t v = 0;
                if (sscanf(line + 3, " %u", &v) == 1) {
                    if (in_max) max_rx = v;
                    if (in_cur) cur_rx = v;
                }
            }
        }
        pclose(f);

        if (max_rx == 0 || cur_rx == 0) continue;

        /* Warn if current ring is less than 25% of maximum */
        int pct = (int)((uint64_t)cur_rx * 100 / max_rx);
        if (pct < 25) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "%s: NIC RX ring buffer at %u/%u slots (%d%% of max) — "
                     "hardware drops likely under burst traffic",
                     ent->d_name, cur_rx, max_rx, pct);
            report_add(r, SEV_WARN, "ringbuf", msg,
                       "sudo ethtool -G <iface> rx <max>  (maximize ring buffer)");
            warnings++;
        } else if (pct < 100) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "%s: NIC RX ring buffer %u/%u slots — "
                     "consider maximizing for high-traffic servers",
                     ent->d_name, cur_rx, max_rx);
            report_add(r, SEV_INFO, "ringbuf", msg,
                       "sudo ethtool -G <iface> rx <max>");
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "%s: NIC ring buffer at maximum (%u slots)", ent->d_name, cur_rx);
            report_add(r, SEV_OK, "ringbuf", msg, "");
        }
    }
    closedir(d);
    (void)warnings;
    return CXMOD_OK;
}

/* ── Full diagnostic ──────────────────────────────────────────────────────── */

int diagnose_all(cxmod_report_t *report)
{
    memset(report, 0, sizeof(*report));

    cxmod_iface_t ifaces[CXMOD_MAX_IFS];
    int n = iface_list(ifaces, CXMOD_MAX_IFS);

    diagnose_buffers(report);
    diagnose_conntrack(report);
    diagnose_timewait(report);
    diagnose_irq(report);
    diagnose_softirq(report);
    diagnose_synbacklog(report);
    diagnose_retransmit(report);
    diagnose_memory(report);
    diagnose_filedescs(report);
    diagnose_ringbuf(report);
    if (n > 0) {
        diagnose_drops(report, ifaces, n);
        diagnose_mtu(report, ifaces, n);
    }

    return CXMOD_OK;
}
