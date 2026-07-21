/*
 * cxmod.h — CXMOD: Connection eXperience MODule
 * Linux server network management system
 *
 * Solves the major bottlenecks in Linux kernel networking:
 *   - Undersized TCP buffers cutting throughput 50-80%
 *   - conntrack table overflow dropping packets silently
 *   - IRQ imbalance saturating CPU 0 while others idle
 *   - TIME_WAIT exhaustion starving new connections
 *   - Receive queue drops before userspace can read
 *   - SYN backlog overflow under traffic spikes
 *   - Orphan socket accumulation causing OOM
 *   - IP fragment queue buildup (MTU mismatch)
 *   - LRO causing issues on bridges/routers
 *   - No unified diagnostics / actionable output
 *   - Settings reset on reboot (no persistence)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CXMOD_H
#define CXMOD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <dirent.h>

/* ── Version ──────────────────────────────────────────────────────────────── */
#define CXMOD_VERSION   "2.1.0"
#define CXMOD_NAME      "cxmod"

/* ── Colour output ────────────────────────────────────────────────────────── */
#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_RED     "\033[31m"
#define COL_GREEN   "\033[32m"
#define COL_YELLOW  "\033[33m"
#define COL_BLUE    "\033[34m"
#define COL_CYAN    "\033[36m"
#define COL_GRAY    "\033[90m"

/* ── Return codes ─────────────────────────────────────────────────────────── */
#define CXMOD_OK        0
#define CXMOD_ERR       1
#define CXMOD_EPERM     2   /* need root */
#define CXMOD_ENODEV    3   /* no such device */
#define CXMOD_ENOFILE   4   /* /proc entry missing */

/* ── Max string sizes ─────────────────────────────────────────────────────── */
#define CXMOD_IFNAMSIZ  IFNAMSIZ
#define CXMOD_PATH_MAX  512
#define CXMOD_LINE_MAX  1024
#define CXMOD_MAX_IFS   64

/* ── Tuning profiles ──────────────────────────────────────────────────────── */
typedef enum {
    PROFILE_BALANCED = 0,
    PROFILE_HIGH_THROUGHPUT,
    PROFILE_LOW_LATENCY,
    PROFILE_SATELLITE,
    PROFILE_HARDENED,
    PROFILE_COUNT
} cxmod_profile_t;

/* ── Diagnostic severity ──────────────────────────────────────────────────── */
typedef enum {
    SEV_OK       = 0,
    SEV_INFO     = 1,
    SEV_WARN     = 2,
    SEV_CRITICAL = 3,
} cxmod_sev_t;

/* ── Network interface info ───────────────────────────────────────────────── */
typedef struct {
    char     name[CXMOD_IFNAMSIZ];
    char     ip4[INET_ADDRSTRLEN];
    char     ip6[INET6_ADDRSTRLEN];
    char     mac[18];
    uint32_t speed_mbps;
    uint32_t mtu;
    bool     up;
    uint64_t rx_bytes, tx_bytes;
    uint64_t rx_pkts,  tx_pkts;
    uint64_t rx_errs,  tx_errs;
    uint64_t rx_drop,  tx_drop;
    uint64_t rx_missed;
} cxmod_iface_t;

/* ── Conntrack snapshot ───────────────────────────────────────────────────── */
typedef struct {
    uint32_t count;
    uint32_t max;
    uint32_t used_pct;
    bool     overflow_risk;
} cxmod_conntrack_t;

/* ── TCP/IP statistics ────────────────────────────────────────────────────── */
typedef struct {
    uint64_t tcp_in_segs;
    uint64_t tcp_out_segs;
    uint64_t tcp_retrans;
    uint64_t tcp_in_errs;
    uint64_t tcp_estab_resets;
    uint64_t tcp_active_opens;
    uint64_t tcp_passive_opens;
    uint64_t tcp_syn_cookies_sent;
    uint64_t tcp_syn_cookies_recv;
    uint64_t tcp_tw_killed;
    uint64_t tcp_time_waited;
    uint64_t udp_in_dgrams;
    uint64_t udp_out_dgrams;
    uint64_t udp_in_errs;
    uint64_t udp_no_ports;
    uint64_t icmp_in_msgs;
    uint64_t icmp_out_msgs;
} cxmod_tcpstat_t;

/* ── Connection state counts ──────────────────────────────────────────────── */
typedef struct {
    uint32_t established;
    uint32_t syn_sent;
    uint32_t syn_recv;
    uint32_t fin_wait1;
    uint32_t fin_wait2;
    uint32_t time_wait;
    uint32_t close_wait;
    uint32_t last_ack;
    uint32_t listen;
    uint32_t closing;
    uint32_t total;
} cxmod_connstates_t;

/* ── IRQ info ─────────────────────────────────────────────────────────────── */
typedef struct {
    int      irq_num;
    char     iface[CXMOD_IFNAMSIZ];
    uint64_t counts[64];   /* per-CPU counts */
    int      ncpus;
    int      affinity_cpu; /* -1 = multi */
} cxmod_irqinfo_t;

/* ── Diagnostic finding ───────────────────────────────────────────────────── */
typedef struct {
    cxmod_sev_t  severity;
    char         subsystem[32];
    char         message[256];
    char         fix[256];
} cxmod_finding_t;

/* ── Diagnostic report ────────────────────────────────────────────────────── */
#define MAX_FINDINGS 96
typedef struct {
    cxmod_finding_t findings[MAX_FINDINGS];
    int             count;
    int             critical;
    int             warnings;
} cxmod_report_t;

/* ── Global flags ─────────────────────────────────────────────────────────── */
extern bool cxmod_verbose;
extern bool cxmod_json;
extern bool cxmod_dry_run;
extern bool cxmod_color;

/* ── util.c ───────────────────────────────────────────────────────────────── */
int   sysctl_read_str(const char *key, char *buf, size_t len);
int   sysctl_read_u64(const char *key, uint64_t *val);
int   sysctl_write(const char *key, const char *value);
int   sysctl_write_u64(const char *key, uint64_t value);
int   proc_read_line(const char *path, char *buf, size_t len);
int   proc_read_u64(const char *path, uint64_t *val);
bool  is_root(void);
void  cxmod_die(const char *fmt, ...);
void  cxmod_warn(const char *fmt, ...);
void  cxmod_info(const char *fmt, ...);
void  cxmod_ok(const char *fmt, ...);
void  cxmod_section(const char *title);
void  print_bar(const char *label, uint64_t val, uint64_t max, int width, const char *color);
const char *sev_str(cxmod_sev_t s);
const char *sev_color(cxmod_sev_t s);
void  report_add(cxmod_report_t *r, cxmod_sev_t sev, const char *sub,
                 const char *msg, const char *fix);
void  report_print(const cxmod_report_t *r);

/* ── iface.c ──────────────────────────────────────────────────────────────── */
int  iface_list(cxmod_iface_t *ifaces, int max);
int  iface_get(const char *name, cxmod_iface_t *iface);
void iface_print(const cxmod_iface_t *iface);
void iface_print_all(const cxmod_iface_t *ifaces, int n);

/* ── diagnose.c ───────────────────────────────────────────────────────────── */
int diagnose_all(cxmod_report_t *report);
int diagnose_buffers(cxmod_report_t *report);
int diagnose_conntrack(cxmod_report_t *report);
int diagnose_timewait(cxmod_report_t *report);
int diagnose_irq(cxmod_report_t *report);
int diagnose_synbacklog(cxmod_report_t *report);
int diagnose_retransmit(cxmod_report_t *report);
int diagnose_drops(cxmod_report_t *report, const cxmod_iface_t *ifaces, int n);
int diagnose_mtu(cxmod_report_t *report, const cxmod_iface_t *ifaces, int n);
int diagnose_memory(cxmod_report_t *report);
int diagnose_filedescs(cxmod_report_t *report);

/* ── tune.c ───────────────────────────────────────────────────────────────── */
int tune_apply_profile(cxmod_profile_t profile, bool dry_run);
int tune_set_param(const char *key, const char *value, bool dry_run);
int tune_print_current(void);
int tune_bdp_calc(uint64_t bandwidth_mbps, double rtt_ms);
int tune_auto_bdp(bool dry_run);
const char *profile_name(cxmod_profile_t p);
const char *profile_desc(cxmod_profile_t p);

/* ── conntrack.c ──────────────────────────────────────────────────────────── */
int conntrack_read(cxmod_conntrack_t *ct);
int conntrack_fix(bool dry_run);
int conntrack_print(const cxmod_conntrack_t *ct);
int connstates_read(cxmod_connstates_t *cs);
void connstates_print(const cxmod_connstates_t *cs);

/* ── proto.c ──────────────────────────────────────────────────────────────── */
int proto_read_snmp(cxmod_tcpstat_t *st);
void proto_print(const cxmod_tcpstat_t *st);
int proto_retrans_rate(const cxmod_tcpstat_t *st, double *pct);

/* ── irq.c ────────────────────────────────────────────────────────────────── */
int irq_get_nic_irqs(const char *iface, cxmod_irqinfo_t *irqs, int max);
int irq_balance(const char *iface, bool dry_run);
int irq_show(const char *iface);
int irq_set_rps(const char *iface, bool dry_run);

/* ── qos.c ────────────────────────────────────────────────────────────────── */
int qos_apply(const char *iface, uint32_t bw_mbit, bool dry_run);
int qos_remove(const char *iface, bool dry_run);
int qos_show(const char *iface);

/* ── route.c ──────────────────────────────────────────────────────────────── */
int route_show(void);
int route_add(const char *dest, const char *gw, const char *iface, int metric, bool dry_run);
int route_del(const char *dest, bool dry_run);

/* ── monitor.c ────────────────────────────────────────────────────────────── */
int monitor_run(const char *iface, int interval_ms);

/* ── sockstat.c ───────────────────────────────────────────────────────────── */
int sockstat_print_all(void);
int sockstat_diagnose(cxmod_report_t *r);

/* ── offload.c ────────────────────────────────────────────────────────────── */
int offload_show(const char *iface);
int offload_set(const char *iface, const char *feature, bool enable, bool dry_run);
int offload_fix_lro(const char *iface, bool dry_run);

/* ── persist.c ────────────────────────────────────────────────────────────── */
int persist_write(cxmod_profile_t profile, const char *path);
int persist_show(void);
int persist_remove(void);

/* ── report.c ─────────────────────────────────────────────────────────────── */
int report_generate(const char *output_path, bool json_mode);

/* ── fix.c ────────────────────────────────────────────────────────────────── */
int fix_all(bool dry_run, bool verbose);

#endif /* CXMOD_H */
