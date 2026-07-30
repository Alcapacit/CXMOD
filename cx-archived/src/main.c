/*
 * main.c — CXMOD command-line interface
 *
 * Usage:
 *   cxmod diagnose                           Full network health report
 *   cxmod fix [--dry-run]                    Fix everything in one shot
 *   cxmod tune --profile=<P>                 Apply tuning profile
 *   cxmod tune --list                        List available profiles
 *   cxmod tune --current                     Show current kernel values
 *   cxmod tune --bdp <Mbit> <ms>             BDP buffer calculator
 *   cxmod tune --auto-bdp                    Auto-detect BDP from interface speed
 *   cxmod tune --set <key>=<value>           Set individual sysctl
 *   cxmod conntrack --stats                  conntrack table status
 *   cxmod conntrack --states                 TCP connection state counts
 *   cxmod conntrack --fix                    Fix conntrack overflow
 *   cxmod irq --show [--iface=<if>]          Show IRQ distribution
 *   cxmod irq --balance [--iface=<if>]       Balance IRQs across CPUs
 *   cxmod irq --rps [--iface=<if>]           Enable RPS/XPS
 *   cxmod qos --apply --iface=<if> --bw=<M>  Apply HTB QoS
 *   cxmod qos --remove --iface=<if>          Remove QoS from interface
 *   cxmod qos --show [--iface=<if>]          Show active qdiscs
 *   cxmod route --show                       Display routing table
 *   cxmod route --add <dst> [via <gw>] [dev <if>] [metric <m>]
 *   cxmod route --del <dst>                  Delete a route
 *   cxmod sockstat                           Socket & buffer statistics
 *   cxmod offload [--iface=<if>]             Show NIC offload status
 *   cxmod offload --fix-lro [--iface=<if>]   Disable LRO
 *   cxmod offload --set <feat> on|off        Set offload feature
 *   cxmod persist --profile=<P>              Write settings to sysctl.d
 *   cxmod persist --show                     Show saved config
 *   cxmod persist --remove                   Remove saved config
 *   cxmod report [--output=<file>]           Generate diagnostic report
 *   cxmod report --json [--output=<file>]    Generate JSON report
 *   cxmod proto                              Protocol statistics
 *   cxmod iface [--iface=<if>]               Interface statistics
 *   cxmod monitor [--iface=<if>] [--interval=<ms>]
 *   cxmod version                            Print version
 *
 * Global flags:
 *   --dry-run     Print commands without executing
 *   --verbose     Verbose output
 *   --no-color    Disable ANSI colour
 *   --json        JSON output (where supported)
 *   --iface=<N>   Target interface name
 */

#include "cxmod.h"
#include <string.h>

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static void print_version(void)
{
    if (cxmod_color) printf(COL_BOLD COL_BLUE);
    printf("CXMOD v" CXMOD_VERSION "\n");
    if (cxmod_color) printf(COL_RESET);
    printf("Connection eXperience MODule — Linux server network management\n");
    printf("Compiled: " __DATE__ " " __TIME__ "\n");
    printf("License: Apache-2.0-or-later\n");
    printf("Source:   https://github.com/Alcapacit/CXMOD \n");
}

static void print_usage(const char *prog)
{
    if (cxmod_color) printf(COL_BOLD);
    printf("Usage: %s <subcommand> [options]\n\n", prog);
    if (cxmod_color) printf(COL_RESET);

    printf("DIAGNOSTICS & FIXES\n");
    printf("  diagnose                   Full network health check (47+ checks)\n");
    printf("  fix [--dry-run]            Fix all issues in one shot\n");
    printf("  report [--json] [--output=F] Generate diagnostic report file\n");
    printf("\nTUNING\n");
    printf("  tune --profile=<P>         Apply tuning profile\n");
    printf("    Profiles: balanced | high_throughput | low_latency | satellite | hardened\n");
    printf("  tune --list                List all profiles with descriptions\n");
    printf("  tune --current             Show current kernel parameter values\n");
    printf("  tune --bdp <Mb> <ms>       Calculate optimal buffer for bandwidth×RTT\n");
    printf("  tune --auto-bdp            Auto-detect BDP from interface speeds\n");
    printf("  tune --set KEY=VALUE       Set a single sysctl\n");
    printf("\nPERSISTENCE\n");
    printf("  persist --profile=<P>      Write tuning to /etc/sysctl.d/90-cxmod.conf\n");
    printf("  persist --show             Show saved persistent configuration\n");
    printf("  persist --remove           Remove saved configuration\n");
    printf("\nCONNECTION TRACKING\n");
    printf("  conntrack                  Show table usage and timeouts\n");
    printf("  conntrack --states         TCP connection state breakdown\n");
    printf("  conntrack --fix            Scale table to RAM, fix timeouts\n");
    printf("\nIRQ & STEERING\n");
    printf("  irq                        Show NIC IRQ distribution across CPUs\n");
    printf("  irq --balance              Distribute IRQs round-robin\n");
    printf("  irq --rps                  Enable RPS/XPS on all queues\n");
    printf("  [all irq commands accept --iface=<N>]\n");
    printf("\nNIC OFFLOAD\n");
    printf("  offload [--iface=<N>]      Show TSO/GSO/GRO/LRO status\n");
    printf("  offload --fix-lro          Disable LRO on all interfaces\n");
    printf("  offload --set <feat> on|off Toggle a specific offload feature\n");
    printf("\nQOS TRAFFIC SHAPING\n");
    printf("  qos --apply --iface=<N> --bw=<Mbit>  Apply 4-class HTB QoS\n");
    printf("  qos --remove --iface=<N>  Remove QoS from interface\n");
    printf("  qos --show [--iface=<N>]  Show active qdiscs\n");
    printf("\nROUTING\n");
    printf("  route                      Display routing table\n");
    printf("  route --add <dst> [via <gw>] [dev <if>] [metric <m>]\n");
    printf("  route --del <dst>          Delete route\n");
    printf("\nSTATISTICS\n");
    printf("  proto                      Protocol stats from /proc/net/snmp\n");
    printf("  sockstat                   Socket & buffer pressure stats\n");
    printf("  iface [--iface=<N>]        Interface statistics\n");
    printf("  monitor [--iface=<N>] [--interval=<ms>]  Live monitor\n");
    printf("\nGLOBAL OPTIONS\n");
    printf("  --dry-run    Print commands without executing\n");
    printf("  --verbose    Verbose output\n");
    printf("  --no-color   Disable ANSI colour\n");
    printf("  --json       JSON output (report, diagnose)\n");
    printf("  --iface=<N>  Target interface\n");
    printf("\nEXAMPLES\n");
    printf("  sudo cx diagnose\n");
    printf("  sudo cx fix\n");
    printf("  sudo cx fix --dry-run\n");
    printf("  sudo cx tune --profile=high_throughput\n");
    printf("  sudo cx persist --profile=balanced\n");
    printf("  cx tune --bdp 10000 20\n");
    printf("  cx tune --auto-bdp\n");
    printf("  sudo cx conntrack --fix\n");
    printf("  sudo cx irq --balance && sudo cx irq --rps\n");
    printf("  sudo cx qos --apply --iface=eth0 --bw=1000\n");
    printf("  cx report --json --output=/tmp/report.json\n");
    printf("  cx monitor --interval=500\n");
}

static bool has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], flag) == 0) return true;
    return false;
}

static const char *get_opt(int argc, char **argv, const char *prefix)
{
    size_t plen = strlen(prefix);
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], prefix, plen) == 0) return argv[i] + plen;
    return NULL;
}

static const char *opt_val(const char *arg, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) == 0) return arg + plen;
    return NULL;
}

static cxmod_profile_t parse_profile(const char *name)
{
    if (!name) return PROFILE_BALANCED;
    if (strcmp(name, "balanced")         == 0) return PROFILE_BALANCED;
    if (strcmp(name, "high_throughput")  == 0) return PROFILE_HIGH_THROUGHPUT;
    if (strcmp(name, "low_latency")      == 0) return PROFILE_LOW_LATENCY;
    if (strcmp(name, "satellite")        == 0) return PROFILE_SATELLITE;
    if (strcmp(name, "hardened")         == 0) return PROFILE_HARDENED;
    fprintf(stderr, "Unknown profile: %s\n", name);
    fprintf(stderr, "  Use: balanced | high_throughput | low_latency | satellite | hardened\n");
    return PROFILE_COUNT;
}

/* ═══════════════════════════════ MAIN ═══════════════════════════════════════ */

int main(int argc, char **argv)
{
    if (argc < 2) { print_usage(argv[0]); return 0; }

    /* Parse global flags */
    cxmod_dry_run = has_flag(argc, argv, "--dry-run");
    cxmod_verbose = has_flag(argc, argv, "--verbose");
    cxmod_json    = has_flag(argc, argv, "--json");
    cxmod_color   = !has_flag(argc, argv, "--no-color") && isatty(STDOUT_FILENO);

    const char *iface  = get_opt(argc, argv, "--iface=");
    const char *subcmd = argv[1];

    /* ── version / help ── */
    if (strcmp(subcmd, "version") == 0 || strcmp(subcmd, "--version") == 0) {
        print_version(); return 0;
    }
    if (strcmp(subcmd, "--help") == 0 || strcmp(subcmd, "help") == 0) {
        print_usage(argv[0]); return 0;
    }

    /* ── diagnose ── */
    if (strcmp(subcmd, "diagnose") == 0 || strcmp(subcmd, "diag") == 0) {
        if (cxmod_json) {
            return report_generate(NULL, true);
        }
        print_version();

        cxmod_section("INTERFACE STATUS");
        cxmod_iface_t ifaces[CXMOD_MAX_IFS];
        int n = iface_list(ifaces, CXMOD_MAX_IFS);
        if (n > 0) iface_print_all(ifaces, n);

        cxmod_tcpstat_t st; proto_read_snmp(&st); proto_print(&st);
        cxmod_conntrack_t ct; conntrack_read(&ct); conntrack_print(&ct);
        cxmod_connstates_t cs; connstates_read(&cs); connstates_print(&cs);
        sockstat_print_all();

        cxmod_report_t report;
        diagnose_all(&report);
        sockstat_diagnose(&report);
        report_print(&report);

        if (report.critical > 0) {
            if (cxmod_color) printf(COL_RED COL_BOLD);
            printf("\n  %d CRITICAL issue(s) found. Run: sudo cx fix\n",
                   report.critical);
            if (cxmod_color) printf(COL_RESET);
            return 1;
        }
        return 0;
    }

    /* ── fix ── */
    if (strcmp(subcmd, "fix") == 0) {
        return fix_all(cxmod_dry_run, cxmod_verbose);
    }

    /* ── tune ── */
    if (strcmp(subcmd, "tune") == 0) {
        if (has_flag(argc, argv, "--list")) {
            cxmod_section("AVAILABLE TUNING PROFILES");
            for (int p = 0; p < PROFILE_COUNT; p++)
                printf("  %-20s %s\n", profile_name(p), profile_desc(p));
            return 0;
        }
        if (has_flag(argc, argv, "--current"))
            return tune_print_current();
        if (has_flag(argc, argv, "--auto-bdp"))
            return tune_auto_bdp(cxmod_dry_run);
        if (has_flag(argc, argv, "--bdp")) {
            uint64_t bw = 1000; double rtt = 10.0;
            for (int i = 2; i < argc - 1; i++) {
                if (strcmp(argv[i], "--bdp") == 0) {
                    bw  = (uint64_t)strtoull(argv[i+1], NULL, 10);
                    if (i + 2 < argc) rtt = atof(argv[i+2]);
                    break;
                }
            }
            return tune_bdp_calc(bw, rtt);
        }
        /* --set key=value */
        const char *setval = get_opt(argc, argv, "--set=");
        if (!setval) {
            for (int i = 2; i < argc - 1; i++)
                if (strcmp(argv[i], "--set") == 0) { setval = argv[i+1]; break; }
        }
        if (setval) {
            char key[128];
            char *eq = strchr(setval, '=');
            if (!eq) { fprintf(stderr, "Use --set key=value\n"); return 1; }
            size_t klen = (size_t)(eq - setval);
            if (klen >= sizeof(key)) klen = sizeof(key) - 1;
            memcpy(key, setval, klen); key[klen] = '\0';
            return tune_set_param(key, eq + 1, cxmod_dry_run);
        }
        const char *pname = get_opt(argc, argv, "--profile=");
        cxmod_profile_t profile = parse_profile(pname);
        if (profile >= PROFILE_COUNT) return 1;
        return tune_apply_profile(profile, cxmod_dry_run);
    }

    /* ── persist ── */
    if (strcmp(subcmd, "persist") == 0) {
        if (has_flag(argc, argv, "--show"))   return persist_show();
        if (has_flag(argc, argv, "--remove")) return persist_remove();
        const char *pname = get_opt(argc, argv, "--profile=");
        cxmod_profile_t profile = parse_profile(pname);
        if (profile >= PROFILE_COUNT) return 1;
        cxmod_section("PERSIST CONFIGURATION");
        int rc = tune_apply_profile(profile, cxmod_dry_run);
        if (rc == CXMOD_OK || cxmod_dry_run) {
            const char *out = get_opt(argc, argv, "--output=");
            return persist_write(profile, out);
        }
        return rc;
    }

    /* ── conntrack ── */
    if (strcmp(subcmd, "conntrack") == 0) {
        if (has_flag(argc, argv, "--fix")) return conntrack_fix(cxmod_dry_run);
        if (has_flag(argc, argv, "--states")) {
            cxmod_connstates_t cs; connstates_read(&cs); connstates_print(&cs);
            return 0;
        }
        cxmod_conntrack_t ct;
        int rc = conntrack_read(&ct);
        conntrack_print(&ct);
        return rc == CXMOD_ENOFILE ? 0 : rc;
    }

    /* ── irq ── */
    if (strcmp(subcmd, "irq") == 0) {
        if (has_flag(argc, argv, "--balance")) return irq_balance(iface, cxmod_dry_run);
        if (has_flag(argc, argv, "--rps"))     return irq_set_rps(iface, cxmod_dry_run);
        return irq_show(iface);
    }

    /* ── offload ── */
    if (strcmp(subcmd, "offload") == 0) {
        if (has_flag(argc, argv, "--fix-lro")) return offload_fix_lro(iface, cxmod_dry_run);
        if (has_flag(argc, argv, "--set")) {
            const char *feat = NULL; const char *onoff = NULL;
            for (int i = 2; i < argc; i++) {
                if (strcmp(argv[i], "--set") == 0 && i + 2 < argc) {
                    feat  = argv[i+1];
                    onoff = argv[i+2];
                    break;
                }
            }
            if (!feat || !onoff) { fprintf(stderr, "Usage: cx offload --set <feature> on|off\n"); return 1; }
            bool enable = (strcmp(onoff, "on") == 0);
            return offload_set(iface, feat, enable, cxmod_dry_run);
        }
        return offload_show(iface);
    }

    /* ── qos ── */
    if (strcmp(subcmd, "qos") == 0) {
        if (has_flag(argc, argv, "--remove")) {
            if (!iface) { fprintf(stderr, "Need --iface=<name>\n"); return 1; }
            return qos_remove(iface, cxmod_dry_run);
        }
        if (has_flag(argc, argv, "--show")) return qos_show(iface);
        if (!iface) { fprintf(stderr, "Need --iface=<name>\n"); return 1; }
        const char *bw_s = get_opt(argc, argv, "--bw=");
        uint32_t bw = bw_s ? (uint32_t)strtoul(bw_s, NULL, 10) : 100;
        return qos_apply(iface, bw, cxmod_dry_run);
    }

    /* ── route ── */
    if (strcmp(subcmd, "route") == 0) {
        if (has_flag(argc, argv, "--add")) {
            const char *dest = NULL, *gw = NULL, *dev = NULL; int metric = 0;
            for (int i = 2; i < argc; i++) {
                if (strcmp(argv[i], "--add") == 0 && i+1 < argc)    dest = argv[++i];
                else if (strcmp(argv[i], "via") == 0 && i+1 < argc) gw   = argv[++i];
                else if (strcmp(argv[i], "dev") == 0 && i+1 < argc) dev  = argv[++i];
                else if (strcmp(argv[i], "metric") == 0 && i+1 < argc) metric = atoi(argv[++i]);
                else { const char *v;
                    if ((v = opt_val(argv[i], "--via="))    != NULL) gw     = v;
                    if ((v = opt_val(argv[i], "--dev="))    != NULL) dev    = v;
                    if ((v = opt_val(argv[i], "--metric=")) != NULL) metric = atoi(v);
                    if (argv[i][0] != '-' && !dest && strcmp(argv[i], "--add") != 0) dest = argv[i];
                }
            }
            if (!dest) { fprintf(stderr, "Need destination\n"); return 1; }
            return route_add(dest, gw, dev ? dev : iface, metric, cxmod_dry_run);
        }
        if (has_flag(argc, argv, "--del")) {
            const char *dest = NULL;
            for (int i = 2; i < argc; i++) {
                if (strcmp(argv[i], "--del") == 0 && i+1 < argc) { dest = argv[++i]; break; }
                const char *v = opt_val(argv[i], "--del=");
                if (v) { dest = v; break; }
            }
            if (!dest) { fprintf(stderr, "Need destination\n"); return 1; }
            return route_del(dest, cxmod_dry_run);
        }
        return route_show();
    }

    /* ── sockstat ── */
    if (strcmp(subcmd, "sockstat") == 0) {
        return sockstat_print_all();
    }

    /* ── proto ── */
    if (strcmp(subcmd, "proto") == 0) {
        cxmod_tcpstat_t st; proto_read_snmp(&st); proto_print(&st);
        return 0;
    }

    /* ── iface ── */
    if (strcmp(subcmd, "iface") == 0 || strcmp(subcmd, "interfaces") == 0) {
        cxmod_section("NETWORK INTERFACES");
        cxmod_iface_t ifaces[CXMOD_MAX_IFS]; int n;
        if (iface) { n = 1; iface_get(iface, &ifaces[0]); }
        else        { n = iface_list(ifaces, CXMOD_MAX_IFS); }
        iface_print_all(ifaces, n);
        return 0;
    }

    /* ── report ── */
    if (strcmp(subcmd, "report") == 0) {
        const char *out = get_opt(argc, argv, "--output=");
        return report_generate(out, cxmod_json);
    }

    /* ── monitor ── */
    if (strcmp(subcmd, "monitor") == 0 || strcmp(subcmd, "mon") == 0) {
        const char *intv_s = get_opt(argc, argv, "--interval=");
        int interval = intv_s ? atoi(intv_s) : 1000;
        return monitor_run(iface, interval);
    }

    fprintf(stderr, "Unknown subcommand: %s\n", subcmd);
    fprintf(stderr, "Run '%s --help' for usage\n", argv[0]);
    return 1;
}
