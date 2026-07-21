/*
 * proto.c — Protocol statistics from /proc/net/snmp and /proc/net/netstat
 *
 * Reads actual kernel MIB counters — the same source as `netstat -s`
 * but without forking a subprocess.  Parses the alternating header/value
 * format used by both files.
 */

#include "cxmod.h"
#include <stddef.h>
#include <string.h>

#define ull unsigned long long

/* ── MIB key → offset in cxmod_tcpstat_t ─────────────────────────────────── */
typedef struct { const char *key; size_t offset; } mib_map_t;

#define OFF(field) offsetof(cxmod_tcpstat_t, field)

static const mib_map_t mib_table[] = {
    { "Tcp.InSegs",           OFF(tcp_in_segs)        },
    { "Tcp.OutSegs",          OFF(tcp_out_segs)        },
    { "Tcp.RetransSegs",      OFF(tcp_retrans)         },
    { "Tcp.InErrs",           OFF(tcp_in_errs)         },
    { "Tcp.EstabResets",      OFF(tcp_estab_resets)    },
    { "Tcp.ActiveOpens",      OFF(tcp_active_opens)    },
    { "Tcp.PassiveOpens",     OFF(tcp_passive_opens)   },
    { "Tcp.SyncookiesSent",   OFF(tcp_syn_cookies_sent)},
    { "Tcp.SyncookiesRecv",   OFF(tcp_syn_cookies_recv)},
    { "Udp.InDatagrams",      OFF(udp_in_dgrams)       },
    { "Udp.OutDatagrams",     OFF(udp_out_dgrams)      },
    { "Udp.InErrors",         OFF(udp_in_errs)         },
    { "Udp.NoPorts",          OFF(udp_no_ports)        },
    { "Icmp.InMsgs",          OFF(icmp_in_msgs)        },
    { "Icmp.OutMsgs",         OFF(icmp_out_msgs)       },
    { NULL, 0 }
};

static void parse_snmp_file(const char *path, cxmod_tcpstat_t *st)
{
    FILE *f = fopen(path, "r");
    if (!f) return;

    char header[CXMOD_LINE_MAX], values[CXMOD_LINE_MAX];
    while (fgets(header, sizeof(header), f) &&
           fgets(values, sizeof(values), f))
    {
        /* header line: "Proto key1 key2 ..." */
        /* values line: "Proto val1 val2 ..." */
        char *hp = header, *vp = values;

        /* read proto name */
        char hproto[32], vproto[32];
        if (sscanf(hp, "%31s", hproto) != 1) continue;
        if (sscanf(vp, "%31s", vproto) != 1) continue;
        /* advance past proto name */
        hp += strlen(hproto); vp += strlen(vproto);

        /* Strip trailing colon from proto */
        size_t plen = strlen(hproto);
        if (plen > 0 && hproto[plen-1] == ':') hproto[plen-1] = '\0';

        while (*hp && *vp) {
            char key[64]; uint64_t val;
            if (sscanf(hp, "%63s", key) != 1) break;
            { unsigned long long _v = 0; if (sscanf(vp, "%llu", &_v) != 1) break; val = (uint64_t)_v; }

            /* build "Proto.Key" */
            char full[128];
            snprintf(full, sizeof(full), "%s.%s", hproto, key);

            for (const mib_map_t *m = mib_table; m->key; m++) {
                if (strcmp(full, m->key) == 0) {
                    uint64_t *field = (uint64_t *)((char *)st + m->offset);
                    *field = val;
                    break;
                }
            }

            /* advance past token */
            hp += strcspn(hp, " \t"); while (*hp == ' ' || *hp == '\t') hp++;
            vp += strcspn(vp, " \t"); while (*vp == ' ' || *vp == '\t') vp++;
        }
    }
    fclose(f);
}

int proto_read_snmp(cxmod_tcpstat_t *st)
{
    memset(st, 0, sizeof(*st));
    parse_snmp_file("/proc/net/snmp",    st);
    parse_snmp_file("/proc/net/netstat", st);
    return CXMOD_OK;
}

int proto_retrans_rate(const cxmod_tcpstat_t *st, double *pct)
{
    if (st->tcp_out_segs == 0) { *pct = 0; return CXMOD_OK; }
    *pct = (double)st->tcp_retrans / (double)st->tcp_out_segs * 100.0;
    return CXMOD_OK;
}

void proto_print(const cxmod_tcpstat_t *st)
{
    double retrans_pct = 0;
    proto_retrans_rate(st, &retrans_pct);

    uint64_t tcp_total  = st->tcp_in_segs  + st->tcp_out_segs;
    uint64_t udp_total  = st->udp_in_dgrams + st->udp_out_dgrams;
    uint64_t icmp_total = st->icmp_in_msgs  + st->icmp_out_msgs;
    uint64_t grand      = tcp_total + udp_total + icmp_total;
    if (grand == 0) grand = 1;

    cxmod_section("PROTOCOL STATISTICS");
    printf("  Source: /proc/net/snmp + /proc/net/netstat\n\n");

    /* Protocol breakdown bars */
    print_bar("TCP",  tcp_total,  grand, 40, COL_BLUE);
    print_bar("UDP",  udp_total,  grand, 40, COL_CYAN);
    print_bar("ICMP", icmp_total, grand, 40, COL_YELLOW);

    printf("\n");
    printf("  TCP  in/out segments:  %llu / %llu\n",
           (ull)st->tcp_in_segs, (ull)st->tcp_out_segs);
    printf("  TCP  retransmits:      %llu  (%.3f%%)\n",
           (ull)st->tcp_retrans, retrans_pct);

    const char *rc = (retrans_pct < 1.0) ? COL_GREEN :
                     (retrans_pct < 3.0) ? COL_YELLOW : COL_RED;
    if (cxmod_color) printf("  TCP  retransmit health: %s%s" COL_RESET "\n",
        rc, (retrans_pct < 1.0) ? "GOOD (<1%)" :
            (retrans_pct < 3.0) ? "ELEVATED (1-3%) — check congestion" :
                                  "BAD (>3%) — serious congestion or loss");
    printf("  TCP  errors:           %llu\n", (ull)st->tcp_in_errs);
    printf("  TCP  resets:           %llu\n", (ull)st->tcp_estab_resets);
    printf("  TCP  active opens:     %llu\n", (ull)st->tcp_active_opens);
    printf("  TCP  passive opens:    %llu\n", (ull)st->tcp_passive_opens);
    printf("  TCP  SYN cookies sent: %llu\n", (ull)st->tcp_syn_cookies_sent);
    printf("\n");
    printf("  UDP  in/out datagrams: %llu / %llu\n",
           (ull)st->udp_in_dgrams, (ull)st->udp_out_dgrams);
    printf("  UDP  errors:           %llu\n", (ull)st->udp_in_errs);
    printf("  UDP  no-port drops:    %llu\n", (ull)st->udp_no_ports);
    printf("\n");
    printf("  ICMP in/out messages:  %llu / %llu\n",
           (ull)st->icmp_in_msgs, (ull)st->icmp_out_msgs);
}
