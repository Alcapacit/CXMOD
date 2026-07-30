/*
 * qos.c — HTB QoS traffic shaping via tc(8)
 *
 * Builds and applies a complete HTB hierarchy:
 *
 *   root (HTB)  ← total bandwidth cap
 *   └─ 1:1     ← parent class
 *       ├─ 1:10  REALTIME    (SSH, VoIP, STUN)       prio 0
 *       ├─ 1:20  INTERACTIVE (HTTP/S, DNS, APIs)      prio 1
 *       ├─ 1:30  BULK        (FTP, NFS, rsync)        prio 2
 *       └─ 1:40  BACKGROUND  (BitTorrent, updates)    prio 3
 *
 * Each leaf gets SFQ for per-flow fairness within the class.
 * u32 filters match dport/sport to route packets to the right class.
 *
 * Falls back to printing the commands when tc is not available.
 */

#include "cxmod.h"
#include <string.h>

#define TC_BIN   "/sbin/tc"
#define IP_BIN   "/sbin/ip"

static int run_cmd(const char *cmd, bool dry_run)
{
    if (dry_run) {
        printf("  %s\n", cmd);
        return 0;
    }
    int rc = system(cmd);
    return WEXITSTATUS(rc);
}

/* Priority class definitions */
typedef struct {
    int         minor;    /* classid 1:minor */
    int         prio;
    int         rate_pct; /* % of total */
    int         ceil_pct;
    const char *burst;
    const char *desc;
    int         ports[8];
    int         nports;
} htb_class_t;

static const htb_class_t CLASSES[] = {
    { 10, 0, 20, 100, "32kbit",  "REALTIME    (SSH, VoIP, STUN)",
      {22, 5060, 5061, 3478, 3479, 0}, 5 },
    { 20, 1, 50, 100, "64kbit",  "INTERACTIVE (HTTP/S, DNS, APIs)",
      {80, 443, 53, 8080, 8443, 5000, 0}, 6 },
    { 30, 2, 25,  80, "128kbit", "BULK        (FTP, NFS, rsync)",
      {21, 20, 2049, 873, 9000, 0}, 5 },
    { 40, 3,  5,  30, "16kbit",  "BACKGROUND  (BitTorrent, updates)",
      {6881, 6882, 6883, 51413, 0}, 4 },
};
#define NCLASSES 4

int qos_apply(const char *iface, uint32_t bw_mbit, bool dry_run)
{
    cxmod_section("QOS: APPLYING HTB POLICY");
    printf("  Interface:  %s\n", iface);
    printf("  Bandwidth:  %u Mbit/s\n", bw_mbit);
    printf("  Dry-run:    %s\n\n", dry_run ? "YES" : "NO");

    char cmd[512];
    char root_rate[32];
    snprintf(root_rate, sizeof(root_rate), "%umbit", bw_mbit);

    /* 1. Clear existing */
    snprintf(cmd, sizeof(cmd),
             TC_BIN " qdisc del dev %s root 2>/dev/null || true", iface);
    run_cmd(cmd, dry_run);

    /* 2. Root HTB qdisc (default to BULK class 1:30) */
    snprintf(cmd, sizeof(cmd),
             TC_BIN " qdisc add dev %s root handle 1: htb default 30", iface);
    if (run_cmd(cmd, dry_run) != 0 && !dry_run) {
        cxmod_warn("Failed to add root qdisc — tc not available?");
        return CXMOD_ERR;
    }

    /* 3. Root class */
    snprintf(cmd, sizeof(cmd),
             TC_BIN " class add dev %s parent 1: classid 1:1 htb "
             "rate %s ceil %s", iface, root_rate, root_rate);
    run_cmd(cmd, dry_run);

    /* 4. Leaf classes + SFQ */
    for (int i = 0; i < NCLASSES; i++) {
        const htb_class_t *c = &CLASSES[i];
        uint32_t rate_kbps = bw_mbit * 1000 * c->rate_pct / 100;
        uint32_t ceil_kbps = bw_mbit * 1000 * c->ceil_pct / 100;

        snprintf(cmd, sizeof(cmd),
                 TC_BIN " class add dev %s parent 1:1 classid 1:%d htb "
                 "rate %ukbit ceil %ukbit burst %s prio %d",
                 iface, c->minor, rate_kbps, ceil_kbps, c->burst, c->prio);
        run_cmd(cmd, dry_run);

        /* SFQ within each leaf */
        snprintf(cmd, sizeof(cmd),
                 TC_BIN " qdisc add dev %s parent 1:%d handle %d: sfq perturb 10",
                 iface, c->minor, c->minor);
        run_cmd(cmd, dry_run);
    }

    /* 5. u32 filters: match dport and sport → class */
    for (int i = 0; i < NCLASSES; i++) {
        const htb_class_t *c = &CLASSES[i];
        for (int p = 0; p < c->nports && c->ports[p]; p++) {
            int port = c->ports[p];

            /* TCP dport */
            snprintf(cmd, sizeof(cmd),
                     TC_BIN " filter add dev %s parent 1: protocol ip "
                     "prio %d u32 match ip protocol 6 0xff "
                     "match ip dport %d 0xffff flowid 1:%d",
                     iface, c->prio + 1, port, c->minor);
            run_cmd(cmd, dry_run);

            /* TCP sport (return traffic) */
            snprintf(cmd, sizeof(cmd),
                     TC_BIN " filter add dev %s parent 1: protocol ip "
                     "prio %d u32 match ip protocol 6 0xff "
                     "match ip sport %d 0xffff flowid 1:%d",
                     iface, c->prio + 1, port, c->minor);
            run_cmd(cmd, dry_run);

            /* UDP dport */
            snprintf(cmd, sizeof(cmd),
                     TC_BIN " filter add dev %s parent 1: protocol ip "
                     "prio %d u32 match ip protocol 17 0xff "
                     "match ip dport %d 0xffff flowid 1:%d",
                     iface, c->prio + 1, port, c->minor);
            run_cmd(cmd, dry_run);
        }
    }

    printf("\n");
    if (!dry_run)
        cxmod_ok("HTB policy applied to %s (%u Mbit/s, 4 priority classes)",
                 iface, bw_mbit);
    else {
        printf("\n  Classes:\n");
        for (int i = 0; i < NCLASSES; i++) {
            const htb_class_t *c = &CLASSES[i];
            printf("    1:%-3d  %s\n", c->minor, c->desc);
            printf("           rate=%u%% ceil=%u%% burst=%s\n",
                   c->rate_pct, c->ceil_pct, c->burst);
        }
    }
    return CXMOD_OK;
}

int qos_remove(const char *iface, bool dry_run)
{
    cxmod_section("QOS: REMOVING POLICY");
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             TC_BIN " qdisc del dev %s root 2>/dev/null || true", iface);
    run_cmd(cmd, dry_run);
    if (!dry_run) cxmod_ok("QoS removed from %s", iface);
    return CXMOD_OK;
}

int qos_show(const char *iface)
{
    cxmod_section("QOS: ACTIVE QDISCS");
    char cmd[256];
    if (iface)
        snprintf(cmd, sizeof(cmd), TC_BIN " -s qdisc show dev %s", iface);
    else
        snprintf(cmd, sizeof(cmd), TC_BIN " -s qdisc show");
    int rc = system(cmd);
    if (WEXITSTATUS(rc) != 0)
        cxmod_info("No qdiscs found (tc not available or no policy applied)");
    return CXMOD_OK;
}
