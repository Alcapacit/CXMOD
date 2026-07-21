/*
 * offload.c — NIC hardware offload detection and management
 *
 * PROBLEM: Several NIC offloads cause issues in production:
 *   - LRO (Large Receive Offload): coalesces packets, breaks TCP RWIN
 *     measurements, causes HOL blocking — should be OFF on routers/bridges
 *   - TSO (TCP Segmentation Offload): can inflate latency for small packets
 *   - GRO (Generic Receive Offload): usually fine but may mask drops
 *   - GSOcheck: needed for virtual NICs
 *
 * This module detects offload settings via /sys/class/net/<if>/features
 * (read-only) or by calling ethtool(8) as a subprocess when available.
 * Writes are done via ethtool.
 *
 * Offload health rules:
 *   - On physical servers: TSO=on GRO=on LRO=off GSOcheck=on
 *   - On VM guests:       TSO=off GRO=on LRO=off GSOcheck=on
 *   - On routers/bridges: TSO=off GRO=off LRO=off (forwarding path)
 */

#include "cxmod.h"
#include <string.h>

typedef struct {
    char name[CXMOD_IFNAMSIZ];
    bool tso;      /* TCP Segmentation Offload */
    bool gso;      /* Generic Segmentation Offload */
    bool gro;      /* Generic Receive Offload */
    bool lro;      /* Large Receive Offload */
    bool rx_csum;  /* RX checksum offload */
    bool tx_csum;  /* TX checksum offload */
    bool scatter_gather;
    bool available; /* ethtool available */
} cxmod_offload_t;

/* Run `ethtool -k <iface>` and parse output */
static int read_offload_ethtool(const char *iface, cxmod_offload_t *off)
{
    if (!iface_name_safe(iface)) return CXMOD_ERR;
    char ethtool[CXMOD_PATH_MAX];
    if (find_tool("ethtool", ethtool, sizeof(ethtool)) != CXMOD_OK)
        return CXMOD_ENOFILE;
    char cmd[CXMOD_PATH_MAX];
    snprintf(cmd, sizeof(cmd), "%s -k %s 2>/dev/null", ethtool, iface);

    FILE *f = popen(cmd, "r");
    if (!f) return CXMOD_ERR;

    char line[CXMOD_LINE_MAX];
    while (fgets(line, sizeof(line), f)) {
        char key[128], val[64];
        /* Format: "feature-name: on/off [fixed]" */
        if (sscanf(line, " %127[^:]: %63s", key, val) == 2) {
            bool on = (strncmp(val, "on", 2) == 0);
            if (strstr(key, "tx-tcp-segmentation") || strcmp(key, "tso") == 0)
                off->tso = on;
            else if (strstr(key, "generic-segmentation-offload") || strcmp(key, "gso") == 0)
                off->gso = on;
            else if (strstr(key, "generic-receive-offload") || strcmp(key, "gro") == 0)
                off->gro = on;
            else if (strstr(key, "large-receive-offload") || strcmp(key, "lro") == 0)
                off->lro = on;
            else if (strstr(key, "rx-checksumming") || strcmp(key, "rx-csum") == 0)
                off->rx_csum = on;
            else if (strstr(key, "tx-checksumming") || strcmp(key, "tx-csum") == 0)
                off->tx_csum = on;
            else if (strstr(key, "scatter-gather") || strcmp(key, "sg") == 0)
                off->scatter_gather = on;
        }
    }
    int rc = pclose(f);
    off->available = (WEXITSTATUS(rc) == 0);
    return CXMOD_OK;
}

/* Read driver from /sys/class/net/iface/device/driver */
static void read_driver(const char *iface, char *driver, size_t len)
{
    char path[CXMOD_PATH_MAX];
    snprintf(path, sizeof(path),
             "/sys/class/net/%.200s/device/driver", iface);
    /* driver is a symlink — use readlink */
    char link[CXMOD_PATH_MAX];
    ssize_t n = readlink(path, link, sizeof(link) - 1);
    if (n > 0) {
        link[n] = '\0';
        /* basename */
        char *base = strrchr(link, '/');
        const char *src = base ? base + 1 : link;
        size_t slen = strnlen(src, len - 1);
        memcpy(driver, src, slen);
        driver[slen] = '\0';
    } else {
        memcpy(driver, "unknown", 7);
        driver[7] = '\0';
    }
}

int offload_show(const char *iface)
{
    cxmod_section("NIC OFFLOAD STATUS");

    /* Enumerate interfaces to check */
    char ifs_to_do[CXMOD_MAX_IFS][CXMOD_IFNAMSIZ];
    int nifs = 0;

    if (iface) {
        strncpy(ifs_to_do[0], iface, CXMOD_IFNAMSIZ - 1);
        nifs = 1;
    } else {
        DIR *d = opendir("/sys/class/net");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) && nifs < CXMOD_MAX_IFS) {
                if (ent->d_name[0] == '.') continue;
                if (strcmp(ent->d_name, "lo") == 0) continue;
                size_t nlen = strnlen(ent->d_name, CXMOD_IFNAMSIZ - 1);
                memset(ifs_to_do[nifs], 0, CXMOD_IFNAMSIZ);
                memcpy(ifs_to_do[nifs], ent->d_name, nlen);
                nifs++;
            }
            closedir(d);
        }
    }

    /* Check ethtool availability */
    char ethtool_path[CXMOD_PATH_MAX];
    bool has_ethtool = (find_tool("ethtool", ethtool_path, sizeof(ethtool_path)) == CXMOD_OK);
    if (!has_ethtool) {
        cxmod_warn("ethtool not found — install it for full offload info");
        cxmod_info("Ubuntu/Debian: apt-get install ethtool");
        cxmod_info("RHEL/CentOS:   yum install ethtool");
        printf("\n");
    }

    if (cxmod_color) printf(COL_BOLD);
    printf("  %-14s %-10s %-3s %-3s %-3s %-3s %-3s %-3s %-8s\n",
           "Interface", "Driver", "TSO", "GSO", "GRO", "LRO", "RX", "TX", "SG");
    if (cxmod_color) printf(COL_RESET);
    printf("  %s\n",
           "──────────────────────────────────────────────────────────────");

    for (int i = 0; i < nifs; i++) {
        cxmod_offload_t off;
        memset(&off, 0, sizeof(off));
        size_t nlen = strnlen(ifs_to_do[i], sizeof(off.name) - 1);
        memcpy(off.name, ifs_to_do[i], nlen);

        char driver[64] = "N/A";
        read_driver(ifs_to_do[i], driver, sizeof(driver));

        if (has_ethtool)
            read_offload_ethtool(ifs_to_do[i], &off);

        #define BOOL_STR(b) ((b) ? "on " : "off")
        #define BOOL_COL(b,warn_on) \
            (!(b) && (warn_on)) ? COL_YELLOW : \
            ((b) && !(warn_on)) ? COL_RED : COL_GREEN

        printf("  %-14s %-10s ", ifs_to_do[i], driver);

        if (!has_ethtool) {
            printf("(install ethtool for details)\n");
            continue;
        }

        /* TSO: on=good, off=warn on physical */
        if (cxmod_color) printf("%s", off.tso ? COL_GREEN : COL_YELLOW);
        printf("%-3s ", BOOL_STR(off.tso));

        /* GSO: on=good */
        if (cxmod_color) printf("%s", off.gso ? COL_GREEN : COL_YELLOW);
        printf("%-3s ", BOOL_STR(off.gso));

        /* GRO: on=good */
        if (cxmod_color) printf("%s", off.gro ? COL_GREEN : COL_YELLOW);
        printf("%-3s ", BOOL_STR(off.gro));

        /* LRO: off=good (on=problem on routers) */
        if (cxmod_color) printf("%s", !off.lro ? COL_GREEN : COL_YELLOW);
        printf("%-3s ", BOOL_STR(off.lro));

        /* RX/TX csum: on=good */
        if (cxmod_color) printf("%s", off.rx_csum ? COL_GREEN : COL_YELLOW);
        printf("%-3s ", BOOL_STR(off.rx_csum));
        if (cxmod_color) printf("%s", off.tx_csum ? COL_GREEN : COL_YELLOW);
        printf("%-3s ", BOOL_STR(off.tx_csum));

        /* SG */
        if (cxmod_color) printf("%s", off.scatter_gather ? COL_GREEN : COL_YELLOW);
        printf("%-8s", BOOL_STR(off.scatter_gather));

        if (cxmod_color) printf(COL_RESET);

        /* Warn about LRO on */
        if (off.lro) {
            if (cxmod_color) printf(COL_YELLOW);
            printf(" [LRO may cause issues on bridge/router — disable with: "
                   "sudo ethtool -K %s lro off]", ifs_to_do[i]);
            if (cxmod_color) printf(COL_RESET);
        }
        printf("\n");
    }
    return CXMOD_OK;
}

int offload_set(const char *iface, const char *feature, bool enable, bool dry_run)
{
    if (!iface) { fprintf(stderr, "Need --iface\n"); return CXMOD_ERR; }
    if (!iface_name_safe(iface)) {
        fprintf(stderr, "Invalid interface name: %s\n", iface);
        return CXMOD_ERR;
    }
    char ethtool[CXMOD_PATH_MAX];
    if (find_tool("ethtool", ethtool, sizeof(ethtool)) != CXMOD_OK) {
        cxmod_warn("ethtool not found — cannot set offload feature");
        return CXMOD_ERR;
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "%s -K %s %s %s", ethtool, iface, feature, enable ? "on" : "off");
    if (dry_run) {
        printf("  [DRY-RUN] %s\n", cmd);
        return CXMOD_OK;
    }
    if (!is_root()) return CXMOD_EPERM;
    int rc = system(cmd);
    if (WEXITSTATUS(rc) == 0)
        cxmod_ok("ethtool -K %s %s %s", iface, feature, enable ? "on" : "off");
    else
        cxmod_warn("Failed to set %s %s", feature, enable ? "on" : "off");
    return WEXITSTATUS(rc) ? CXMOD_ERR : CXMOD_OK;
}

int offload_fix_lro(const char *iface, bool dry_run)
{
    cxmod_section("OFFLOAD FIX: DISABLE LRO");

    if (!is_root() && !dry_run) {
        cxmod_warn("Need root. Re-run: sudo cx offload --fix-lro%s%s",
                   iface ? " --iface=" : "", iface ? iface : "");
        return CXMOD_EPERM;
    }

    char ifs_to_do[CXMOD_MAX_IFS][CXMOD_IFNAMSIZ];
    int nifs = 0;

    if (iface) {
        strncpy(ifs_to_do[0], iface, CXMOD_IFNAMSIZ - 1);
        nifs = 1;
    } else {
        DIR *d = opendir("/sys/class/net");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) && nifs < CXMOD_MAX_IFS) {
                if (ent->d_name[0] == '.') continue;
                if (strcmp(ent->d_name, "lo") == 0) continue;
                size_t nlen = strnlen(ent->d_name, CXMOD_IFNAMSIZ - 1);
                memset(ifs_to_do[nifs], 0, CXMOD_IFNAMSIZ);
                memcpy(ifs_to_do[nifs], ent->d_name, nlen);
                nifs++;
            }
            closedir(d);
        }
    }

    for (int i = 0; i < nifs; i++)
        offload_set(ifs_to_do[i], "lro", false, dry_run);

    return CXMOD_OK;
}
