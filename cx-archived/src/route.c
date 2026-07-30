/*
 * route.c — Routing table management
 * Reads /proc/net/route (kernel FIB) — no subprocess needed for display.
 * add/del operations use `ip route` with dry-run support.
 */

#include "cxmod.h"
#include <string.h>
#include <netinet/in.h>

static void hex_to_ipstr(const char *hex, char *out, size_t len)
{
    unsigned int v;
    sscanf(hex, "%x", &v);
    uint32_t addr = (uint32_t)v;
    /* /proc/net/route stores address in host byte order of little-endian kernel */
    unsigned char *b = (unsigned char *)&addr;
    snprintf(out, len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static int prefix_len(const char *hex_mask)
{
    unsigned int v = 0;
    sscanf(hex_mask, "%x", &v);
    return __builtin_popcount(v);
}

int route_show(void)
{
    cxmod_section("ROUTING TABLE");

    FILE *f = fopen("/proc/net/route", "r");
    if (!f) {
        /* fallback to ip route */
        cxmod_info("Falling back to `ip route show`");
        system("/sbin/ip route show 2>/dev/null || ip route show 2>/dev/null");
        return CXMOD_OK;
    }

    char line[CXMOD_LINE_MAX];
    fgets(line, sizeof(line), f); /* skip header */

    if (cxmod_color) printf(COL_BOLD);
    printf("  %-20s %-16s %-16s %-6s %s\n",
           "Destination", "Gateway", "Interface", "Metric", "Flags");
    if (cxmod_color) printf(COL_RESET);

    while (fgets(line, sizeof(line), f)) {
        char iface[IFNAMSIZ];
        char dest_h[16], gw_h[16], mask_h[16];
        unsigned int flags, metric;

        if (sscanf(line, "%15s %15s %15s %x %*s %*s %u %15s",
                   iface, dest_h, gw_h, &flags, &metric, mask_h) < 5)
            continue;

        char dest_s[20], gw_s[20], mask_s[20];
        hex_to_ipstr(dest_h, dest_s, sizeof(dest_s));
        hex_to_ipstr(gw_h,   gw_s,   sizeof(gw_s));
        hex_to_ipstr(mask_h, mask_s, sizeof(mask_s));
        int plen = prefix_len(mask_h);

        /* Build CIDR */
        char cidr[32];
        if (strcmp(dest_s, "0.0.0.0") == 0)
            snprintf(cidr, sizeof(cidr), "default");
        else
            snprintf(cidr, sizeof(cidr), "%s/%d", dest_s, plen);

        /* Flags */
        char flag_s[16] = "";
        if (flags & 0x0001) strcat(flag_s, "U");
        if (flags & 0x0002) strcat(flag_s, "G");
        if (flags & 0x0004) strcat(flag_s, "H");

        bool is_default = (strcmp(dest_s, "0.0.0.0") == 0);

        if (cxmod_color && is_default) printf(COL_GREEN);
        printf("  %-20s %-16s %-16s %-6u %s\n",
               cidr,
               strcmp(gw_s, "0.0.0.0") == 0 ? "on-link" : gw_s,
               iface, metric, flag_s);
        if (cxmod_color && is_default) printf(COL_RESET);
    }
    fclose(f);
    return CXMOD_OK;
}

int route_add(const char *dest, const char *gw, const char *iface,
              int metric, bool dry_run)
{
    char cmd[512];
    char *p = cmd;
    size_t rem = sizeof(cmd);

    int n = snprintf(p, rem, "/sbin/ip route add %s", dest);
    p += n; rem -= n;
    if (gw && gw[0]) { n = snprintf(p, rem, " via %s", gw);        p += n; rem -= n; }
    if (iface && iface[0]) { n = snprintf(p, rem, " dev %s", iface); p += n; rem -= n; }
    if (metric)  { n = snprintf(p, rem, " metric %d", metric);      p += n; rem -= n; }

    if (dry_run) { printf("  [DRY-RUN] %s\n", cmd); return CXMOD_OK; }
    if (!is_root()) return CXMOD_EPERM;

    int rc = system(cmd);
    if (WEXITSTATUS(rc) == 0) cxmod_ok("Route added: %s", dest);
    else                       cxmod_warn("Route add failed: %s", dest);
    return WEXITSTATUS(rc) ? CXMOD_ERR : CXMOD_OK;
}

int route_del(const char *dest, bool dry_run)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/ip route del %s", dest);
    if (dry_run) { printf("  [DRY-RUN] %s\n", cmd); return CXMOD_OK; }
    if (!is_root()) return CXMOD_EPERM;

    int rc = system(cmd);
    if (WEXITSTATUS(rc) == 0) cxmod_ok("Route deleted: %s", dest);
    else                       cxmod_warn("Route delete failed: %s", dest);
    return WEXITSTATUS(rc) ? CXMOD_ERR : CXMOD_OK;
}
