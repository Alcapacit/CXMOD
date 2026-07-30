/*
 * irq.c — NIC IRQ affinity management and RPS/RFS configuration
 *
 * BOTTLENECK: By default all NIC receive interrupts land on CPU 0.
 * On a busy 10 GbE server this single CPU saturates at ~100% softirq
 * while CPUs 1-N sit idle — throughput caps at one CPU's interrupt rate
 * even though the machine has plenty of spare capacity.
 *
 * FIX 1: Spread NIC IRQs across CPUs (SMP IRQ affinity)
 * FIX 2: Enable RPS (Receive Packet Steering) to fan out to all CPUs
 * FIX 3: Enable XPS (Transmit Packet Steering) to pin TX queues to CPUs
 */

#include "cxmod.h"
#include <string.h>
#include <ctype.h>

static int get_ncpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}

/* Build CPU bitmask string covering all CPUs: e.g. 4 CPUs → "f" */
static void all_cpu_mask(int ncpus, char *buf, size_t len)
{
    /* each hex digit covers 4 CPUs */
    uint64_t mask = 0;
    for (int i = 0; i < ncpus && i < 64; i++)
        mask |= (1ULL << i);
    snprintf(buf, len, "%llx", (unsigned long long)mask);
}

/* ── IRQ show ─────────────────────────────────────────────────────────────── */

int irq_show(const char *iface)
{
    cxmod_section("IRQ DISTRIBUTION");

    int ncpus = get_ncpus();
    printf("  CPUs online: %d\n\n", ncpus);

    FILE *f = fopen("/proc/interrupts", "r");
    if (!f) { cxmod_warn("Cannot open /proc/interrupts"); return CXMOD_ERR; }

    char line[CXMOD_LINE_MAX];
    /* Skip header line */
    fgets(line, sizeof(line), f);

    if (cxmod_color) printf(COL_BOLD);
    printf("  %-6s  %-20s", "IRQ", "Driver/Description");
    for (int c = 0; c < ncpus && c < 8; c++) printf("  CPU%-3d", c);
    printf("  %s\n", ncpus > 8 ? "(+more)" : "");
    if (cxmod_color) printf(COL_RESET);

    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Only show lines containing the iface name (or all if iface is NULL) */
        if (iface && !strstr(line, iface)) continue;
        if (!iface) {
            /* skip non-NIC IRQs when not filtering */
            if (!strstr(line, "eth") && !strstr(line, "ens") &&
                !strstr(line, "enp") && !strstr(line, "bond") &&
                !strstr(line, "em")  && !strstr(line, "p[0-9]") &&
                !strstr(line, "TxRx") && !strstr(line, "mlx") &&
                !strstr(line, "ixgbe") && !strstr(line, "i40e"))
                continue;
        }

        char irq_str[16];
        sscanf(line, "%15s", irq_str);
        /* strip colon */
        char *c = strchr(irq_str, ':');
        if (c) *c = '\0';

        printf("  %-6s  ", irq_str);

        /* Read affinity */
        char aff_path[CXMOD_PATH_MAX];
        snprintf(aff_path, sizeof(aff_path),
                 "/proc/irq/%s/smp_affinity_list", irq_str);
        char aff[64] = "?";
        proc_read_line(aff_path, aff, sizeof(aff));
        printf("%-20s", aff);

        /* Print per-CPU counts */
        char *p = line + strlen(irq_str) + 1;
        while (*p == ' ') p++;
        int cpu = 0;
        while (*p && cpu < ncpus && cpu < 8) {
            uint64_t cnt = strtoull(p, &p, 10);
            printf("  %-7llu", (unsigned long long)cnt);
            cpu++;
            while (*p == ' ') p++;
        }
        printf("\n");
        found++;
    }
    fclose(f);

    if (found == 0)
        printf("  No matching NIC IRQs found%s\n",
               iface ? " for this interface" : "");

    return CXMOD_OK;
}

/* ── IRQ balance ──────────────────────────────────────────────────────────── */

int irq_balance(const char *iface, bool dry_run)
{
    cxmod_section("IRQ AFFINITY BALANCING");

    if (!is_root() && !dry_run) {
        cxmod_warn("Need root. Re-run: sudo cx irq --balance%s%s",
                   iface ? " --iface=" : "", iface ? iface : "");
        return CXMOD_EPERM;
    }

    int ncpus = get_ncpus();
    printf("  CPUs online: %d\n", ncpus);
    if (ncpus < 2) {
        cxmod_info("Single-CPU system — IRQ balancing has no effect");
        return CXMOD_OK;
    }

    /* Enumerate NIC IRQs */
    DIR *d = opendir("/proc/irq");
    if (!d) { cxmod_warn("Cannot open /proc/irq"); return CXMOD_ERR; }

    struct dirent *ent;
    int cpu_round = 0, changed = 0;

    while ((ent = readdir(d))) {
        if (!isdigit(ent->d_name[0])) continue;
        int irq_num = atoi(ent->d_name);

        /* Read device name from /proc/irq/N/spurious or check action */
        char action_path[CXMOD_PATH_MAX];
        snprintf(action_path, sizeof(action_path),
                 "/proc/irq/%d/actions", irq_num);
        char action[128] = "";
        proc_read_line(action_path, action, sizeof(action));

        /* Filter: only NIC IRQs */
        bool is_nic = (strstr(action, "eth")  || strstr(action, "ens")  ||
                       strstr(action, "enp")  || strstr(action, "em")   ||
                       strstr(action, "bond") || strstr(action, "TxRx") ||
                       strstr(action, "mlx")  || strstr(action, "ixgbe")||
                       strstr(action, "i40e") || strstr(action, "virtio"));
        if (!is_nic) continue;

        /* If filtering by iface, check */
        if (iface && !strstr(action, iface)) continue;

        /* Assign this IRQ to next CPU in round-robin */
        int target_cpu = cpu_round % ncpus;
        uint64_t mask  = (1ULL << target_cpu);

        char aff_path[CXMOD_PATH_MAX];
        snprintf(aff_path, sizeof(aff_path),
                 "/proc/irq/%d/smp_affinity", irq_num);
        char mask_str[32];
        snprintf(mask_str, sizeof(mask_str), "%llx", (unsigned long long)mask);

        if (dry_run) {
            printf("  [DRY-RUN] echo %s > %s  (IRQ %d → CPU %d, action=%s)\n",
                   mask_str, aff_path, irq_num, target_cpu, action);
        } else {
            int fd = open(aff_path, O_WRONLY);
            if (fd >= 0) {
                write(fd, mask_str, strlen(mask_str));
                close(fd);
                cxmod_ok("IRQ %d → CPU %d (%s)", irq_num, target_cpu, action);
            } else {
                cxmod_warn("IRQ %d: cannot write affinity (%s)", irq_num, strerror(errno));
            }
        }
        cpu_round++;
        changed++;
    }
    closedir(d);

    if (changed == 0)
        cxmod_info("No NIC IRQs found to balance%s%s",
                   iface ? " for " : "", iface ? iface : "");
    else if (!dry_run)
        cxmod_ok("Balanced %d NIC IRQs across %d CPUs", changed, ncpus);

    return CXMOD_OK;
}

/* ── RPS — Receive Packet Steering ───────────────────────────────────────── */

int irq_set_rps(const char *iface, bool dry_run)
{
    cxmod_section("RPS / XPS CONFIGURATION");

    int ncpus = get_ncpus();
    char mask[32];
    all_cpu_mask(ncpus, mask, sizeof(mask));

    printf("  CPUs online: %d  mask: 0x%s\n\n", ncpus, mask);

    if (!is_root() && !dry_run) {
        cxmod_warn("Need root. Re-run: sudo cx irq --rps%s%s",
                   iface ? " --iface=" : "", iface ? iface : "");
        return CXMOD_EPERM;
    }

    /* If iface given, do just that one; else do all */
    char ifs_to_do[CXMOD_MAX_IFS][CXMOD_IFNAMSIZ];
    int  nifs = 0;

    if (iface) {
        strncpy(ifs_to_do[0], iface, CXMOD_IFNAMSIZ - 1);
        nifs = 1;
    } else {
        /* enumerate from /sys/class/net */
        DIR *d = opendir("/sys/class/net");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) && nifs < CXMOD_MAX_IFS) {
                if (ent->d_name[0] == '.') continue;
                memset(ifs_to_do[nifs], 0, CXMOD_IFNAMSIZ);
                memcpy(ifs_to_do[nifs], ent->d_name,
                       strnlen(ent->d_name, CXMOD_IFNAMSIZ - 1));
                nifs++;
            }
            closedir(d);
        }
    }

    int changed = 0;

    for (int i = 0; i < nifs; i++) {
        const char *ifname = ifs_to_do[i];

        /* Skip loopback */
        if (strcmp(ifname, "lo") == 0) continue;

        /* Set RPS on all RX queues */
        char rx_base[CXMOD_PATH_MAX];
        snprintf(rx_base, sizeof(rx_base),
                 "/sys/class/net/%.15s/queues", ifname);

        DIR *qd = opendir(rx_base);
        if (!qd) continue;

        struct dirent *qent;
        while ((qent = readdir(qd))) {
            if (strncmp(qent->d_name, "rx-", 3) != 0) continue;

            char rps_path[CXMOD_PATH_MAX];
            snprintf(rps_path, sizeof(rps_path),
                     "%.400s/%.80s/rps_cpus", rx_base, qent->d_name);

            if (dry_run) {
                printf("  [DRY-RUN] echo %s > %s\n", mask, rps_path);
            } else {
                int fd = open(rps_path, O_WRONLY);
                if (fd >= 0) {
                    write(fd, mask, strlen(mask));
                    close(fd);
                    cxmod_ok("RPS %s/%s → 0x%s",
                             ifname, qent->d_name, mask);
                    changed++;
                }
            }
        }

        /* Set XPS on all TX queues */
        int cpu_idx = 0;
        while ((qent = readdir(qd))) {
            if (strncmp(qent->d_name, "tx-", 3) != 0) continue;

            char xps_path[CXMOD_PATH_MAX];
            snprintf(xps_path, sizeof(xps_path),
                     "%.400s/%.80s/xps_cpus", rx_base, qent->d_name);

            uint64_t xps_mask = (1ULL << (cpu_idx % ncpus));
            char xps_mask_str[32];
            snprintf(xps_mask_str, sizeof(xps_mask_str), "%llx",
                     (unsigned long long)xps_mask);

            if (dry_run) {
                printf("  [DRY-RUN] echo %s > %s\n", xps_mask_str, xps_path);
            } else {
                int fd = open(xps_path, O_WRONLY);
                if (fd >= 0) {
                    write(fd, xps_mask_str, strlen(xps_mask_str));
                    close(fd);
                }
            }
            cpu_idx++;
        }
        closedir(qd);
    }

    if (!dry_run && changed > 0)
        cxmod_ok("RPS/XPS configured on %d queues", changed);
    else if (!dry_run)
        cxmod_info("No RPS-capable queues found");

    /* Also increase rps_sock_flow_entries for RFS */
    if (dry_run) {
        printf("  [DRY-RUN] sysctl -w net.core.rps_sock_flow_entries=32768\n");
    } else {
        sysctl_write("net.core.rps_sock_flow_entries", "32768");
        cxmod_ok("net.core.rps_sock_flow_entries = 32768");
    }

    return CXMOD_OK;
}
