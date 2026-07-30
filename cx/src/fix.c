/*
 * fix.c — One-shot comprehensive network fix
 *
 * `cx fix` applies all safe remediations in the correct order:
 *
 *  1. Apply balanced tuning profile (TCP buffers, syncookies, tw_reuse, etc.)
 *  2. Fix conntrack table (scale to RAM, aggressive timeout cleanup)
 *  3. Balance NIC IRQs across CPUs
 *  4. Enable RPS/XPS on all interfaces
 *  5. Disable LRO on all interfaces (if ethtool available)
 *  6. Persist settings to /etc/sysctl.d/90-cxmod.conf
 *
 * Each step is skipped gracefully if the prerequisite is missing
 * (no root, no ethtool, conntrack not loaded, etc.).
 *
 * With --dry-run: prints every command that would be executed
 * With --verbose: prints every sysctl being set
 */

#include "cxmod.h"
#include <string.h>

static void step(int n, int total, const char *desc)
{
    if (cxmod_color) printf(COL_BOLD COL_BLUE);
    printf("\n  [%d/%d] %s\n", n, total, desc);
    if (cxmod_color) printf(COL_RESET);
}

static void step_done(bool ok)
{
    if (ok) cxmod_ok("Done");
    else    cxmod_warn("Step completed with warnings (check above)");
}

int fix_all(bool dry_run, bool verbose)
{
    cxmod_section("CXMOD FIX-ALL");
    printf("  Mode: %s\n", dry_run ? "DRY-RUN (no changes applied)" : "LIVE (writing to kernel)");
    if (!is_root() && !dry_run) {
        if (cxmod_color) printf(COL_RED);
        printf("  ERROR: Run as root: sudo cx fix\n");
        if (cxmod_color) printf(COL_RESET);
        return CXMOD_EPERM;
    }

    /* Run diagnostics first so user sees what we're fixing */
    cxmod_report_t report;
    diagnose_all(&report);
    sockstat_diagnose(&report);

    if (report.count == 0 || (report.critical == 0 && report.warnings == 0)) {
        if (cxmod_color) printf(COL_GREEN COL_BOLD);
        printf("\n  No issues detected — system is already well-configured!\n");
        if (cxmod_color) printf(COL_RESET);
        return CXMOD_OK;
    }

    printf("\n  Found %d issue(s) to fix (%d critical, %d warnings)\n",
           report.count, report.critical, report.warnings);

    const int NSTEPS = 6;
    int step_num = 0;
    int errs = 0;

    /* ── Step 1: Apply balanced profile ───────────────────────────────────── */
    step(++step_num, NSTEPS,
         "Apply balanced TCP/IP tuning profile");
    cxmod_verbose = verbose;
    int rc = tune_apply_profile(PROFILE_BALANCED, dry_run);
    step_done(rc == CXMOD_OK);
    if (rc != CXMOD_OK) errs++;

    /* ── Step 2: Fix conntrack ─────────────────────────────────────────────── */
    step(++step_num, NSTEPS, "Fix conntrack table (scale to RAM, reduce timeouts)");
    cxmod_conntrack_t ct;
    int ct_rc = conntrack_read(&ct);
    if (ct_rc == CXMOD_ENOFILE) {
        cxmod_info("nf_conntrack not loaded — skipping");
    } else {
        rc = conntrack_fix(dry_run);
        step_done(rc == CXMOD_OK || rc == CXMOD_ENOFILE);
        if (rc != CXMOD_OK && rc != CXMOD_ENOFILE) errs++;
    }

    /* ── Step 3: IRQ balance ───────────────────────────────────────────────── */
    step(++step_num, NSTEPS, "Balance NIC IRQs across CPUs");
    int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 2) {
        cxmod_info("Single-CPU system — IRQ balance not needed");
    } else {
        rc = irq_balance(NULL, dry_run);
        step_done(rc == CXMOD_OK);
        if (rc != CXMOD_OK) errs++;
    }

    /* ── Step 4: RPS/XPS ──────────────────────────────────────────────────── */
    step(++step_num, NSTEPS, "Enable RPS/XPS receive packet steering");
    if (ncpus < 2) {
        cxmod_info("Single-CPU system — RPS not useful");
    } else {
        rc = irq_set_rps(NULL, dry_run);
        step_done(rc == CXMOD_OK);
        if (rc != CXMOD_OK) errs++;
    }

    /* ── Step 5: Disable LRO ──────────────────────────────────────────────── */
    step(++step_num, NSTEPS, "Disable LRO on all interfaces (if ethtool available)");
    char ethtool_path[CXMOD_PATH_MAX];
    if (find_tool("ethtool", ethtool_path, sizeof(ethtool_path)) == CXMOD_OK) {
        rc = offload_fix_lro(NULL, dry_run);
        step_done(rc == CXMOD_OK);
        if (rc != CXMOD_OK) errs++;
    } else {
        cxmod_info("ethtool not found — skipping LRO fix");
        cxmod_info("Install ethtool: apt-get install ethtool  or  yum install ethtool");
    }

    /* ── Step 6: Persist settings ─────────────────────────────────────────── */
    step(++step_num, NSTEPS,
         "Persist settings to /etc/sysctl.d/90-cxmod.conf (survives reboots)");
    if (dry_run) {
        printf("  [DRY-RUN] Would write /etc/sysctl.d/90-cxmod.conf\n");
    } else {
        rc = persist_write(PROFILE_BALANCED, NULL);
        step_done(rc == CXMOD_OK);
        if (rc != CXMOD_OK) errs++;
    }

    /* ── Summary ──────────────────────────────────────────────────────────── */
    printf("\n");
    if (cxmod_color) printf(COL_BOLD);

    if (errs == 0) {
        if (cxmod_color) printf(COL_GREEN);
        if (dry_run)
            printf("  DRY-RUN complete. Re-run without --dry-run to apply.\n");
        else
            printf("  All %d steps completed successfully.\n", NSTEPS);
    } else {
        if (cxmod_color) printf(COL_YELLOW);
        printf("  Completed with %d error(s). Review warnings above.\n", errs);
    }
    if (cxmod_color) printf(COL_RESET);

    if (!dry_run && errs == 0) {
        printf("\n  Next steps:\n");
        printf("    sudo cx diagnose          # verify all issues resolved\n");
        printf("    sudo cx monitor           # watch live traffic\n");
        printf("    sudo cx persist --show    # view saved configuration\n");
    }

    return errs ? CXMOD_ERR : CXMOD_OK;
}
