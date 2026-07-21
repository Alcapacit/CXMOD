/*
 * monitor.c — Continuous real-time network monitor
 *
 * Samples /proc/net/dev every interval_ms milliseconds and displays
 * per-interface RX/TX rates, error deltas, and connection state counts.
 * Press Ctrl-C to exit.
 */

#include "cxmod.h"
#include <time.h>
#include <signal.h>
#include <string.h>

static volatile bool g_running = true;

static void sig_handler(int sig) { (void)sig; g_running = false; }

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void fmt_rate(uint64_t bps, char *buf, size_t len)
{
    if      (bps >= 1000000000ULL) snprintf(buf, len, "%4.1f Gb/s", bps/1e9);
    else if (bps >= 1000000ULL)    snprintf(buf, len, "%4.1f Mb/s", bps/1e6);
    else if (bps >= 1000ULL)       snprintf(buf, len, "%4.1f kb/s", bps/1e3);
    else                           snprintf(buf, len, "%4llu b/s",  (unsigned long long)bps);
}

int monitor_run(const char *iface_filter, int interval_ms)
{
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    if (interval_ms < 100) interval_ms = 1000;

    cxmod_iface_t prev[CXMOD_MAX_IFS], cur[CXMOD_MAX_IFS];
    int n = iface_list(prev, CXMOD_MAX_IFS);
    uint64_t prev_time = now_ms();

    /* hide cursor */
    printf("\033[?25l");

    while (g_running) {
        sleep_ms(interval_ms);
        if (!g_running) break;

        uint64_t cur_time = now_ms();
        n = iface_list(cur, CXMOD_MAX_IFS);
        double dt_sec = (cur_time - prev_time) / 1000.0;
        if (dt_sec < 0.01) dt_sec = 0.01;

        /* Move cursor to top */
        printf("\033[H\033[2J");

        /* Header */
        if (cxmod_color) printf(COL_BOLD COL_BLUE);
        printf("CXMOD v" CXMOD_VERSION " — Live Network Monitor"
               "   [Ctrl-C to exit]   interval=%dms\n",
               interval_ms);
        if (cxmod_color) printf(COL_RESET);

        char time_str[32];
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
        printf("  %s\n\n", time_str);

        if (cxmod_color) printf(COL_BOLD);
        printf("  %-12s  %-12s  %-12s  %-8s  %-8s  %-8s  %-8s\n",
               "Interface", "RX rate", "TX rate",
               "RX drops", "TX drops", "RX errs", "TX errs");
        if (cxmod_color) printf(COL_RESET);
        printf("  %s\n", "──────────────────────────────────────────────────────────────────────────");

        for (int i = 0; i < n; i++) {
            if (iface_filter && strcmp(cur[i].name, iface_filter) != 0) continue;

            /* Find matching prev */
            int pi = -1;
            for (int j = 0; j < n; j++) {
                if (strcmp(prev[j].name, cur[i].name) == 0) { pi = j; break; }
            }

            if (pi < 0) continue;

            uint64_t rx_delta = cur[i].rx_bytes - prev[pi].rx_bytes;
            uint64_t tx_delta = cur[i].tx_bytes - prev[pi].tx_bytes;
            uint64_t rx_drop_d = cur[i].rx_drop - prev[pi].rx_drop;
            uint64_t tx_drop_d = cur[i].tx_drop - prev[pi].tx_drop;
            uint64_t rx_err_d  = cur[i].rx_errs - prev[pi].rx_errs;
            uint64_t tx_err_d  = cur[i].tx_errs - prev[pi].tx_errs;

            uint64_t rx_bps = (uint64_t)(rx_delta * 8 / dt_sec);
            uint64_t tx_bps = (uint64_t)(tx_delta * 8 / dt_sec);

            char rx_s[16], tx_s[16];
            fmt_rate(rx_bps, rx_s, sizeof(rx_s));
            fmt_rate(tx_bps, tx_s, sizeof(tx_s));

            const char *state_col = cur[i].up ? COL_GREEN : COL_RED;
            printf("  ");
            if (cxmod_color) printf("%s", state_col);
            printf("%-12s", cur[i].name);
            if (cxmod_color) printf(COL_RESET);

            if (cxmod_color) printf(COL_GREEN);
            printf("  %-12s", rx_s);
            if (cxmod_color) printf(COL_RESET);

            if (cxmod_color) printf(COL_BLUE);
            printf("  %-12s", tx_s);
            if (cxmod_color) printf(COL_RESET);

            /* drops/errors in red if non-zero */
            #define PRINT_CNT(val) do { \
                if ((val) > 0 && cxmod_color) printf(COL_RED); \
                printf("  %-8llu", (unsigned long long)(val)); \
                if ((val) > 0 && cxmod_color) printf(COL_RESET); \
            } while(0)

            PRINT_CNT(rx_drop_d);
            PRINT_CNT(tx_drop_d);
            PRINT_CNT(rx_err_d);
            PRINT_CNT(tx_err_d);
            printf("\n");
        }

        /* Connection states */
        printf("\n");
        cxmod_connstates_t cs;
        connstates_read(&cs);
        printf("  TCP States — ESTAB:%-6u LISTEN:%-6u TW:%-6u SYN_RECV:%-6u TOTAL:%-6u\n",
               cs.established, cs.listen, cs.time_wait, cs.syn_recv, cs.total);

        /* conntrack */
        cxmod_conntrack_t ct;
        if (conntrack_read(&ct) == CXMOD_OK && ct.max > 0) {
            const char *ct_col = ct.used_pct >= 80 ? COL_RED :
                                 ct.used_pct >= 60 ? COL_YELLOW : COL_GREEN;
            printf("  conntrack — ");
            if (cxmod_color) printf("%s", ct_col);
            printf("%u/%u (%u%%)", ct.count, ct.max, ct.used_pct);
            if (cxmod_color) printf(COL_RESET);
            printf("\n");
        }

        memcpy(prev, cur, sizeof(cxmod_iface_t) * n);
        prev_time = cur_time;
    }

    /* restore cursor */
    printf("\033[?25h\n");
    cxmod_ok("Monitor stopped");
    return CXMOD_OK;
}
