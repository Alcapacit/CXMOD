/*
 * util.c — CXMOD utility helpers
 * sysctl read/write, proc helpers, output formatting
 */

#include "cxmod.h"
#include <stdarg.h>

bool cxmod_verbose = false;
bool cxmod_json    = false;
bool cxmod_dry_run = false;
bool cxmod_color   = true;

/* ── sysctl / /proc helpers ──────────────────────────────────────────────── */

/* Build /proc/sys path from dotted sysctl key */
static void sysctl_to_path(const char *key, char *path, size_t len)
{
    snprintf(path, len, "/proc/sys/%s", key);
    for (char *p = path + 10; *p; p++)
        if (*p == '.') *p = '/';
}

int sysctl_read_str(const char *key, char *buf, size_t len)
{
    char path[CXMOD_PATH_MAX];
    sysctl_to_path(key, path, sizeof(path));
    return proc_read_line(path, buf, len);
}

int sysctl_read_u64(const char *key, uint64_t *val)
{
    char buf[64];
    int rc = sysctl_read_str(key, buf, sizeof(buf));
    if (rc == 0)
        *val = strtoull(buf, NULL, 10);
    return rc;
}

int sysctl_write(const char *key, const char *value)
{
    char path[CXMOD_PATH_MAX];
    sysctl_to_path(key, path, sizeof(path));

    if (cxmod_dry_run) {
        printf("  [DRY-RUN] sysctl -w %s=%s\n", key, value);
        return CXMOD_OK;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) return CXMOD_EPERM;
        if (errno == ENOENT)                   return CXMOD_ENOFILE;
        return CXMOD_ERR;
    }
    ssize_t n = write(fd, value, strlen(value));
    close(fd);
    return (n > 0) ? CXMOD_OK : CXMOD_ERR;
}

int sysctl_write_u64(const char *key, uint64_t value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
    return sysctl_write(key, buf);
}

int proc_read_line(const char *path, char *buf, size_t len)
{
    FILE *f = fopen(path, "r");
    if (!f) return (errno == ENOENT) ? CXMOD_ENOFILE : CXMOD_ERR;
    if (!fgets(buf, (int)len, f)) { fclose(f); return CXMOD_ERR; }
    fclose(f);
    /* strip trailing newline */
    size_t l = strlen(buf);
    if (l > 0 && buf[l-1] == '\n') buf[l-1] = '\0';
    return CXMOD_OK;
}

int proc_read_u64(const char *path, uint64_t *val)
{
    char buf[64];
    int rc = proc_read_line(path, buf, sizeof(buf));
    if (rc == 0) *val = strtoull(buf, NULL, 10);
    return rc;
}

/* ── Permission check ────────────────────────────────────────────────────── */

bool is_root(void) { return geteuid() == 0; }

/* ── Formatted output ────────────────────────────────────────────────────── */

static void vprint_colored(const char *color, const char *prefix,
                           const char *fmt, va_list ap)
{
    if (cxmod_color && color)
        fputs(color, stdout);
    if (prefix)
        fputs(prefix, stdout);
    vfprintf(stdout, fmt, ap);
    if (cxmod_color && color)
        fputs(COL_RESET, stdout);
    putchar('\n');
}

void cxmod_die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs(COL_RED "[FATAL] " COL_RESET, stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

void cxmod_warn(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vprint_colored(COL_YELLOW, "  [WARN]  ", fmt, ap);
    va_end(ap);
}

void cxmod_info(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vprint_colored(COL_CYAN, "  [INFO]  ", fmt, ap);
    va_end(ap);
}

void cxmod_ok(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vprint_colored(COL_GREEN, "  [ OK ]  ", fmt, ap);
    va_end(ap);
}

void cxmod_section(const char *title)
{
    printf("\n");
    if (cxmod_color) printf(COL_BOLD COL_BLUE);
    printf("== %s ", title);
    int w = 60 - (int)strlen(title) - 4;
    for (int i = 0; i < w; i++) putchar('=');
    if (cxmod_color) printf(COL_RESET);
    printf("\n");
}

void print_bar(const char *label, uint64_t val, uint64_t max,
               int width, const char *color)
{
    int fill = (max > 0) ? (int)((uint64_t)width * val / max) : 0;
    if (fill > width) fill = width;
    printf("  %-16s [", label);
    if (cxmod_color && color) printf("%s", color);
    for (int i = 0; i < fill;  i++) putchar('#');
    for (int i = fill; i < width; i++) putchar('-');
    if (cxmod_color && color) printf(COL_RESET);
    printf("] %llu / %llu\n", (unsigned long long)val, (unsigned long long)max);
}

const char *sev_str(cxmod_sev_t s)
{
    switch (s) {
    case SEV_OK:       return "OK";
    case SEV_INFO:     return "INFO";
    case SEV_WARN:     return "WARN";
    case SEV_CRITICAL: return "CRIT";
    default:           return "????";
    }
}

const char *sev_color(cxmod_sev_t s)
{
    switch (s) {
    case SEV_OK:       return COL_GREEN;
    case SEV_INFO:     return COL_CYAN;
    case SEV_WARN:     return COL_YELLOW;
    case SEV_CRITICAL: return COL_RED;
    default:           return COL_RESET;
    }
}

/* ── Diagnostic report ───────────────────────────────────────────────────── */

void report_add(cxmod_report_t *r, cxmod_sev_t sev,
                const char *sub, const char *msg, const char *fix)
{
    if (r->count >= MAX_FINDINGS) return;
    cxmod_finding_t *f = &r->findings[r->count++];
    f->severity = sev;
    strncpy(f->subsystem, sub, sizeof(f->subsystem) - 1);
    strncpy(f->message,   msg, sizeof(f->message) - 1);
    strncpy(f->fix,       fix, sizeof(f->fix) - 1);
    if (sev == SEV_CRITICAL) r->critical++;
    if (sev == SEV_WARN)     r->warnings++;
}

void report_print(const cxmod_report_t *r)
{
    cxmod_section("DIAGNOSTIC SUMMARY");
    for (int i = 0; i < r->count; i++) {
        const cxmod_finding_t *f = &r->findings[i];
        if (cxmod_color) printf("%s", sev_color(f->severity));
        printf("  [%-4s] %-16s %s\n", sev_str(f->severity), f->subsystem, f->message);
        if (cxmod_color) printf(COL_RESET);
        if (f->fix[0]) {
            if (cxmod_color) printf(COL_GRAY);
            printf("           FIX: %s\n", f->fix);
            if (cxmod_color) printf(COL_RESET);
        }
    }
    printf("\n");
    if (cxmod_color) printf(COL_BOLD);
    printf("  Total: %d findings  |  Critical: %d  |  Warnings: %d\n",
           r->count, r->critical, r->warnings);
    if (cxmod_color) printf(COL_RESET);
}
