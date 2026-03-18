/*
 * roam.c — Read-Only Access Mode shell with sudo audit integration
 *
 * Designed to be invoked via:
 *   sudo -u roam /usr/local/sbin/roam
 *
 * Combines Landlock (filesystem read-only enforcement) with
 * CAP_DAC_READ_SEARCH (bypass read permission checks) to create
 * a shell where the user can read any file but write to nothing
 * except explicitly configured exception paths.
 *
 * Requires:
 *   - Linux kernel 5.13+ (Landlock support)
 *   - File capabilities: setcap cap_dac_read_search,cap_setpcap+eip <binary>
 *   - A dedicated system user (default: roam)
 *   - sudo configured for session logging
 *
 * Configuration: /etc/sysconfig/roam
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/landlock.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* --- Constants --- */

#define CONFIG_PATH       "/etc/sysconfig/roam"
#define MAX_WRITABLE      64
#define MAX_LINE          4096
#define DEFAULT_USER      "roam"
#define DEFAULT_WRITABLE  "/dev /proc /sys /run /tmp"

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION 0
#endif

#ifndef CAP_DAC_READ_SEARCH
#define CAP_DAC_READ_SEARCH 2
#endif

#ifndef CAP_SETPCAP
#define CAP_SETPCAP 8
#endif

/* --- Landlock syscall wrappers --- */

static int ll_create_ruleset(const struct landlock_ruleset_attr *attr,
                             size_t size, __u32 flags)
{
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int ll_add_rule(int ruleset_fd, enum landlock_rule_type type,
                       const void *rule_attr, __u32 flags)
{
    return syscall(__NR_landlock_add_rule, ruleset_fd, type, rule_attr, flags);
}

static int ll_restrict_self(int ruleset_fd, __u32 flags)
{
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/* --- Helpers --- */

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static char *strip(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\n' || end[-1] == '\r'))
        end--;
    *end = '\0';
    return s;
}

static char *unquote(char *s)
{
    size_t len = strlen(s);
    if (len >= 2 &&
        ((s[0] == '"' && s[len - 1] == '"') ||
         (s[0] == '\'' && s[len - 1] == '\''))) {
        s[len - 1] = '\0';
        return s + 1;
    }
    return s;
}

static int is_abs_path(const char *s)
{
    return s && s[0] == '/';
}

static char *canonicalize_path(const char *path, const char *what)
{
    if (!is_abs_path(path)) {
        fprintf(stderr, "roam: %s path must be absolute: %s\n", what, path);
        return NULL;
    }
    char *resolved = realpath(path, NULL);
    if (!resolved) {
        fprintf(stderr, "roam: %s path '%s': %s (skipped)\n",
                what, path, strerror(errno));
        return NULL;
    }
    return resolved;
}

/* --- Configuration --- */

struct config {
    char *writable[MAX_WRITABLE];
    int   writable_count;
    char *shell;
    char *user;
};

static void config_add_paths(struct config *cfg, const char *paths)
{
    char *buf = strdup(paths);
    if (!buf)
        return;
    char *tok = strtok(buf, " \t");
    while (tok && cfg->writable_count < MAX_WRITABLE) {
        char *canon = canonicalize_path(tok, "writable");
        if (canon)
            cfg->writable[cfg->writable_count++] = canon;
        tok = strtok(NULL, " \t");
    }
    free(buf);
}

static void config_load(struct config *cfg)
{
    int got_writable = 0;

    cfg->user = strdup(DEFAULT_USER);
    if (!cfg->user)
        die("strdup");
    cfg->shell = NULL;

    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) {
        if (errno == ENOENT) {
            config_add_paths(cfg, DEFAULT_WRITABLE);
            return;
        }
        die("fopen(" CONFIG_PATH ")");
    }

    /* Security: config must be owned by root and not group/world-writable. */
    struct stat st;
    if (fstat(fileno(f), &st) == -1)
        die("fstat(" CONFIG_PATH ")");
    if (st.st_uid != 0) {
        fprintf(stderr, "roam: %s must be owned by root\n", CONFIG_PATH);
        exit(EXIT_FAILURE);
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        fprintf(stderr, "roam: %s must not be group/world-writable\n",
                CONFIG_PATH);
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        char *s = strip(line);
        if (*s == '\0' || *s == '#')
            continue;

        char *eq = strchr(s, '=');
        if (!eq)
            continue;
        *eq = '\0';

        char *key = strip(s);
        char *val = unquote(strip(eq + 1));

        if (strcmp(key, "ROAM_WRITABLE") == 0) {
            got_writable = 1;
            config_add_paths(cfg, val);
        } else if (strcmp(key, "ROAM_SHELL") == 0) {
            free(cfg->shell);
            cfg->shell = canonicalize_path(val, "shell");
        } else if (strcmp(key, "ROAM_USER") == 0) {
            free(cfg->user);
            cfg->user = strdup(val);
            if (!cfg->user)
                die("strdup");
        }
    }
    fclose(f);

    if (!got_writable)
        config_add_paths(cfg, DEFAULT_WRITABLE);
}

static void config_free(struct config *cfg)
{
    for (int i = 0; i < cfg->writable_count; i++)
        free(cfg->writable[i]);
    free(cfg->shell);
    free(cfg->user);
}

/* --- Capability helpers (raw syscalls, no libcap dependency) --- */

static int cap_in_effective(int cap)
{
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}, {0}};

    if (syscall(__NR_capget, &hdr, data) == -1)
        return 0;

    return !!(data[cap / 32].effective & (1U << (cap % 32)));
}

static int cap_set_epi(__u32 eff0, __u32 eff1,
                       __u32 prm0, __u32 prm1,
                       __u32 inh0, __u32 inh1)
{
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {
        { .effective = eff0, .permitted = prm0, .inheritable = inh0 },
        { .effective = eff1, .permitted = prm1, .inheritable = inh1 },
    };
    return syscall(__NR_capset, &hdr, data);
}

/* --- Main --- */

int main(int argc, char *argv[])
{
    struct config cfg = {0};
    int abi, ruleset_fd, err;

    /* ================================================================
     * PHASE 1: Configuration and validation
     * ================================================================ */

    config_load(&cfg);

    /* Verify we have CAP_DAC_READ_SEARCH (from file caps on this binary). */
    if (!cap_in_effective(CAP_DAC_READ_SEARCH)) {
        fprintf(stderr,
            "roam: CAP_DAC_READ_SEARCH not available.\n"
            "Ensure file capabilities are set on this binary:\n"
            "  sudo setcap cap_dac_read_search,cap_setpcap+eip %s\n",
            argv[0]);
        config_free(&cfg);
        return EXIT_FAILURE;
    }

    /* Verify we're running as the expected user (via sudo -u). */
    struct passwd *pw = getpwnam(cfg.user);
    if (!pw) {
        fprintf(stderr, "roam: user '%s' not found\n", cfg.user);
        config_free(&cfg);
        return EXIT_FAILURE;
    }
    if (getuid() != pw->pw_uid) {
        fprintf(stderr,
            "roam: must run as '%s' (uid %u), got uid %u\n"
            "Usage: sudo -u %s %s [command...]\n",
            cfg.user, pw->pw_uid, getuid(), cfg.user, argv[0]);
        config_free(&cfg);
        return EXIT_FAILURE;
    }

    /* Always add the user's home as a writable exception. */
    if (pw->pw_dir && pw->pw_dir[0] != '\0' &&
        cfg.writable_count < MAX_WRITABLE) {
        char *home = canonicalize_path(pw->pw_dir, "home");
        if (home)
            cfg.writable[cfg.writable_count++] = home;
    }

    /* ================================================================
     * PHASE 2: Capability setup
     *
     * Goal: make CAP_DAC_READ_SEARCH survive through exec() into
     * bash and all child processes via the ambient capability set.
     *
     * Ordering is critical:
     *   1. Add to inheritable set (required for ambient raise)
     *   2. Raise as ambient
     *   3. Clear bounding set (defense-in-depth)
     *   4. Drop CAP_SETPCAP from our own sets
     *
     * All of this MUST happen BEFORE PR_SET_NO_NEW_PRIVS, because
     * some kernels block PR_CAP_AMBIENT_RAISE after no_new_privs.
     * ================================================================ */

    __u32 dac_bit     = 1U << (CAP_DAC_READ_SEARCH % 32);
    __u32 setpcap_bit = 1U << (CAP_SETPCAP % 32);

    /* 2a. Set cap sets: keep DAC_READ_SEARCH + SETPCAP in E/P,
     *     add DAC_READ_SEARCH to inheritable. */
    if (cap_set_epi(
            dac_bit | setpcap_bit, 0,   /* effective  */
            dac_bit | setpcap_bit, 0,   /* permitted  */
            dac_bit, 0                  /* inheritable */
        ) == -1)
        die("capset (add inheritable)");

    /* 2b. Raise CAP_DAC_READ_SEARCH as ambient.
     *     Requires cap in both permitted and inheritable (done above). */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
              CAP_DAC_READ_SEARCH, 0, 0) == -1)
        die("prctl(PR_CAP_AMBIENT_RAISE)");

    /* 2c. Clear bounding set except CAP_DAC_READ_SEARCH.
     *     Requires CAP_SETPCAP (which we have from file caps).
     *     Non-fatal if SETPCAP is missing — defense-in-depth only. */
    if (cap_in_effective(CAP_SETPCAP)) {
        for (int c = 0; c < 64; c++) {
            if (c == CAP_DAC_READ_SEARCH)
                continue;
            if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) == -1) {
                if (errno == EINVAL)
                    break;  /* past last known capability */
            }
        }
    }

    /* 2d. Drop CAP_SETPCAP — only keep DAC_READ_SEARCH going forward. */
    if (cap_set_epi(
            dac_bit, 0,   /* effective  */
            dac_bit, 0,   /* permitted  */
            dac_bit, 0    /* inheritable */
        ) == -1)
        die("capset (drop setpcap)");

    /* ================================================================
     * PHASE 3: Landlock setup
     *
     * Create a read-only-everywhere ruleset with writable exceptions
     * for configured paths and the user's home directory.
     * ================================================================ */

    /* 3a. Detect Landlock ABI version. */
    abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi == -1) {
        if (errno == ENOSYS || errno == EOPNOTSUPP)
            fprintf(stderr, "roam: Landlock not supported by this kernel "
                    "(need 5.13+)\n");
        else
            perror("landlock_create_ruleset (version query)");
        config_free(&cfg);
        return EXIT_FAILURE;
    }
    if (abi < 1) {
        config_free(&cfg);
        return EXIT_FAILURE;
    }
    if (abi > 5)
        abi = 5;

    /* ABI compatibility mask, from landlock(7). */
    static const __u64 abi_mask[] = {
        (LANDLOCK_ACCESS_FS_MAKE_SYM   << 1) - 1,  /* v1 */
        (LANDLOCK_ACCESS_FS_REFER      << 1) - 1,  /* v2 */
        (LANDLOCK_ACCESS_FS_TRUNCATE   << 1) - 1,  /* v3 */
        (LANDLOCK_ACCESS_FS_TRUNCATE   << 1) - 1,  /* v4 (TCP, no new FS) */
        (LANDLOCK_ACCESS_FS_IOCTL_DEV  << 1) - 1,  /* v5 */
    };

    /* 3b. Declare all filesystem rights we handle. */
    struct landlock_ruleset_attr ruleset_attr = {0};
    ruleset_attr.handled_access_fs =
        (LANDLOCK_ACCESS_FS_EXECUTE |
         LANDLOCK_ACCESS_FS_WRITE_FILE |
         LANDLOCK_ACCESS_FS_READ_FILE |
         LANDLOCK_ACCESS_FS_READ_DIR |
         LANDLOCK_ACCESS_FS_REMOVE_DIR |
         LANDLOCK_ACCESS_FS_REMOVE_FILE |
         LANDLOCK_ACCESS_FS_MAKE_CHAR |
         LANDLOCK_ACCESS_FS_MAKE_DIR |
         LANDLOCK_ACCESS_FS_MAKE_REG |
         LANDLOCK_ACCESS_FS_MAKE_SOCK |
         LANDLOCK_ACCESS_FS_MAKE_FIFO |
         LANDLOCK_ACCESS_FS_MAKE_BLOCK |
         LANDLOCK_ACCESS_FS_MAKE_SYM |
         LANDLOCK_ACCESS_FS_REFER |
         LANDLOCK_ACCESS_FS_TRUNCATE |
         LANDLOCK_ACCESS_FS_IOCTL_DEV) & abi_mask[abi - 1];

    /* Read-only access mask (applied globally to /). */
    __u64 ro_access =
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR;

    /* Full access mask for DIRECTORY exceptions — grant every handled right.
     * File-specific rights (e.g. IOCTL_DEV) propagate to files beneath. */
    __u64 rw_dir_access = ruleset_attr.handled_access_fs;

    /* Write access mask for FILE exceptions (e.g. /dev/null, /dev/tty).
     * Landlock rejects directory-only rights on file fds, so intersect
     * with only file-compatible rights.  ABI masking is already applied
     * to handled_access_fs, so version checks are implicit. */
    static const __u64 file_compat =
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_TRUNCATE |
        LANDLOCK_ACCESS_FS_IOCTL_DEV;
    __u64 rw_file_access = ruleset_attr.handled_access_fs & file_compat;

    /* 3c. Create the ruleset. */
    ruleset_fd = ll_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd == -1)
        die("landlock_create_ruleset");

    /* 3d. Global read/execute under "/". */
    struct landlock_path_beneath_attr pb = {0};
    int fd = open("/", O_PATH | O_CLOEXEC);
    if (fd == -1)
        die("open(\"/\")");
    pb.parent_fd = fd;
    pb.allowed_access = ro_access;
    err = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    close(fd);
    if (err)
        die("landlock_add_rule (/)");

    /* 3e. Writable exceptions from config + user home.
     *     For each path, stat to determine file vs directory and
     *     use the appropriate access mask — Landlock rejects
     *     directory-only rights (MAKE_*, REMOVE_*, READ_DIR) on
     *     non-directory fds. */
    for (int i = 0; i < cfg.writable_count; i++) {
        fd = open(cfg.writable[i], O_PATH | O_CLOEXEC);
        if (fd == -1) {
            fprintf(stderr, "roam: note: writable path '%s': %s "
                    "(skipped)\n", cfg.writable[i], strerror(errno));
            continue;
        }
        struct stat path_st;
        if (fstat(fd, &path_st) == -1) {
            fprintf(stderr, "roam: note: stat '%s': %s (skipped)\n",
                    cfg.writable[i], strerror(errno));
            close(fd);
            continue;
        }
        pb.parent_fd = fd;
        pb.allowed_access = S_ISDIR(path_st.st_mode)
                          ? rw_dir_access
                          : rw_file_access;
        err = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
        close(fd);
        if (err)
            fprintf(stderr, "roam: note: landlock rule '%s': %s "
                    "(skipped)\n", cfg.writable[i], strerror(errno));
    }

    /* ================================================================
     * PHASE 4: Lock down
     * ================================================================ */

    /* Prevent privilege escalation via setuid/setgid binaries.
     * Also required by landlock_restrict_self(). */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        die("prctl(PR_SET_NO_NEW_PRIVS)");

    /* Enforce the Landlock ruleset on this process and all descendants. */
    if (ll_restrict_self(ruleset_fd, 0))
        die("landlock_restrict_self");
    close(ruleset_fd);

    /* ================================================================
     * PHASE 5: Exec shell
     *
     * At this point:
     *   - Effective/Permitted/Inheritable: {CAP_DAC_READ_SEARCH}
     *   - Ambient: {CAP_DAC_READ_SEARCH}
     *   - Bounding set: {CAP_DAC_READ_SEARCH}
     *   - Landlock: read-only everywhere except configured paths
     *   - no_new_privs: set
     *
     * After exec, bash inherits CAP_DAC_READ_SEARCH via ambient caps.
     * All child processes (cat, less, grep, ...) also inherit it.
     * ================================================================ */

    /* Determine shell: config > /bin/bash. */
    const char *shell = cfg.shell;
    if (!shell || shell[0] == '\0')
        shell = "/bin/bash";

    /* Ensure HOME and SHELL are set correctly.
     * sudo sets SHELL to the target user's login shell (/sbin/nologin),
     * which breaks tools that invoke $SHELL (e.g. less via LESSOPEN). */
    if (pw->pw_dir)
        setenv("HOME", pw->pw_dir, 1);
    setenv("SHELL", shell, 1);
    setenv("ROAM", "1", 1);

    fprintf(stderr,
        "roam: Read-Only Access Mode active (user: %s, Landlock ABI v%d)\n"
        "  CAP_DAC_READ_SEARCH: can read all files\n"
        "  Writable exceptions:",
        cfg.user, abi);
    for (int i = 0; i < cfg.writable_count; i++)
        fprintf(stderr, " %s", cfg.writable[i]);
    fprintf(stderr, "\n  Type 'exit' to return.\n");

    /* Use the "-shellname" argv[0] convention to start a login shell. */
    const char *base = strrchr(shell, '/');
    base = base ? base + 1 : shell;
    char login_argv0[256];
    snprintf(login_argv0, sizeof(login_argv0), "-%s", base);

    config_free(&cfg);

    if (argc > 1) {
        /* Run a specific command instead of interactive shell. */
        execvp(argv[1], &argv[1]);
        die("execvp");
    } else {
        execl(shell, login_argv0, (char *)NULL);
        die("execl");
    }

    return EXIT_SUCCESS;  /* unreachable */
}
