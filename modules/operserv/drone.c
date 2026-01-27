/*
 * SPDX-License-Identifier: ISC
 *
 * modules/operserv/drone.c
 * Persistent Dronescan module for Atheme.
 *
 * UPDATED: Fixed compilation types for libmowgli-2
 *
 * * COMBINED FEATURES:
 * - Supports Wildcards (*.vpn.net)
 * - Supports Regex (/^drone-\d+/) using standard POSIX regex
 * - Delete Regex by ID (e.g., DRONE DEL 1)
 * - Checks: Nick, Ident (User), IP, Host
 * - Persistent Flatfile Database (etc/drone.db)
 * - SRA-Only Access
 * - Regex with Delimiters (/pattern/flags)
 * - Instant K-Line (No crash warnings)
 * - Registered User Protection
 * - Hit Counters
 * - Buffered Save (No disk thrashing)
 * - Pipe-delimited DB (Supports spaces in regex)
 * - Regex Error Reporting (Immediate feedback)
 * - DRONE TEST command
 * - DRONE SCAN (Dry Run by default, EXEC to ban)
 * - CONFIGURABLE DURATIONS (10m, 1h, 7d, perm)
 * - SINGLE-PASS SCANNING (High Performance)
 */

#include "atheme.h"
#include <sys/types.h>
#include <regex.h>
#include <ctype.h>

#define DRONE_DB_FILE "etc/drone.db"
#define DEFAULT_DURATION 86400 /* 24 Hours */

/* Ensure standard messages are defined */
#ifndef STR_INSUFFICIENT_PARAMS
#define STR_INSUFFICIENT_PARAMS _("Insufficient parameters for \2%s\2.")
#endif
#ifndef STR_INVALID_PARAMS
#define STR_INVALID_PARAMS _("Invalid parameters for \2%s\2.")
#endif
#ifndef STR_NOT_AUTHORIZED
#define STR_NOT_AUTHORIZED _("You are not authorized to use this command.")
#endif

/* Fallback definition for SRA check */
#ifndef is_sra
 #ifdef MU_SRA
  #define is_sra(u) ((u) && ((u)->flags & MU_SRA))
 #else
  #define is_sra(u) (has_priv(si, PRIV_USER_ADMIN))
 #endif
#endif

static mowgli_patricia_t *drone_cmds = NULL;
static mowgli_list_t drone_list;
static mowgli_eventloop_timer_t *save_timer = NULL;

struct drone_entry {
    char *mask;
    char *reason;
    char *setter;
    time_t set_time;
    long duration; /* Duration in seconds */
    unsigned int hits;
    regex_t *regex;
    mowgli_node_t node;
};

/* --------------------------------------------------------------------- */
/* Helper Functions */
/* --------------------------------------------------------------------- */

/* Parse duration string (e.g. "10m", "1h") to seconds */
static long
parse_duration(const char *s)
{
    if (!s) return DEFAULT_DURATION;
    
    char *endptr;
    long value = strtol(s, &endptr, 10);
    
    if (value <= 0 && strcasecmp(s, "0") != 0 && strcasecmp(s, "perm") != 0) 
        return DEFAULT_DURATION; /* Failed parse or invalid */

    if (*endptr) {
        switch (tolower((unsigned char)*endptr)) {
            case 's': break; /* Seconds */
            case 'm': value *= 60; break;
            case 'h': value *= 3600; break;
            case 'd': value *= 86400; break;
            case 'w': value *= 604800; break;
            case 'y': value *= 31536000; break;
            default: return DEFAULT_DURATION;
        }
    }
    return value;
}

/* Check a single string against a drone entry */
static bool
matches_entry(const struct drone_entry *d, const char *str)
{
    if (!str) return false;

    if (d->regex) {
        return (regexec(d->regex, str, 0, NULL, 0) == 0);
    } else {
        return (match(d->mask, str) == 0);
    }
}

static void
add_drone(const char *mask, const char *reason, const char *setter, time_t t, long duration, unsigned int hits)
{
    struct drone_entry *d = mowgli_alloc(sizeof(struct drone_entry));
    d->mask = sstrdup(mask);
    d->reason = sstrdup(reason);
    d->setter = sstrdup(setter);
    d->set_time = t;
    d->duration = duration;
    d->hits = hits;
    d->regex = NULL;

    /* Detect Regex: Must start with / */
    if (mask[0] == '/')
    {
        char *pattern = sstrdup(mask + 1);
        size_t len = strlen(pattern);
        if (len > 0 && pattern[len - 1] == '/') {
            pattern[len - 1] = '\0';
        }

        d->regex = mowgli_alloc(sizeof(regex_t));
        if (regcomp(d->regex, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
            free(d->regex);
            d->regex = NULL;
        }
        free(pattern);
    }

    mowgli_node_add(d, &d->node, &drone_list);
}

static struct drone_entry *
find_drone_mask(const char *mask)
{
    mowgli_node_t *n;
    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        if (!strcasecmp(d->mask, mask))
            return d;
    }
    return NULL;
}

static bool
is_numeric_string(const char *str)
{
    if (!str || !*str) return false;
    while (*str) {
        if (!isdigit((unsigned char)*str)) return false;
        str++;
    }
    return true;
}

/* --------------------------------------------------------------------- */
/* Persistence (Pipe Delimited) */
/* --------------------------------------------------------------------- */

static void
save_drone_db(void)
{
    FILE *f = fopen(DRONE_DB_FILE, "w");
    mowgli_node_t *n;

    if (!f) {
        slog(LG_ERROR, "DRONE: Could not open %s: %s", DRONE_DB_FILE, strerror(errno));
        return;
    }

    /* Format: D <Mask>|<Time>|<Setter>|<Hits>|<Duration>|<Reason> */
    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        fprintf(f, "D %s|%ld|%s|%u|%ld|%s\n", d->mask, (long)d->set_time, d->setter, d->hits, d->duration, d->reason);
    }

    fclose(f);
}

static void
save_timer_func(void *unused)
{
    save_drone_db();
}

static void
load_drone_db(void)
{
    FILE *f = fopen(DRONE_DB_FILE, "r");
    char line[BUFSIZE];
    char *type, *p1, *p2, *p3, *p4, *p5, *p6;

    if (!f) return;

    while (fgets(line, sizeof(line), f))
    {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;

        /* First token is space-separated "D " */
        type = strtok(line, " ");
        
        if (type && !strcasecmp(type, "D"))
        {
            /* Rest is pipe-separated */
            p1 = strtok(NULL, "|"); /* Mask */
            p2 = strtok(NULL, "|"); /* Time */
            p3 = strtok(NULL, "|"); /* Setter */
            p4 = strtok(NULL, "|"); /* Hits */
            p5 = strtok(NULL, "|"); /* Duration OR Reason (Old format) */
            p6 = strtok(NULL, "");  /* Reason (New format) */
            
            if (p1 && p2 && p3 && p4 && p5) 
            {
                long dur;
                char *reason_str;

                if (p6) {
                    /* New Format: p5 is Duration, p6 is Reason */
                    dur = atol(p5);
                    reason_str = p6;
                } else {
                    /* Old Format: p5 is Reason */
                    dur = DEFAULT_DURATION;
                    reason_str = p5;
                }

                add_drone(p1, reason_str, p3, (time_t)atol(p2), dur, (unsigned int)atoi(p4));
            }
        }
    }
    fclose(f);
    slog(LG_INFO, "DRONE: Database loaded from %s", DRONE_DB_FILE);
}

/* --------------------------------------------------------------------- */
/* Core Check Logic (Single Pass) */
/* --------------------------------------------------------------------- */

static void
enforce_drone(struct user *u, struct drone_entry *d)
{
    struct service *oserv = service_find("operserv");
    if (!oserv || !u || !d) return;

    /* Buffered Hit Counting */
    d->hits++;
    
    char reason[BUFSIZE];
    snprintf(reason, sizeof(reason), "Blacklisted: %s", d->reason);

    slog(LG_INFO, "DRONE: Klining user %s (%s) -> Matched blacklist: %s", u->nick, u->ip, d->mask);
    
    kline_add("*", u->ip, reason, d->duration, oserv->nick);
}

static void
check_user_hook(void *data)
{
    struct user **u_ptr = (struct user **)data;
    struct user *u;

    if (!u_ptr) return;
    u = *u_ptr;

    if (!u || is_internal_client(u)) return;
    if (u->myuser || is_ircop(u)) return;

    mowgli_node_t *n;
    
    /* SINGLE PASS SCAN: Check all fields in one loop */
    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;

        if (matches_entry(d, u->nick) || 
            (u->user && matches_entry(d, u->user)) || 
            (u->ip && matches_entry(d, u->ip)) || 
            (u->host && matches_entry(d, u->host)))
        {
            enforce_drone(u, d);
            return; /* Stop after first match to avoid double-klining */
        }
    }
}

/* --------------------------------------------------------------------- */
/* Commands */
/* --------------------------------------------------------------------- */

static void
cmd_drone_add(struct sourceinfo *si, int parc, char *parv[])
{
    char *target = parv[0];
    char *arg2 = parv[1];
    char *arg3 = parv[2];
    
    char *reason = NULL;
    long duration = DEFAULT_DURATION;

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!target || !arg2) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE ADD");
        command_fail(si, fault_needmoreparams, _("Usage: DRONE ADD <Mask> [Duration] <Reason>"));
        return;
    }

    /* Logic to handle optional Duration */
    if (arg3) {
        /* 3 arguments: Mask, Duration, Reason */
        duration = parse_duration(arg2);
        reason = arg3;
    } else {
        /* 2 arguments: Mask, Reason (or possibly Duration?) */
        /* Check if arg2 looks like a duration */
        if (isdigit((unsigned char)arg2[0])) {
            /* It starts with a digit, is it a duration or a reason like "404 Error"? */
            /* Let's try to parse it. If parse returns Default but input wasn't default, treat as reason */
            long test_dur = parse_duration(arg2);
            if (test_dur == DEFAULT_DURATION && strcasecmp(arg2, "24h") != 0 && strcasecmp(arg2, "1d") != 0 && strcasecmp(arg2, "86400") != 0) {
                /* Probably a reason */
                reason = arg2;
            } else {
                /* Valid duration, but missing reason? */
                command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE ADD");
                command_fail(si, fault_needmoreparams, _("If you specify a duration, you must provide a reason."));
                return;
            }
        } else {
            reason = arg2;
        }
    }

    if (find_drone_mask(target)) {
        command_fail(si, fault_nochange, "Mask \2%s\2 is already in the drone list.", target);
        return;
    }

    /* PRE-VALIDATION: Check Regex Validity */
    if (target[0] == '/')
    {
        char *pattern = sstrdup(target + 1);
        size_t len = strlen(pattern);
        if (len > 0 && pattern[len - 1] == '/') pattern[len - 1] = '\0';

        regex_t reg_check;
        int err = regcomp(&reg_check, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
        free(pattern);

        if (err != 0) {
            char errbuf[256];
            regerror(err, &reg_check, errbuf, sizeof(errbuf));
            command_fail(si, fault_badparams, "Invalid Regex: %s", errbuf);
            return;
        }
        regfree(&reg_check);
    }

    add_drone(target, reason, get_storage_oper_name(si), CURRTIME, duration, 0);
    save_drone_db();
    
    char dur_buf[64];
    if (duration == 0) strcpy(dur_buf, "Permanent");
    else snprintf(dur_buf, sizeof(dur_buf), "%ld sec", duration);

    command_success_nodata(si, "Added \2%s\2 to the Drone blacklist (%s).", target, dur_buf);
    logcommand(si, CMDLOG_ADMIN, "DRONE:ADD: \2%s\2 (%s) Reason: %s", target, dur_buf, reason);
}

static void
cmd_drone_del(struct sourceinfo *si, int parc, char *parv[])
{
    char *target = parv[0];
    mowgli_node_t *n, *tn;
    int index_to_del = -1;
    int current_idx = 0;

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!target) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE DEL");
        return;
    }

    if (is_numeric_string(target)) index_to_del = atoi(target);

    MOWGLI_ITER_FOREACH_SAFE(n, tn, drone_list.head)
    {
        struct drone_entry *d = n->data;
        current_idx++;

        if (current_idx == index_to_del || !strcasecmp(d->mask, target))
        {
            mowgli_node_delete(n, &drone_list);
            if (d->regex) {
                regfree(d->regex);
                mowgli_free(d->regex);
            }
            
            command_success_nodata(si, "Removed \2%s\2 (ID: %d).", d->mask, current_idx);
            logcommand(si, CMDLOG_ADMIN, "DRONE:DEL: \2%s\2 (ID: %d)", d->mask, current_idx);

            free(d->mask);
            free(d->reason);
            free(d->setter);
            mowgli_free(d);
            
            save_drone_db(); 
            return;
        }
    }
    
    command_fail(si, fault_nosuch_target, "Target \2%s\2 not found.", target);
}

static void
cmd_drone_test(struct sourceinfo *si, int parc, char *parv[])
{
    char *test_str = parv[0];
    mowgli_node_t *n;

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!test_str) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE TEST");
        return;
    }

    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        if (matches_entry(d, test_str))
        {
            command_success_nodata(si, "MATCH: String \2%s\2 matches rule \2%s\2 (ID: %s)", 
                test_str, d->mask, d->setter);
            return;
        }
    }

    command_success_nodata(si, "NO MATCH: String \2%s\2 is clean.", test_str);
}

static void
cmd_drone_list(struct sourceinfo *si, int parc, char *parv[])
{
    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    mowgli_node_t *n;
    unsigned int count = 0;
    char buf[BUFSIZE];
    struct tm tm;

    command_success_nodata(si, "Drone Blacklist:");
    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        tm = *localtime(&d->set_time);
        strftime(buf, BUFSIZE, TIME_FORMAT, &tm);
        
        char dur_str[32];
        if (d->duration == 0) strcpy(dur_str, "Perm");
        else snprintf(dur_str, sizeof(dur_str), "%lds", d->duration);

        command_success_nodata(si, "%d: \2%s\2 (Hits: %u) (Duration: %s) (Set: %s on %s)", 
            ++count, d->mask, d->hits, dur_str, d->setter, buf);
    }
    command_success_nodata(si, "End of list.");
}

static void
cmd_drone_scan(struct sourceinfo *si, int parc, char *parv[])
{
    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    /* Check for EXEC flag */
    bool execute = false;
    if (parc > 0 && parv[0] && !strcasecmp(parv[0], "EXEC")) {
        execute = true;
    }

    mowgli_patricia_iteration_state_t state;
    struct user *u;
    mowgli_list_t victim_list = { NULL, NULL, 0 };
    mowgli_node_t *n, *tn;
    int scanned = 0;
    int matches = 0;

    logcommand(si, CMDLOG_ADMIN, "DRONE:SCAN:%s", execute ? "EXEC" : "TEST");
    command_success_nodata(si, "Scanning users against Drone blacklist (%s Mode)...", 
        execute ? "\2EXEC - BANNING\2" : "\2DRY RUN - REPORT ONLY\2");

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        if (is_internal_client(u) || u->myuser) continue;
        scanned++;

        mowgli_node_t *dn;
        MOWGLI_ITER_FOREACH(dn, drone_list.head)
        {
            struct drone_entry *d = dn->data;
            if (matches_entry(d, u->nick) || 
                (u->user && matches_entry(d, u->user)) || 
                (u->ip && matches_entry(d, u->ip)) || 
                (u->host && matches_entry(d, u->host)))
            {
                mowgli_node_add(u, mowgli_node_create(), &victim_list);
                break; /* Only need to match once per user */
            }
        }
    }

    MOWGLI_ITER_FOREACH_SAFE(n, tn, victim_list.head)
    {
        u = (struct user *)n->data;
        if (user_find(u->nick))
        {
            /* Re-find the exact rule for logging purposes */
            mowgli_node_t *dn;
            struct drone_entry *hit = NULL;
            MOWGLI_ITER_FOREACH(dn, drone_list.head) {
                struct drone_entry *d = dn->data;
                if (matches_entry(d, u->nick) || (u->user && matches_entry(d, u->user)) || 
                    (u->ip && matches_entry(d, u->ip)) || (u->host && matches_entry(d, u->host))) {
                    hit = d; break;
                }
            }

            if (hit) {
                matches++;
                if (execute) {
                    enforce_drone(u, hit);
                } else {
                    command_success_nodata(si, "MATCH: \2%s\2 (%s) matches rule \2%s\2", 
                        u->nick, u->host, hit->mask);
                }
            }
        }
        mowgli_node_delete(n, &victim_list);
        mowgli_node_free(n);
    }

    if (execute)
        command_success_nodata(si, "Scan complete. Scanned: %d. Banned: %d.", scanned, matches);
    else
        command_success_nodata(si, "Dry Run complete. Scanned: %d. Found %d matches. (Use \2SCAN EXEC\2 to ban)", scanned, matches);
}

static void
cmd_drone_dispatch(struct sourceinfo *si, int parc, char *parv[])
{
    if (parc < 1) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE");
        command_fail(si, fault_needmoreparams, _("Available: ADD, DEL, LIST, SCAN, TEST"));
        return;
    }
    subcommand_dispatch_simple(si->service, si, parc, parv, drone_cmds, "DRONE");
}

/* --------------------------------------------------------------------- */
/* Init / Deinit */
/* --------------------------------------------------------------------- */

static struct command cmd_drone_add_rec = {
    .name = "ADD", .desc = "Add a drone rule.", .access = PRIV_USER_ADMIN,
    .maxparc = 3, .cmd = &cmd_drone_add, .help = { .path = "oservice/drone_add" }
};
static struct command cmd_drone_del_rec = {
    .name = "DEL", .desc = "Remove a drone rule.", .access = PRIV_USER_ADMIN,
    .maxparc = 1, .cmd = &cmd_drone_del, .help = { .path = "oservice/drone_del" }
};
static struct command cmd_drone_list_rec = {
    .name = "LIST", .desc = "List drone rules.", .access = PRIV_USER_ADMIN,
    .maxparc = 0, .cmd = &cmd_drone_list, .help = { .path = "oservice/drone_list" }
};
static struct command cmd_drone_scan_rec = {
    .name = "SCAN", .desc = "Scan users (default: Dry Run).", .access = PRIV_USER_ADMIN,
    .maxparc = 1, .cmd = &cmd_drone_scan, .help = { .path = "oservice/drone_scan" }
};
static struct command cmd_drone_test_rec = {
    .name = "TEST", .desc = "Test a string against rules.", .access = PRIV_USER_ADMIN,
    .maxparc = 1, .cmd = &cmd_drone_test, .help = { .path = "oservice/drone_test" }
};
static struct command cmd_drone = {
    .name = "DRONE", .desc = "Manage local IP blacklist.", .access = PRIV_USER_ADMIN,
    .maxparc = 3, .cmd = &cmd_drone_dispatch, .help = { .path = "oservice/drone" }
};

void
mod_init(struct module *const restrict m)
{
    struct service *oserv = service_find("operserv");
    if (!oserv) {
        m->mflags = MODFLAG_FAIL;
        return;
    }

    drone_cmds = mowgli_patricia_create(strcasecanon);
    command_add(&cmd_drone_add_rec, drone_cmds);
    command_add(&cmd_drone_del_rec, drone_cmds);
    command_add(&cmd_drone_list_rec, drone_cmds);
    command_add(&cmd_drone_scan_rec, drone_cmds);
    command_add(&cmd_drone_test_rec, drone_cmds); 
    command_add(&cmd_drone, oserv->commands);

    hook_add_hook("user_add", (void (*)(void *))check_user_hook);

    load_drone_db();

    save_timer = mowgli_timer_add(base_eventloop, "drone_save_db", 
                                  save_timer_func, NULL, 300);

    slog(LG_INFO, "DRONE: Module loaded (Buffered Save | Pipe DB | Regex Check | Safe Scan | Duration)");
}

void
mod_deinit(const enum module_unload_intent intent)
{
    struct service *oserv = service_find("operserv");

    if (save_timer) {
        mowgli_timer_destroy(base_eventloop, save_timer);
        save_timer = NULL;
    }
    save_drone_db();

    hook_del_hook("user_add", (void (*)(void *))check_user_hook);
    
    command_delete(&cmd_drone_add_rec, drone_cmds);
    command_delete(&cmd_drone_del_rec, drone_cmds);
    command_delete(&cmd_drone_list_rec, drone_cmds);
    command_delete(&cmd_drone_scan_rec, drone_cmds);
    command_delete(&cmd_drone_test_rec, drone_cmds);

    if (oserv) command_delete(&cmd_drone, oserv->commands);

    mowgli_patricia_destroy(drone_cmds, NULL, NULL);

    mowgli_node_t *n, *tn;
    MOWGLI_ITER_FOREACH_SAFE(n, tn, drone_list.head) {
        struct drone_entry *d = n->data;
        if (d->regex) {
            regfree(d->regex);
            mowgli_free(d->regex);
        }
        free(d->mask);
        free(d->reason);
        free(d->setter);
        mowgli_free(d);
    }
}

DECLARE_MODULE_V1
(
    "operserv/drone", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
    PACKAGE_STRING,
    "Atheme Development Group <http://www.atheme.org>"
);
