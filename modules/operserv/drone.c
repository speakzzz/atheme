/*
 * SPDX-License-Identifier: ISC
 *
 * modules/operserv/drone.c
 * Persistent Dronescan module for Atheme.
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
 */

#include "atheme.h"
#include <sys/types.h>
#include <regex.h>
#include <ctype.h> /* For isdigit */

#define DRONE_DB_FILE "etc/drone.db"

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

/* Fallback definition for SRA check if implicit */
#ifndef is_sra
 #ifdef MU_SRA
  #define is_sra(u) ((u) && ((u)->flags & MU_SRA))
 #else
  #define is_sra(u) (has_priv(si, PRIV_USER_ADMIN))
 #endif
#endif

/* Local Command Table */
static mowgli_patricia_t *drone_cmds = NULL;

/* List of Drones */
static mowgli_list_t drone_list;

/* Structure */
struct drone_entry {
    char *mask;
    char *reason;
    char *setter;
    time_t set_time;
    unsigned int hits;
    regex_t *regex; /* Standard POSIX Regex Object */
    mowgli_node_t node;
};

/* --------------------------------------------------------------------- */
/* Helper Functions */
/* --------------------------------------------------------------------- */

static void
add_drone(const char *mask, const char *reason, const char *setter, time_t t, unsigned int hits)
{
    struct drone_entry *d = mowgli_alloc(sizeof(struct drone_entry));
    d->mask = sstrdup(mask);
    d->reason = sstrdup(reason);
    d->setter = sstrdup(setter);
    d->set_time = t;
    d->hits = hits;
    d->regex = NULL;

    /* Detect Regex: Must start with / */
    if (mask[0] == '/')
    {
        /* Remove the leading '/' for compilation. */
        char *pattern = sstrdup(mask + 1);
        /* If last char is /, remove it */
        size_t len = strlen(pattern);
        if (len > 0 && pattern[len - 1] == '/') {
            pattern[len - 1] = '\0';
        }

        d->regex = mowgli_alloc(sizeof(regex_t));
        /* Compile Extended Regex, Case Insensitive */
        if (regcomp(d->regex, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0)
        {
            slog(LG_INFO, "DRONE: Failed to compile regex for mask: %s", mask);
            free(d->regex);
            d->regex = NULL;
        }
        free(pattern);
    }

    mowgli_node_add(d, &d->node, &drone_list);
}

static struct drone_entry *
find_drone(const char *mask)
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

/* Matching Logic: Handles both Regex and Glob */
static struct drone_entry *
match_drone(const char *user_string)
{
    mowgli_node_t *n;
    if (!user_string) return NULL;

    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;

        if (d->regex)
        {
            /* POSIX Regex Match */
            if (regexec(d->regex, user_string, 0, NULL, 0) == 0)
                return d;
        }
        else
        {
            /* Standard Wildcard Match */
            if (!match(d->mask, user_string))
                return d;
        }
    }
    return NULL;
}

/* Check if string is a number */
static bool
is_numeric_string(const char *str)
{
    if (!str || !*str) return false;
    while (*str)
    {
        if (!isdigit((unsigned char)*str)) return false;
        str++;
    }
    return true;
}

/* --------------------------------------------------------------------- */
/* Persistence Functions (Flatfile) */
/* --------------------------------------------------------------------- */

static void
save_drone_db(void)
{
    FILE *f = fopen(DRONE_DB_FILE, "w");
    mowgli_node_t *n;

    if (!f)
    {
        slog(LG_ERROR, "DRONE: Could not open %s for writing: %s", DRONE_DB_FILE, strerror(errno));
        return;
    }

    /* Format: D <Mask> <Time> <Setter> <Hits> <Reason> */
    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        fprintf(f, "D %s %ld %s %u %s\n", d->mask, (long)d->set_time, d->setter, d->hits, d->reason);
    }

    fclose(f);
}

static void
load_drone_db(void)
{
    FILE *f = fopen(DRONE_DB_FILE, "r");
    char line[BUFSIZE];
    char *type, *p1, *p2, *p3, *p4, *p5;

    if (!f) return;

    while (fgets(line, sizeof(line), f))
    {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;

        type = strtok(line, " ");
        if (!type) continue;

        if (!strcasecmp(type, "D"))
        {
            p1 = strtok(NULL, " "); /* Mask */
            p2 = strtok(NULL, " "); /* Time */
            p3 = strtok(NULL, " "); /* Setter */
            p4 = strtok(NULL, " "); /* Hits */
            p5 = strtok(NULL, "");  /* Reason (Rest of line) */
            
            if (p1 && p2 && p3 && p4 && p5) 
            {
                add_drone(p1, p5, p3, (time_t)atol(p2), (unsigned int)atoi(p4));
            }
        }
    }
    fclose(f);
    slog(LG_INFO, "DRONE: Database loaded from %s", DRONE_DB_FILE);
}

/* --------------------------------------------------------------------- */
/* Core Check Logic */
/* --------------------------------------------------------------------- */

static void
enforce_drone(struct user *u, struct drone_entry *d)
{
    struct service *oserv = service_find("operserv");
    if (!oserv || !u || !d) return;

    /* Increment Hits */
    d->hits++;
    save_drone_db(); /* Save hits immediately */

    /* Clean reason format */
    char reason[BUFSIZE];
    snprintf(reason, sizeof(reason), "Blacklisted: %s", d->reason);

    slog(LG_INFO, "DRONE: Klining user %s (%s) -> Matched blacklist: %s", u->nick, u->ip, d->mask);
    
    /* Place K-Line only (IRCd handles disconnect) */
    kline_add("*", u->ip, reason, 86400, oserv->nick);
}

static void
check_user_hook(void *data)
{
    struct user **u_ptr = (struct user **)data;
    struct user *u;

    if (!u_ptr) return;
    u = *u_ptr;

    /* Ignore Internal Clients */
    if (!u || is_internal_client(u)) return;
    
    /* SAFETY: Ignore Registered Users and IRCops */
    if (u->myuser || is_ircop(u)) return;

    struct drone_entry *hit = NULL;

    /* 1. Check Nickname */
    if (!hit) hit = match_drone(u->nick);

    /* 2. Check Ident (User) */
    if (!hit && u->user) hit = match_drone(u->user);

    /* 3. Check IP (if present) */
    if (!hit && u->ip) hit = match_drone(u->ip);
    
    /* 4. Check Hostname (if present) */
    if (!hit && u->host) hit = match_drone(u->host);

    if (hit)
    {
        enforce_drone(u, hit);
    }
}

/* --------------------------------------------------------------------- */
/* Commands */
/* --------------------------------------------------------------------- */

static void
cmd_drone_add(struct sourceinfo *si, int parc, char *parv[])
{
    char *target = parv[0];
    char *reason = parv[1];

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!target || !reason)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE ADD");
        command_fail(si, fault_needmoreparams, _("Usage: DRONE ADD <IP/Mask/Regex> <Reason>"));
        return;
    }

    if (find_drone(target))
    {
        command_fail(si, fault_nochange, "Mask \2%s\2 is already in the drone list.", target);
        return;
    }

    add_drone(target, reason, get_storage_oper_name(si), CURRTIME, 0);
    save_drone_db();
    
    command_success_nodata(si, "Added \2%s\2 to the Drone blacklist.", target);
    logcommand(si, CMDLOG_ADMIN, "DRONE:ADD: \2%s\2 (Reason: %s)", target, reason);
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

    if (!target)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE DEL");
        return;
    }

    /* Check if target is a number (ID deletion) */
    if (is_numeric_string(target))
    {
        index_to_del = atoi(target);
    }

    MOWGLI_ITER_FOREACH_SAFE(n, tn, drone_list.head)
    {
        struct drone_entry *d = n->data;
        current_idx++;

        /* Check for ID match OR String Match */
        if (current_idx == index_to_del || !strcasecmp(d->mask, target))
        {
            mowgli_node_delete(n, &drone_list);
            if (d->regex) {
                regfree(d->regex);
                mowgli_free(d->regex);
            }
            
            command_success_nodata(si, "Removed \2%s\2 (ID: %d) from the Drone blacklist.", d->mask, current_idx);
            logcommand(si, CMDLOG_ADMIN, "DRONE:DEL: \2%s\2 (ID: %d)", d->mask, current_idx);

            free(d->mask);
            free(d->reason);
            free(d->setter);
            mowgli_free(d);
            save_drone_db();
            
            return;
        }
    }
    
    if (index_to_del > 0)
        command_fail(si, fault_nosuch_target, "Drone ID \2%d\2 not found.", index_to_del);
    else
        command_fail(si, fault_nosuch_target, "Mask \2%s\2 not found in drone list.", target);
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
        command_success_nodata(si, "%d: \2%s\2 (Hits: %u) (Set by: %s on %s) Reason: %s", 
            ++count, d->mask, d->hits, d->setter, buf, d->reason);
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

    mowgli_patricia_iteration_state_t state;
    struct user *u;
    mowgli_list_t victim_list = { NULL, NULL, 0 };
    mowgli_node_t *n, *tn;
    int scanned = 0;

    logcommand(si, CMDLOG_ADMIN, "DRONE:SCAN");
    command_success_nodata(si, "Scanning users against Drone blacklist...");

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        if (is_internal_client(u) || u->myuser) continue;
        scanned++;

        /* Check Nick */
        if (match_drone(u->nick)) {
            mowgli_node_add(u, mowgli_node_create(), &victim_list);
            continue;
        }
        /* Check Ident */
        if (match_drone(u->user)) {
            mowgli_node_add(u, mowgli_node_create(), &victim_list);
            continue;
        }
        /* Check IP */
        if (u->ip && match_drone(u->ip)) {
            mowgli_node_add(u, mowgli_node_create(), &victim_list);
            continue;
        }
        /* Check Host */
        if (u->host && match_drone(u->host)) {
            mowgli_node_add(u, mowgli_node_create(), &victim_list);
        }
    }

    int banned_count = 0;
    MOWGLI_ITER_FOREACH_SAFE(n, tn, victim_list.head)
    {
        u = (struct user *)n->data;
        if (user_find(u->nick))
        {
            struct drone_entry *hit = match_drone(u->nick);
            if (!hit) hit = match_drone(u->user);
            if (!hit && u->ip) hit = match_drone(u->ip);
            if (!hit && u->host) hit = match_drone(u->host);

            if (hit)
            {
                enforce_drone(u, hit);
                banned_count++;
            }
        }
        mowgli_node_delete(n, &victim_list);
        mowgli_node_free(n);
    }

    command_success_nodata(si, "Drone Scan complete. Scanned: %d. Banned: %d.", scanned, banned_count);
}

/* Dispatch function */
static void
cmd_drone_dispatch(struct sourceinfo *si, int parc, char *parv[])
{
    if (parc < 1)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE");
        command_fail(si, fault_needmoreparams, _("Available commands: ADD, DEL, LIST, SCAN"));
        command_fail(si, fault_needmoreparams, _("Type \2/msg OperServ HELP DRONE <command>\2 for more information."));
        return;
    }
    
    subcommand_dispatch_simple(si->service, si, parc, parv, drone_cmds, "DRONE");
}

/* --------------------------------------------------------------------- */
/* Module Init & Deinit */
/* --------------------------------------------------------------------- */

static struct command cmd_drone_add_rec = {
    .name = "ADD",
    .desc = "Add an IP or mask to the drone blacklist.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 2,
    .cmd = &cmd_drone_add,
    .help = { .path = "oservice/drone_add" }
};

static struct command cmd_drone_del_rec = {
    .name = "DEL",
    .desc = "Remove an IP or mask from the drone blacklist.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 1,
    .cmd = &cmd_drone_del,
    .help = { .path = "oservice/drone_del" }
};

static struct command cmd_drone_list_rec = {
    .name = "LIST",
    .desc = "List all blacklisted drones.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 0,
    .cmd = &cmd_drone_list,
    .help = { .path = "oservice/drone_list" }
};

static struct command cmd_drone_scan_rec = {
    .name = "SCAN",
    .desc = "Scan online users against drone list.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 0,
    .cmd = &cmd_drone_scan,
    .help = { .path = "oservice/drone_scan" }
};

static struct command cmd_drone = {
    .name = "DRONE",
    .desc = "Manage local IP blacklist.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 3,
    .cmd = &cmd_drone_dispatch,
    .help = { .path = "oservice/drone" }
};

void
mod_init(struct module *const restrict m)
{
    struct service *oserv = service_find("operserv");

    if (!oserv)
    {
        slog(LG_ERROR, "DRONE: OperServ service not found!");
        m->mflags = MODFLAG_FAIL;
        return;
    }

    drone_cmds = mowgli_patricia_create(strcasecanon);

    command_add(&cmd_drone_add_rec, drone_cmds);
    command_add(&cmd_drone_del_rec, drone_cmds);
    command_add(&cmd_drone_list_rec, drone_cmds);
    command_add(&cmd_drone_scan_rec, drone_cmds);

    command_add(&cmd_drone, oserv->commands);

    hook_add_hook("user_add", (void (*)(void *))check_user_hook);

    load_drone_db();

    slog(LG_INFO, "DRONE: Module loaded successfully.");
}

void
mod_deinit(const enum module_unload_intent intent)
{
    struct service *oserv = service_find("operserv");

    hook_del_hook("user_add", (void (*)(void *))check_user_hook);

    command_delete(&cmd_drone_add_rec, drone_cmds);
    command_delete(&cmd_drone_del_rec, drone_cmds);
    command_delete(&cmd_drone_list_rec, drone_cmds);
    command_delete(&cmd_drone_scan_rec, drone_cmds);

    if (oserv)
        command_delete(&cmd_drone, oserv->commands);

    mowgli_patricia_destroy(drone_cmds, NULL, NULL);

    /* Clean list */
    mowgli_node_t *n, *tn;
    MOWGLI_ITER_FOREACH_SAFE(n, tn, drone_list.head)
    {
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
