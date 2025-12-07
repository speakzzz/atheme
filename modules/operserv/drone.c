/*
 * SPDX-License-Identifier: ISC
 *
 * modules/operserv/drone.c
 * Persistent Dronescan module for Atheme.
 * * COMBINED FEATURES:
 * - Database Storage
 * - Regex with Delimiters (/pattern/flags)
 * - AKILLs (Network Bans)
 * - Registered User Protection
 * - Hit Counters
 */

#include <atheme.h>

struct drone_pattern {
    char *pattern;
    char *reason;
    struct atheme_regex *regex;
    mowgli_node_t node;
    unsigned int hits; /* Hit Counter */
};

static mowgli_list_t drone_list;
static mowgli_patricia_t *os_drone_cmds = NULL;

/* Helper: Find a pattern in the list by string */
static struct drone_pattern *
find_drone_pattern(const char *pattern)
{
    mowgli_node_t *n;
    struct drone_pattern *dp;

    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        dp = n->data;
        if (!strcasecmp(dp->pattern, pattern))
            return dp;
    }
    return NULL;
}

/* Helper: Compile a regex string (handling /pattern/flags format) */
static struct atheme_regex *
drone_compile_regex(const char *pattern_str)
{
    char *parse_buf, *p;
    char *extracted;
    int flags = 0;
    struct atheme_regex *regex;

    parse_buf = sstrdup(pattern_str);
    extracted = regex_extract(parse_buf, &p, &flags);

    if (extracted == NULL)
    {
        sfree(parse_buf);
        return regex_create((char *)pattern_str, 0);
    }

    regex = regex_create(extracted, flags);
    sfree(parse_buf);
    
    return regex;
}

/* --------------------------------------------------------------------- */
/* DATABASE HANDLING                                                     */
/* --------------------------------------------------------------------- */

static void
db_h_drone(struct database_handle *db, const char *type)
{
    const char *pattern_const = db_read_str(db);
    const char *reason = db_read_str(db);
    struct drone_pattern *dp;
    struct atheme_regex *regex;
    unsigned int hits = 0;

    /* Read hit count if available */
    if (!db_read_uint(db, &hits))
        hits = 0;

    if (!pattern_const || !reason)
        return;

    regex = drone_compile_regex(pattern_const);
    if (!regex)
    {
        slog(LG_ERROR, "DRONE:DB:LOAD: Invalid regex pattern in database: %s", pattern_const);
        return;
    }

    dp = smalloc(sizeof(struct drone_pattern));
    dp->pattern = sstrdup(pattern_const);
    dp->reason = sstrdup(reason);
    dp->regex = regex;
    dp->hits = hits;

    mowgli_node_add(dp, &dp->node, &drone_list);
}

static void
write_drone_db(struct database_handle *db)
{
    mowgli_node_t *n;
    struct drone_pattern *dp;

    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        dp = n->data;
        db_start_row(db, "DRONE");
        db_write_str(db, dp->pattern);
        db_write_str(db, dp->reason);
        db_write_uint(db, dp->hits); /* Persist Hit Count */
        db_commit_row(db);
    }
}

/* --------------------------------------------------------------------- */
/* COMMANDS                                                              */
/* --------------------------------------------------------------------- */

static void
os_cmd_drone_add(struct sourceinfo *si, int parc, char *parv[])
{
    char *pattern_arg = parv[0];
    char *reason = parv[1];
    struct drone_pattern *dp;
    struct atheme_regex *regex;

    if (!pattern_arg || !reason)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE ADD");
        command_fail(si, fault_needmoreparams, _("Syntax: DRONE ADD <regex> <reason>"));
        return;
    }

    if (find_drone_pattern(pattern_arg))
    {
        command_fail(si, fault_nochange, _("Pattern \2%s\2 already exists."), pattern_arg);
        return;
    }

    regex = drone_compile_regex(pattern_arg);
    
    if (!regex)
    {
        command_fail(si, fault_badparams, _("The provided regex \2%s\2 is invalid. Use format /regex/flags"), pattern_arg);
        return;
    }

    dp = smalloc(sizeof(struct drone_pattern));
    dp->pattern = sstrdup(pattern_arg);
    dp->reason = sstrdup(reason);
    dp->regex = regex;
    dp->hits = 0;

    mowgli_node_add(dp, &dp->node, &drone_list);

    command_success_nodata(si, _("Added \2%s\2 to the drone scan list."), dp->pattern);
    logcommand(si, CMDLOG_ADMIN, "DRONE:ADD: \2%s\2 (Reason: \2%s\2)", dp->pattern, dp->reason);
}

static void
os_cmd_drone_del(struct sourceinfo *si, int parc, char *parv[])
{
    char *pattern = parv[0];
    struct drone_pattern *dp;

    if (!pattern)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE DEL");
        command_fail(si, fault_needmoreparams, _("Syntax: DRONE DEL <regex>"));
        return;
    }

    if (!(dp = find_drone_pattern(pattern)))
    {
        command_fail(si, fault_nosuch_target, _("Pattern \2%s\2 not found."), pattern);
        return;
    }

    mowgli_node_delete(&dp->node, &drone_list);
    regex_destroy(dp->regex);
    sfree(dp->pattern);
    sfree(dp->reason);
    sfree(dp);

    command_success_nodata(si, _("Removed \2%s\2 from the drone scan list."), pattern);
    logcommand(si, CMDLOG_ADMIN, "DRONE:DEL: \2%s\2", pattern);
}

static void
os_cmd_drone_list(struct sourceinfo *si, int parc, char *parv[])
{
    mowgli_node_t *n;
    struct drone_pattern *dp;
    unsigned int i = 1;

    command_success_nodata(si, _("Drone Scan list:"));
    
    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        dp = n->data;
        command_success_nodata(si, _("%d: Pattern: \2%s\2 | Hits: \2%u\2 | Reason: %s"), 
            i++, dp->pattern, dp->hits, dp->reason);
    }
    
    command_success_nodata(si, _("End of list."));
}

/* --------------------------------------------------------------------- */
/* HOOKS                                                                 */
/* --------------------------------------------------------------------- */

static void
hook_user_add(struct hook_user_nick *data)
{
    struct user *u = data->u;
    mowgli_node_t *n;
    struct drone_pattern *dp;
    char usermask[512];
    struct service *operserv;

    if (!u || is_internal_client(u))
        return;

    /* PROTECTION: Ignore users who are already identified to Services */
    if (u->myuser)
        return;

    /* Build: nick!user@host realname */
    snprintf(usermask, sizeof(usermask), "%s!%s@%s %s", u->nick, u->user, u->host, u->gecos);

    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        dp = n->data;
        if (regex_match(dp->regex, usermask))
        {
            /* Count it */
            dp->hits++;

            slog(LG_INFO, "DRONE: Matched user %s against pattern %s", usermask, dp->pattern);
            
            operserv = service_find("operserv");
            
            if (operserv)
            {
                notice(operserv->me->nick, u->nick, "You have been detected as a drone/bad client.");
                notice(operserv->me->nick, u->nick, "Reason: %s", dp->reason);

                /* Send AKILL (1 hour ban) */
                kline_sts("*", u->user, u->host, 3600, dp->reason);

                wallops("DRONE: matched \2%s\2 against \2%s\2 -- banning (1h)", usermask, dp->pattern);
            }
            
            return;
        }
    }
}

/* --------------------------------------------------------------------- */
/* MODULE INIT                                                           */
/* --------------------------------------------------------------------- */

static struct command os_drone_add = {
    .name           = "ADD",
    .desc           = N_("Add a drone regex pattern."),
    .access         = PRIV_ADMIN,
    .maxparc        = 2,
    .cmd            = &os_cmd_drone_add,
    .help           = { .path = "oservice/drone_add" },
};

static struct command os_drone_del = {
    .name           = "DEL",
    .desc           = N_("Delete a drone regex pattern."),
    .access         = PRIV_ADMIN,
    .maxparc        = 1,
    .cmd            = &os_cmd_drone_del,
    .help           = { .path = "oservice/drone_del" },
};

static struct command os_drone_list = {
    .name           = "LIST",
    .desc           = N_("List drone regex patterns."),
    .access         = PRIV_ADMIN,
    .maxparc        = 0,
    .cmd            = &os_cmd_drone_list,
    .help           = { .path = "oservice/drone_list" },
};

static void
os_cmd_drone(struct sourceinfo *si, int parc, char *parv[])
{
    if (parc < 1)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE");
        command_fail(si, fault_needmoreparams, _("Syntax: DRONE ADD|DEL|LIST [params]"));
        return;
    }
    subcommand_dispatch_simple(si->service, si, parc, parv, os_drone_cmds, "DRONE");
}

static struct command os_drone = {
    .name           = "DRONE",
    .desc           = N_("Manage regex drone detection."),
    .access         = PRIV_ADMIN,
    .maxparc        = 3,
    .cmd            = &os_cmd_drone,
    .help           = { .path = "oservice/drone" },
};

static void
mod_init(struct module *const restrict m)
{
    MODULE_TRY_REQUEST_DEPENDENCY(m, "operserv/main");

    os_drone_cmds = mowgli_patricia_create(strcasecanon);

    command_add(&os_drone_add, os_drone_cmds);
    command_add(&os_drone_del, os_drone_cmds);
    command_add(&os_drone_list, os_drone_cmds);

    service_named_bind_command("operserv", &os_drone);

    hook_add_user_add(hook_user_add);
    hook_add_db_write(write_drone_db);

    db_register_type_handler("DRONE", db_h_drone);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
    mowgli_node_t *n, *tn;
    struct drone_pattern *dp;

    hook_del_user_add(hook_user_add);
    hook_del_db_write(write_drone_db);
    db_unregister_type_handler("DRONE");

    service_named_unbind_command("operserv", &os_drone);
    
    if (os_drone_cmds)
        mowgli_patricia_destroy(os_drone_cmds, NULL, NULL);

    MOWGLI_ITER_FOREACH_SAFE(n, tn, drone_list.head)
    {
        dp = n->data;
        regex_destroy(dp->regex);
        sfree(dp->pattern);
        sfree(dp->reason);
        sfree(dp);
        mowgli_node_delete(n, &drone_list);
    }
}

SIMPLE_DECLARE_MODULE_V1("operserv/drone", MODULE_UNLOAD_CAPABILITY_OK)
