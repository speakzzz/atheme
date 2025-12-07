/*
 * SPDX-License-Identifier: ISC
 *
 * modules/operserv/geoip.c
 * Services-side GeoIP Manager.
 * Allows blocking entire countries via OperServ.
 *
 * Syntax:
 * /msg OS GEOIP BAD <CC> <Reason>
 * /msg OS GEOIP GOOD <CC>
 * /msg OS GEOIP LIST
 */

#include <atheme.h>
#include <maxminddb.h>

/* Configuration: Updated Path */
#define GEOIP_DB_PATH "/var/lib/GeoIP/GeoLite2-Country.mmdb"

struct geoip_rule {
    char *country_code;
    char *reason;
    mowgli_node_t node;
};

static mowgli_list_t geoip_list;
static mowgli_patricia_t *os_geoip_cmds = NULL;
static MMDB_s mmdb;
static int mmdb_loaded = 0;

/* --------------------------------------------------------------------- */
/* DATABASE & HELPERS                                                    */
/* --------------------------------------------------------------------- */

static struct geoip_rule *
find_geoip_rule(const char *cc)
{
    mowgli_node_t *n;
    struct geoip_rule *r;

    MOWGLI_ITER_FOREACH(n, geoip_list.head)
    {
        r = n->data;
        if (!strcasecmp(r->country_code, cc))
            return r;
    }
    return NULL;
}

static void
db_h_geoip(struct database_handle *db, const char *type)
{
    const char *cc = db_read_str(db);
    const char *reason = db_read_str(db);
    struct geoip_rule *r;

    if (!cc || !reason) return;

    r = smalloc(sizeof(struct geoip_rule));
    r->country_code = sstrdup(cc);
    r->reason = sstrdup(reason);
    mowgli_node_add(r, &r->node, &geoip_list);
}

static void
write_geoip_db(struct database_handle *db)
{
    mowgli_node_t *n;
    struct geoip_rule *r;

    MOWGLI_ITER_FOREACH(n, geoip_list.head)
    {
        r = n->data;
        db_start_row(db, "GEOIP");
        db_write_str(db, r->country_code);
        db_write_str(db, r->reason);
        db_commit_row(db);
    }
}

/* --------------------------------------------------------------------- */
/* COMMANDS                                                              */
/* --------------------------------------------------------------------- */

static void
os_cmd_geoip_bad(struct sourceinfo *si, int parc, char *parv[])
{
    char *cc = parv[0];
    char *reason = parv[1];
    struct geoip_rule *r;

    if (!cc || !reason)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP BAD");
        command_fail(si, fault_needmoreparams, _("Syntax: GEOIP BAD <CC> <Reason>"));
        return;
    }

    if (strlen(cc) != 2)
    {
        command_fail(si, fault_badparams, _("Country code must be exactly 2 letters (e.g. US, RU)."));
        return;
    }

    if (find_geoip_rule(cc))
    {
        command_fail(si, fault_nochange, _("Country \2%s\2 is already blocked."), cc);
        return;
    }

    r = smalloc(sizeof(struct geoip_rule));
    r->country_code = sstrdup(cc);
    r->reason = sstrdup(reason);
    mowgli_node_add(r, &r->node, &geoip_list);

    command_success_nodata(si, _("Added \2%s\2 to the GeoIP block list."), cc);
    logcommand(si, CMDLOG_ADMIN, "GEOIP:BAD: \2%s\2 (Reason: \2%s\2)", cc, reason);
}

static void
os_cmd_geoip_good(struct sourceinfo *si, int parc, char *parv[])
{
    char *cc = parv[0];
    struct geoip_rule *r;

    if (!cc)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP GOOD");
        return;
    }

    if (!(r = find_geoip_rule(cc)))
    {
        command_fail(si, fault_nosuch_target, _("Country \2%s\2 is not blocked."), cc);
        return;
    }

    mowgli_node_delete(&r->node, &geoip_list);
    sfree(r->country_code);
    sfree(r->reason);
    sfree(r);

    command_success_nodata(si, _("Removed \2%s\2 from the GeoIP block list."), cc);
    logcommand(si, CMDLOG_ADMIN, "GEOIP:GOOD: \2%s\2", cc);
}

static void
os_cmd_geoip_list(struct sourceinfo *si, int parc, char *parv[])
{
    mowgli_node_t *n;
    struct geoip_rule *r;

    command_success_nodata(si, _("Blocked Countries:"));
    MOWGLI_ITER_FOREACH(n, geoip_list.head)
    {
        r = n->data;
        command_success_nodata(si, _("- \2%s\2: %s"), r->country_code, r->reason);
    }
    command_success_nodata(si, _("End of list."));
}

/* --------------------------------------------------------------------- */
/* HOOK: USER ADD                                                        */
/* --------------------------------------------------------------------- */

static void
hook_user_add(struct hook_user_nick *data)
{
    struct user *u = data->u;
    struct geoip_rule *r;
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;
    char country_code[3] = "??";
    struct service *operserv;

    if (!mmdb_loaded || !u || is_internal_client(u)) return;

    /* EXEMPTION: Skip registered users */
    if (u->myuser) return;

    /* Lookup IP */
    result = MMDB_lookup_string(&mmdb, u->ip, &gai_error, &mmdb_error);
    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) return;

    if (MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
             snprintf(country_code, 3, "%.*s", entry_data.data_size, entry_data.utf8_string);
        }
    }

    /* Check Blocklist */
    if ((r = find_geoip_rule(country_code)))
    {
        operserv = service_find("operserv");
        if (operserv)
        {
            slog(LG_INFO, "GEOIP: Blocked user %s from %s", u->nick, country_code);
            
            /* Add an AKILL (K-Line) for 1 day */
            kline_sts("*", "*", u->host, 86400, r->reason);
            
            /* Notify Admins */
            wallops("GEOIP: Banned \2%s\2 (Country: \2%s\2)", u->nick, country_code);
        }
    }
}

/* --------------------------------------------------------------------- */
/* BOILERPLATE                                                           */
/* --------------------------------------------------------------------- */

static struct command os_geoip_bad = {
    .name = "BAD", .desc = N_("Block a country."), .access = PRIV_ADMIN,
    .maxparc = 2, .cmd = &os_cmd_geoip_bad, .help = { .path = "oservice/geoip_bad" },
};

static struct command os_geoip_good = {
    .name = "GOOD", .desc = N_("Unblock a country."), .access = PRIV_ADMIN,
    .maxparc = 1, .cmd = &os_cmd_geoip_good, .help = { .path = "oservice/geoip_good" },
};

static struct command os_geoip_list = {
    .name = "LIST", .desc = N_("List blocked countries."), .access = PRIV_ADMIN,
    .maxparc = 0, .cmd = &os_cmd_geoip_list, .help = { .path = "oservice/geoip_list" },
};

static void
os_cmd_geoip(struct sourceinfo *si, int parc, char *parv[])
{
    if (parc < 1) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP");
        command_fail(si, fault_needmoreparams, _("Syntax: GEOIP BAD|GOOD|LIST [params]"));
        return;
    }
    subcommand_dispatch_simple(si->service, si, parc, parv, os_geoip_cmds, "GEOIP");
}

static struct command os_geoip = {
    .name = "GEOIP", .desc = N_("Manage Country Blocking."), .access = PRIV_ADMIN,
    .maxparc = 3, .cmd = &os_cmd_geoip, .help = { .path = "oservice/geoip" },
};

static void
mod_init(struct module *const restrict m)
{
    MODULE_TRY_REQUEST_DEPENDENCY(m, "operserv/main");

    /* Load DB */
    if (MMDB_open(GEOIP_DB_PATH, MMDB_MODE_MMAP, &mmdb) == MMDB_SUCCESS) {
        mmdb_loaded = 1;
        slog(LG_INFO, "GeoIP: Database loaded.");
    } else {
        slog(LG_ERROR, "GeoIP: Failed to load %s", GEOIP_DB_PATH);
    }

    os_geoip_cmds = mowgli_patricia_create(strcasecanon);

    command_add(&os_geoip_bad, os_geoip_cmds);
    command_add(&os_geoip_good, os_geoip_cmds);
    command_add(&os_geoip_list, os_geoip_cmds);

    service_named_bind_command("operserv", &os_geoip);

    hook_add_user_add(hook_user_add);
    hook_add_db_write(write_geoip_db);
    db_register_type_handler("GEOIP", db_h_geoip);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
    mowgli_node_t *n, *tn;
    struct geoip_rule *r;

    if (mmdb_loaded) MMDB_close(&mmdb);
    
    hook_del_user_add(hook_user_add);
    hook_del_db_write(write_geoip_db);
    db_unregister_type_handler("GEOIP");
    service_named_unbind_command("operserv", &os_geoip);
    if (os_geoip_cmds) mowgli_patricia_destroy(os_geoip_cmds, NULL, NULL);

    MOWGLI_ITER_FOREACH_SAFE(n, tn, geoip_list.head) {
        r = n->data;
        sfree(r->country_code);
        sfree(r->reason);
        sfree(r);
        mowgli_node_delete(n, &geoip_list);
    }
}

SIMPLE_DECLARE_MODULE_V1("operserv/geoip", MODULE_UNLOAD_CAPABILITY_OK)
