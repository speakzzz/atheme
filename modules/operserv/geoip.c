/*
 * SPDX-License-Identifier: ISC
 *
 * modules/operserv/geoip.c
 * Services-side GeoIP & ASN Manager.
 * Allows blocking entire countries or ASNs via OperServ.
 *
 * Syntax:
 * /msg OperServ GEOIP ADD BADCOUNTRY <CC> <Reason>
 * /msg OperServ GEOIP ADD BADASN <ASN> <Reason>
 * /msg OperServ GEOIP DEL BADCOUNTRY <CC>
 * /msg OperServ GEOIP DEL BADASN <ASN>
 * /msg OperServ GEOIP LIST BADCOUNTRY
 * /msg OperServ GEOIP LIST BADASN
 */

#include <atheme.h>
#include <maxminddb.h>

/* Configuration: Database Paths */
#define GEOIP_DB_PATH "/var/lib/GeoIP/GeoLite2-Country.mmdb"
#define ASN_DB_PATH   "/var/lib/GeoIP/GeoLite2-ASN.mmdb"

struct geoip_rule {
    char *country_code;
    char *reason;
    mowgli_node_t node;
};

struct asn_rule {
    uint32_t asn;
    char *reason;
    mowgli_node_t node;
};

static mowgli_list_t geoip_list;
static mowgli_list_t asn_list;
static mowgli_patricia_t *os_geoip_cmds = NULL;

static MMDB_s mmdb_country;
static MMDB_s mmdb_asn;
static int country_db_loaded = 0;
static int asn_db_loaded = 0;

/* --------------------------------------------------------------------- */
/* HELPERS                                                               */
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

static struct asn_rule *
find_asn_rule(uint32_t asn)
{
    mowgli_node_t *n;
    struct asn_rule *r;

    MOWGLI_ITER_FOREACH(n, asn_list.head)
    {
        r = n->data;
        if (r->asn == asn)
            return r;
    }
    return NULL;
}

/* --------------------------------------------------------------------- */
/* DATABASE HANDLING                                                     */
/* --------------------------------------------------------------------- */

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
db_h_geoip_asn(struct database_handle *db, const char *type)
{
    uint32_t asn;
    const char *reason = db_read_str(db);
    struct asn_rule *r;

    if (!db_read_uint(db, &asn) || !reason) return;

    r = smalloc(sizeof(struct asn_rule));
    r->asn = asn;
    r->reason = sstrdup(reason);
    mowgli_node_add(r, &r->node, &asn_list);
}

static void
write_geoip_db(struct database_handle *db)
{
    mowgli_node_t *n;
    struct geoip_rule *gr;
    struct asn_rule *ar;

    MOWGLI_ITER_FOREACH(n, geoip_list.head)
    {
        gr = n->data;
        db_start_row(db, "GEOIP");
        db_write_str(db, gr->country_code);
        db_write_str(db, gr->reason);
        db_commit_row(db);
    }

    MOWGLI_ITER_FOREACH(n, asn_list.head)
    {
        ar = n->data;
        db_start_row(db, "GEOIP_ASN");
        db_write_uint(db, ar->asn);
        db_write_str(db, ar->reason);
        db_commit_row(db);
    }
}

/* --------------------------------------------------------------------- */
/* COMMANDS: ADD                                                         */
/* --------------------------------------------------------------------- */

static void
os_cmd_geoip_add(struct sourceinfo *si, int parc, char *parv[])
{
    char *type = parv[0];
    char *target = parv[1];
    char *reason = parv[2];

    if (!type || !target || !reason)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP ADD");
        command_fail(si, fault_needmoreparams, _("Syntax: GEOIP ADD <BADCOUNTRY|BADASN> <Target> <Reason>"));
        return;
    }

    if (!strcasecmp(type, "BADCOUNTRY"))
    {
        /* --- Country Logic --- */
        struct geoip_rule *r;

        if (strlen(target) != 2)
        {
            command_fail(si, fault_badparams, _("Country code must be exactly 2 letters (e.g. US, RU)."));
            return;
        }

        if (find_geoip_rule(target))
        {
            command_fail(si, fault_nochange, _("Country \2%s\2 is already blocked."), target);
            return;
        }

        r = smalloc(sizeof(struct geoip_rule));
        r->country_code = sstrdup(target);
        r->reason = sstrdup(reason);
        mowgli_node_add(r, &r->node, &geoip_list);

        command_success_nodata(si, _("Added \2%s\2 to the GeoIP block list."), target);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:ADD:BADCOUNTRY: \2%s\2 (Reason: \2%s\2)", target, reason);
    }
    else if (!strcasecmp(type, "BADASN"))
    {
        /* --- ASN Logic --- */
        struct asn_rule *r;
        uint32_t asn;

        asn = (uint32_t)strtoul(target, NULL, 10);
        if (asn == 0)
        {
            command_fail(si, fault_badparams, _("Invalid ASN."));
            return;
        }

        if (find_asn_rule(asn))
        {
            command_fail(si, fault_nochange, _("ASN \2%u\2 is already blocked."), asn);
            return;
        }

        r = smalloc(sizeof(struct asn_rule));
        r->asn = asn;
        r->reason = sstrdup(reason);
        mowgli_node_add(r, &r->node, &asn_list);

        command_success_nodata(si, _("Added ASN \2%u\2 to the block list."), asn);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:ADD:BADASN: \2%u\2 (Reason: \2%s\2)", asn, reason);
    }
    else
    {
        command_fail(si, fault_badparams, _("Invalid type. Use BADCOUNTRY or BADASN."));
    }
}

/* --------------------------------------------------------------------- */
/* COMMANDS: DEL                                                         */
/* --------------------------------------------------------------------- */

static void
os_cmd_geoip_del(struct sourceinfo *si, int parc, char *parv[])
{
    char *type = parv[0];
    char *target = parv[1];

    if (!type || !target)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP DEL");
        command_fail(si, fault_needmoreparams, _("Syntax: GEOIP DEL <BADCOUNTRY|BADASN> <Target>"));
        return;
    }

    if (!strcasecmp(type, "BADCOUNTRY"))
    {
        struct geoip_rule *r;

        if (!(r = find_geoip_rule(target)))
        {
            command_fail(si, fault_nosuch_target, _("Country \2%s\2 is not blocked."), target);
            return;
        }

        mowgli_node_delete(&r->node, &geoip_list);
        sfree(r->country_code);
        sfree(r->reason);
        sfree(r);

        command_success_nodata(si, _("Removed \2%s\2 from the GeoIP block list."), target);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:DEL:BADCOUNTRY: \2%s\2", target);
    }
    else if (!strcasecmp(type, "BADASN"))
    {
        struct asn_rule *r;
        uint32_t asn;

        asn = (uint32_t)strtoul(target, NULL, 10);
        if (!(r = find_asn_rule(asn)))
        {
            command_fail(si, fault_nosuch_target, _("ASN \2%u\2 is not blocked."), asn);
            return;
        }

        mowgli_node_delete(&r->node, &asn_list);
        sfree(r->reason);
        sfree(r);

        command_success_nodata(si, _("Removed ASN \2%u\2 from the block list."), asn);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:DEL:BADASN: \2%u\2", asn);
    }
    else
    {
        command_fail(si, fault_badparams, _("Invalid type. Use BADCOUNTRY or BADASN."));
    }
}

/* --------------------------------------------------------------------- */
/* COMMANDS: LIST                                                        */
/* --------------------------------------------------------------------- */

static void
os_cmd_geoip_list(struct sourceinfo *si, int parc, char *parv[])
{
    char *type = parv[0];

    if (!type)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP LIST");
        command_fail(si, fault_needmoreparams, _("Syntax: GEOIP LIST <BADCOUNTRY|BADASN>"));
        return;
    }

    if (!strcasecmp(type, "BADCOUNTRY"))
    {
        mowgli_node_t *n;
        struct geoip_rule *gr;

        command_success_nodata(si, _("Blocked Countries:"));
        MOWGLI_ITER_FOREACH(n, geoip_list.head)
        {
            gr = n->data;
            command_success_nodata(si, _("- \2%s\2: %s"), gr->country_code, gr->reason);
        }
        command_success_nodata(si, _("End of list."));
    }
    else if (!strcasecmp(type, "BADASN"))
    {
        mowgli_node_t *n;
        struct asn_rule *ar;

        command_success_nodata(si, _("Blocked ASNs:"));
        MOWGLI_ITER_FOREACH(n, asn_list.head)
        {
            ar = n->data;
            command_success_nodata(si, _("- \2%u\2: %s"), ar->asn, ar->reason);
        }
        command_success_nodata(si, _("End of list."));
    }
    else
    {
        command_fail(si, fault_badparams, _("Invalid type. Use BADCOUNTRY or BADASN."));
    }
}

/* --------------------------------------------------------------------- */
/* HOOK: USER ADD                                                        */
/* --------------------------------------------------------------------- */

static void
hook_user_add(struct hook_user_nick *data)
{
    struct user *u = data->u;
    struct geoip_rule *gr;
    struct asn_rule *ar;
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;
    char country_code[3] = "??";
    uint32_t asn = 0;
    struct service *operserv;

    if (!u || is_internal_client(u)) return;

    /* EXEMPTION: Skip registered users */
    if (u->myuser) return;

    /* 1. Country Lookup */
    if (country_db_loaded)
    {
        result = MMDB_lookup_string(&mmdb_country, u->ip, &gai_error, &mmdb_error);
        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && result.found_entry)
        {
            if (MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL) == MMDB_SUCCESS) {
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    snprintf(country_code, 3, "%.*s", entry_data.data_size, entry_data.utf8_string);
                }
            }
        }
    }

    /* 2. ASN Lookup */
    if (asn_db_loaded)
    {
        result = MMDB_lookup_string(&mmdb_asn, u->ip, &gai_error, &mmdb_error);
        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && result.found_entry)
        {
            if (MMDB_get_value(&result.entry, &entry_data, "autonomous_system_number", NULL) == MMDB_SUCCESS) {
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32) {
                    /* FIX: use .uint32 instead of .uint32_value */
                    asn = entry_data.uint32;
                }
            }
        }
    }

    operserv = service_find("operserv");
    if (!operserv) return;

    /* Check Country Block */
    if ((gr = find_geoip_rule(country_code)))
    {
        slog(LG_INFO, "GEOIP: Blocked user %s from %s", u->nick, country_code);
        kline_sts("*", "*", u->host, 86400, gr->reason);
        wallops("GEOIP: Banned \2%s\2 (Country: \2%s\2)", u->nick, country_code);
        return;
    }

    /* Check ASN Block */
    if (asn > 0 && (ar = find_asn_rule(asn)))
    {
        slog(LG_INFO, "GEOIP: Blocked user %s from ASN %u", u->nick, asn);
        kline_sts("*", "*", u->host, 86400, ar->reason);
        wallops("GEOIP: Banned \2%s\2 (ASN: \2%u\2)", u->nick, asn);
        return;
    }
}

/* --------------------------------------------------------------------- */
/* BOILERPLATE                                                           */
/* --------------------------------------------------------------------- */

static struct command os_geoip_add = {
    .name = "ADD", .desc = N_("Add a GeoIP or ASN block."), .access = PRIV_ADMIN,
    .maxparc = 3, .cmd = &os_cmd_geoip_add, .help = { .path = "oservice/geoip_add" },
};

static struct command os_geoip_del = {
    .name = "DEL", .desc = N_("Remove a GeoIP or ASN block."), .access = PRIV_ADMIN,
    .maxparc = 2, .cmd = &os_cmd_geoip_del, .help = { .path = "oservice/geoip_del" },
};

static struct command os_geoip_list = {
    .name = "LIST", .desc = N_("List blocked countries or ASNs."), .access = PRIV_ADMIN,
    .maxparc = 1, .cmd = &os_cmd_geoip_list, .help = { .path = "oservice/geoip_list" },
};

static void
os_cmd_geoip(struct sourceinfo *si, int parc, char *parv[])
{
    if (parc < 1) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP");
        command_fail(si, fault_needmoreparams, _("Syntax: GEOIP ADD|DEL|LIST [params]"));
        return;
    }
    subcommand_dispatch_simple(si->service, si, parc, parv, os_geoip_cmds, "GEOIP");
}

static struct command os_geoip = {
    .name = "GEOIP", .desc = N_("Manage GeoIP/ASN Blocking."), .access = PRIV_ADMIN,
    .maxparc = 4, .cmd = &os_cmd_geoip, .help = { .path = "oservice/geoip" },
};

static void
mod_init(struct module *const restrict m)
{
    MODULE_TRY_REQUEST_DEPENDENCY(m, "operserv/main");

    /* Load Country DB */
    if (MMDB_open(GEOIP_DB_PATH, MMDB_MODE_MMAP, &mmdb_country) == MMDB_SUCCESS) {
        country_db_loaded = 1;
        slog(LG_INFO, "GeoIP: Country Database loaded.");
    } else {
        slog(LG_ERROR, "GeoIP: Failed to load %s", GEOIP_DB_PATH);
    }

    /* Load ASN DB */
    if (MMDB_open(ASN_DB_PATH, MMDB_MODE_MMAP, &mmdb_asn) == MMDB_SUCCESS) {
        asn_db_loaded = 1;
        slog(LG_INFO, "GeoIP: ASN Database loaded.");
    } else {
        slog(LG_ERROR, "GeoIP: Failed to load %s", ASN_DB_PATH);
    }
    
    os_geoip_cmds = mowgli_patricia_create(strcasecanon);

    command_add(&os_geoip_add, os_geoip_cmds);
    command_add(&os_geoip_del, os_geoip_cmds);
    command_add(&os_geoip_list, os_geoip_cmds);

    service_named_bind_command("operserv", &os_geoip);

    hook_add_user_add(hook_user_add);
    hook_add_db_write(write_geoip_db);
    db_register_type_handler("GEOIP", db_h_geoip);
    db_register_type_handler("GEOIP_ASN", db_h_geoip_asn);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
    mowgli_node_t *n, *tn;
    struct geoip_rule *gr;
    struct asn_rule *ar;

    if (country_db_loaded) MMDB_close(&mmdb_country);
    if (asn_db_loaded) MMDB_close(&mmdb_asn);
    
    hook_del_user_add(hook_user_add);
    hook_del_db_write(write_geoip_db);
    db_unregister_type_handler("GEOIP");
    db_unregister_type_handler("GEOIP_ASN");
    service_named_unbind_command("operserv", &os_geoip);
    if (os_geoip_cmds) mowgli_patricia_destroy(os_geoip_cmds, NULL, NULL);

    MOWGLI_ITER_FOREACH_SAFE(n, tn, geoip_list.head) {
        gr = n->data;
        sfree(gr->country_code);
        sfree(gr->reason);
        sfree(gr);
        mowgli_node_delete(n, &geoip_list);
    }

    MOWGLI_ITER_FOREACH_SAFE(n, tn, asn_list.head) {
        ar = n->data;
        sfree(ar->reason);
        sfree(ar);
        mowgli_node_delete(n, &asn_list);
    }
}

SIMPLE_DECLARE_MODULE_V1("operserv/geoip", MODULE_UNLOAD_CAPABILITY_OK)
