/*
 * SPDX-License-Identifier: ISC
 *
 * modules/operserv/geoip.c
 * Services-side GeoIP & ASN Manager.
 */

#include "atheme.h"
#include "atheme/database_backend.h"
#include <maxminddb.h>

#define GEOIP_DB_FILE "etc/geoip.db"

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
  /* If MU_SRA is missing, fallback to generic Admin check */
  #define is_sra(u) (has_priv(si, PRIV_USER_ADMIN))
 #endif
#endif

/* Local Command Table for GEOIP subcommands */
static mowgli_patricia_t *geoip_cmds = NULL;

/* Local Configuration Table */
static mowgli_list_t geoip_conf_table;

/* Global configuration variables */
static char *country_db_path = NULL;
static char *asn_db_path = NULL;

/* MaxMind DB Handles */
static MMDB_s country_mmdb;
static MMDB_s asn_mmdb;
static bool country_db_loaded = false;
static bool asn_db_loaded = false;

/* Lists */
static mowgli_list_t badcountry_list;
static mowgli_list_t badasn_list;
static mowgli_list_t geoip_exempt_list;

/* Structures */
struct badcountry {
    char *iso_code;
    char *reason;
    mowgli_node_t node;
};

struct badasn {
    unsigned int asn;
    char *reason;
    mowgli_node_t node;
};

struct geoip_exempt {
    char *mask;
    char *reason;
    char *setter;
    time_t set_time;
    mowgli_node_t node;
};

/* --------------------------------------------------------------------- */
/* Persistence Functions (Flatfile) */
/* --------------------------------------------------------------------- */

/* Forward declarations */
static void add_badcountry_entry(const char *iso, const char *reason);
static void add_badasn_entry(unsigned int asn, const char *reason);
static void add_exempt(const char *mask, const char *reason, const char *setter, time_t t);

static void
save_geoip_db(void)
{
    FILE *f = fopen(GEOIP_DB_FILE, "w");
    mowgli_node_t *n;

    if (!f)
    {
        slog(LG_ERROR, "GEOIP: Could not open %s for writing: %s", GEOIP_DB_FILE, strerror(errno));
        return;
    }

    /* Save Countries: C <ISO> <Reason> */
    MOWGLI_ITER_FOREACH(n, badcountry_list.head)
    {
        struct badcountry *bc = n->data;
        fprintf(f, "C %s %s\n", bc->iso_code, bc->reason);
    }

    /* Save ASNs: A <ASN> <Reason> */
    MOWGLI_ITER_FOREACH(n, badasn_list.head)
    {
        struct badasn *ba = n->data;
        fprintf(f, "A %u %s\n", ba->asn, ba->reason);
    }

    /* Save Exemptions: E <Mask> <Time> <Setter> <Reason> */
    MOWGLI_ITER_FOREACH(n, geoip_exempt_list.head)
    {
        struct geoip_exempt *e = n->data;
        fprintf(f, "E %s %ld %s %s\n", e->mask, (long)e->set_time, e->setter, e->reason);
    }

    fclose(f);
}

static void
load_geoip_db(void)
{
    FILE *f = fopen(GEOIP_DB_FILE, "r");
    char line[BUFSIZE];
    char *type, *p1, *p2, *p3, *p4;

    if (!f) return; /* No DB yet, that's fine */

    while (fgets(line, sizeof(line), f))
    {
        /* Strip newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;

        type = strtok(line, " ");
        if (!type) continue;

        if (!strcasecmp(type, "C"))
        {
            p1 = strtok(NULL, " "); /* ISO */
            p2 = strtok(NULL, "");  /* Reason (Rest of line) */
            if (p1 && p2) add_badcountry_entry(p1, p2);
        }
        else if (!strcasecmp(type, "A"))
        {
            p1 = strtok(NULL, " "); /* ASN */
            p2 = strtok(NULL, "");  /* Reason */
            if (p1 && p2) add_badasn_entry(atoi(p1), p2);
        }
        else if (!strcasecmp(type, "E"))
        {
            p1 = strtok(NULL, " "); /* Mask */
            p2 = strtok(NULL, " "); /* Time */
            p3 = strtok(NULL, " "); /* Setter */
            p4 = strtok(NULL, "");  /* Reason */
            if (p1 && p2 && p3 && p4) add_exempt(p1, p4, p3, (time_t)atol(p2));
        }
    }
    fclose(f);
    slog(LG_INFO, "GEOIP: Database loaded from %s", GEOIP_DB_FILE);
}

/* --------------------------------------------------------------------- */
/* Helper Functions */
/* --------------------------------------------------------------------- */

static bool
is_exempt(const char *ip)
{
    mowgli_node_t *n;

    if (!ip) return false;

    MOWGLI_ITER_FOREACH(n, geoip_exempt_list.head)
    {
        struct geoip_exempt *e = n->data;
        if (!match(e->mask, ip))
            return true;
    }
    return false;
}

static void
add_exempt(const char *mask, const char *reason, const char *setter, time_t t)
{
    struct geoip_exempt *e = mowgli_alloc(sizeof(struct geoip_exempt));
    e->mask = sstrdup(mask);
    e->reason = sstrdup(reason);
    e->setter = sstrdup(setter);
    e->set_time = t;
    mowgli_node_add(e, &e->node, &geoip_exempt_list);
}

static void
add_badcountry_entry(const char *iso, const char *reason)
{
    struct badcountry *bc = mowgli_alloc(sizeof(struct badcountry));
    bc->iso_code = sstrdup(iso);
    bc->reason = sstrdup(reason);
    mowgli_node_add(bc, &bc->node, &badcountry_list);
}

static void
add_badasn_entry(unsigned int asn, const char *reason)
{
    struct badasn *ba = mowgli_alloc(sizeof(struct badasn));
    ba->asn = asn;
    ba->reason = sstrdup(reason);
    mowgli_node_add(ba, &ba->node, &badasn_list);
}

static struct badcountry *
find_badcountry(const char *iso)
{
    mowgli_node_t *n;
    if (!iso) return NULL;
    MOWGLI_ITER_FOREACH(n, badcountry_list.head)
    {
        struct badcountry *bc = n->data;
        if (!strcasecmp(bc->iso_code, iso))
            return bc;
    }
    return NULL;
}

static struct badasn *
find_badasn(unsigned int asn)
{
    mowgli_node_t *n;
    MOWGLI_ITER_FOREACH(n, badasn_list.head)
    {
        struct badasn *ba = n->data;
        if (ba->asn == asn)
            return ba;
    }
    return NULL;
}

/* --------------------------------------------------------------------- */
/* Configuration Handlers */
/* --------------------------------------------------------------------- */

static int
conf_country_db(mowgli_config_file_entry_t *ce)
{
    if (!ce->vardata) return 0;
    if (country_db_path) free(country_db_path);
    country_db_path = sstrdup(ce->vardata);
    return 0;
}

static int
conf_asn_db(mowgli_config_file_entry_t *ce)
{
    if (!ce->vardata) return 0;
    if (asn_db_path) free(asn_db_path);
    asn_db_path = sstrdup(ce->vardata);
    return 0;
}

static int
geoip_config_handler(mowgli_config_file_entry_t *ce)
{
    return subblock_handler(ce, &geoip_conf_table);
}

/* --------------------------------------------------------------------- */
/* Database Persistence (Atheme DB Backend Hooks - Legacy support) */
/* --------------------------------------------------------------------- */

static void
write_geoip_db(struct database_handle *db)
{
    /* We use flatfile now, but we keep this empty hook to satisfy Atheme's engine if needed */
}

static void
db_h_geoip_exempt(struct database_handle *db, const char *type)
{
    /* Handled by flatfile load */
    const char *mask = db_read_word(db);
    const char *reason = db_read_word(db);
    const char *setter = db_read_word(db);
    time_t t;
    if (!db_read_time(db, &t)) t = 0;
    (void)mask; (void)reason; (void)setter; /* Suppress unused warning */
}

static void
db_h_geoip_country(struct database_handle *db, const char *type)
{
    const char *iso = db_read_word(db);
    const char *reason = db_read_word(db);
    (void)iso; (void)reason;
}

static void
db_h_geoip_asn(struct database_handle *db, const char *type)
{
    unsigned int asn = 0;
    const char *reason;
    if (!db_read_uint(db, &asn)) return;
    reason = db_read_word(db);
    (void)reason;
}

/* --------------------------------------------------------------------- */
/* Core Check Logic */
/* --------------------------------------------------------------------- */

/* Returns a reason string if banned, NULL if allowed */
static const char *
get_geoip_ban_reason(struct user *u)
{
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;
    static char reason[BUFSIZE];

    if (!u) return NULL;
    
    if (is_internal_client(u)) return NULL;

    if (!u->ip) return NULL;

    /* Debug disabled to reduce spam */
    /* slog(LG_DEBUG, "GEOIP: Checking user %s IP %s", u->nick, u->ip); */

    /* 1. Check Whitelist First */
    if (is_exempt(u->ip))
    {
        return NULL;
    }

    /* 2. Check Country */
    if (country_db_loaded)
    {
        result = MMDB_lookup_string(&country_mmdb, u->ip, &gai_error, &mmdb_error);
        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && result.found_entry)
        {
            if (MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL) == MMDB_SUCCESS)
            {
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING)
                {
                    char iso_code[3];
                    memset(iso_code, 0, sizeof(iso_code));
                    memcpy(iso_code, entry_data.utf8_string, 2);

                    struct badcountry *bc = find_badcountry(iso_code);
                    if (bc)
                    {
                        snprintf(reason, sizeof(reason), "Country banned (%s): %s", bc->iso_code, bc->reason);
                        return reason;
                    }
                }
            }
        }
    }

    /* 3. Check ASN */
    if (asn_db_loaded)
    {
        result = MMDB_lookup_string(&asn_mmdb, u->ip, &gai_error, &mmdb_error);
        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && result.found_entry)
        {
            if (MMDB_get_value(&result.entry, &entry_data, "autonomous_system_number", NULL) == MMDB_SUCCESS)
            {
                if (entry_data.has_data && (entry_data.type == MMDB_DATA_TYPE_UINT32 || entry_data.type == MMDB_DATA_TYPE_UINT16))
                {
                    unsigned int asn = entry_data.uint32;
                    struct badasn *ba = find_badasn(asn);
                    if (ba)
                    {
                        snprintf(reason, sizeof(reason), "ASN banned (%u): %s", asn, ba->reason);
                        return reason;
                    }
                }
            }
        }
    }

    return NULL;
}

static void
enforce_geoip(struct user *u, const char *reason)
{
    struct service *oserv = service_find("operserv");
    if (!oserv || !u || !reason) return;

    /* Keep INFO level log for Bans so admins know action was taken */
    slog(LG_INFO, "GEOIP: Klining user %s (%s) -> %s", u->nick, u->ip, reason);
    
    /* Add K-Line for 1 day (86400 seconds) */
    kline_add("*", u->ip, reason, 86400, oserv->nick);
    
    /* Kill to enforce immediately */
    kill_user(oserv->me, u, "%s", reason);
}

static void
check_user_hook(void *data)
{
    /* In Atheme, the 'user_add' hook passes a struct hook_user_nick* as data. */
    struct user **u_ptr = (struct user **)data;
    struct user *u;

    if (!u_ptr) return;
    u = *u_ptr;

    if (!u) return;

    const char *reason = get_geoip_ban_reason(u);
    if (reason)
    {
        enforce_geoip(u, reason);
    }
}

/* --------------------------------------------------------------------- */
/* Commands */
/* --------------------------------------------------------------------- */

static void
cmd_geoip_scan(struct sourceinfo *si, int parc, char *parv[])
{
    mowgli_patricia_iteration_state_t state;
    struct user *u;
    mowgli_list_t victim_list = { NULL, NULL, 0 };
    mowgli_node_t *n, *tn;
    int scanned = 0;
    
    /* SRA CHECK */
    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    logcommand(si, CMDLOG_ADMIN, "GEOIP:SCAN");
    command_success_nodata(si, "Scanning all users against GeoIP database...");

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        if (is_internal_client(u)) continue;
        scanned++;

        const char *reason = get_geoip_ban_reason(u);
        if (reason)
        {
            mowgli_node_add(u, mowgli_node_create(), &victim_list);
        }
    }

    int banned_count = 0;
    MOWGLI_ITER_FOREACH_SAFE(n, tn, victim_list.head)
    {
        u = (struct user *)n->data;
        if (user_find(u->nick)) 
        {
            const char *reason = get_geoip_ban_reason(u); 
            if (reason) {
                enforce_geoip(u, reason);
                banned_count++;
            }
        }
        mowgli_node_delete(n, &victim_list);
        mowgli_node_free(n);
    }

    command_success_nodata(si, "GeoIP Scan complete. Scanned: %d. Banned: %d.", scanned, banned_count);
}

static void
cmd_geoip_exempt(struct sourceinfo *si, int parc, char *parv[])
{
    char *action = parv[0];
    char *mask = parv[1];
    char *reason = parv[2];
    mowgli_node_t *n, *tn;

    /* SRA CHECK */
    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!action)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP EXEMPT");
        command_fail(si, fault_needmoreparams, _("Usage: GEOIP EXEMPT ADD <mask/ip> <reason>"));
        command_fail(si, fault_needmoreparams, _("       GEOIP EXEMPT DEL <mask/ip>"));
        command_fail(si, fault_needmoreparams, _("       GEOIP EXEMPT LIST"));
        return;
    }

    if (!strcasecmp(action, "ADD"))
    {
        if (!mask || !reason)
        {
            command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP EXEMPT ADD");
            return;
        }

        if (is_exempt(mask))
        {
            command_fail(si, fault_nochange, "Mask \2%s\2 is already exempted.", mask);
            return;
        }

        add_exempt(mask, reason, get_storage_oper_name(si), CURRTIME);
        save_geoip_db();
        command_success_nodata(si, "Added \2%s\2 to the GeoIP exemption list.", mask);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:EXEMPT:ADD: \2%s\2 (Reason: %s)", mask, reason);
    }
    else if (!strcasecmp(action, "DEL"))
    {
        if (!mask)
        {
            command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP EXEMPT DEL");
            return;
        }

        MOWGLI_ITER_FOREACH_SAFE(n, tn, geoip_exempt_list.head)
        {
            struct geoip_exempt *e = n->data;
            if (!strcasecmp(e->mask, mask))
            {
                mowgli_node_delete(n, &geoip_exempt_list);
                free(e->mask);
                free(e->reason);
                free(e->setter);
                mowgli_free(e);
                save_geoip_db();
                command_success_nodata(si, "Removed \2%s\2 from the GeoIP exemption list.", mask);
                logcommand(si, CMDLOG_ADMIN, "GEOIP:EXEMPT:DEL: \2%s\2", mask);
                return;
            }
        }
        command_fail(si, fault_nosuch_target, "Mask \2%s\2 not found in exemption list.", mask);
    }
    else if (!strcasecmp(action, "LIST"))
    {
        unsigned int count = 0;
        char buf[BUFSIZE];
        struct tm tm;

        command_success_nodata(si, "GeoIP Exemption List:");
        MOWGLI_ITER_FOREACH(n, geoip_exempt_list.head)
        {
            struct geoip_exempt *e = n->data;
            tm = *localtime(&e->set_time);
            strftime(buf, BUFSIZE, TIME_FORMAT, &tm);
            command_success_nodata(si, "%d: \2%s\2 (Set by: %s on %s) Reason: %s", 
                ++count, e->mask, e->setter, buf, e->reason);
        }
        command_success_nodata(si, "End of list.");
    }
    else
    {
        command_fail(si, fault_badparams, STR_INVALID_PARAMS, "GEOIP EXEMPT");
    }
}

static void
cmd_geoip_add(struct sourceinfo *si, int parc, char *parv[])
{
    char *type = parv[0];
    char *target = parv[1];
    char *reason = parv[2];

    /* SRA CHECK */
    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!type || !target || !reason)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP ADD");
        command_fail(si, fault_needmoreparams, _("Usage: GEOIP ADD BADCOUNTRY <CC> <Reason>"));
        command_fail(si, fault_needmoreparams, _("       GEOIP ADD BADASN <ASN> <Reason>"));
        return;
    }

    if (!strcasecmp(type, "BADCOUNTRY"))
    {
        if (strlen(target) != 2)
        {
            command_fail(si, fault_badparams, "Country code must be exactly 2 characters (ISO 3166-1 alpha-2).");
            return;
        }
        if (find_badcountry(target))
        {
            command_fail(si, fault_nochange, "Country \2%s\2 is already blocked.", target);
            return;
        }

        add_badcountry_entry(target, reason);
        save_geoip_db();
        command_success_nodata(si, "Country \2%s\2 added to blocklist. Perform a \2GEOIP SCAN\2 to apply immediately.", target);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:ADD:BADCOUNTRY: \2%s\2 (Reason: %s)", target, reason);
    }
    else if (!strcasecmp(type, "BADASN"))
    {
        unsigned int asn = atoi(target);
        if (asn == 0)
        {
            command_fail(si, fault_badparams, "Invalid ASN specified.");
            return;
        }
        if (find_badasn(asn))
        {
            command_fail(si, fault_nochange, "ASN \2%u\2 is already blocked.", asn);
            return;
        }

        add_badasn_entry(asn, reason);
        save_geoip_db();
        command_success_nodata(si, "ASN \2%u\2 added to blocklist. Perform a \2GEOIP SCAN\2 to apply immediately.", asn);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:ADD:BADASN: \2%u\2 (Reason: %s)", asn, reason);
    }
    else
    {
        command_fail(si, fault_badparams, "Unknown type. Use BADCOUNTRY or BADASN.");
    }
}

static void
cmd_geoip_del(struct sourceinfo *si, int parc, char *parv[])
{
    char *type = parv[0];
    char *target = parv[1];

    /* SRA CHECK */
    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!type || !target)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP DEL");
        command_fail(si, fault_needmoreparams, _("Usage: GEOIP DEL BADCOUNTRY <CC>"));
        command_fail(si, fault_needmoreparams, _("       GEOIP DEL BADASN <ASN>"));
        return;
    }

    if (!strcasecmp(type, "BADCOUNTRY"))
    {
        struct badcountry *bc = find_badcountry(target);
        if (!bc)
        {
            command_fail(si, fault_nosuch_target, "Country \2%s\2 is not blocked.", target);
            return;
        }
        mowgli_node_delete(&bc->node, &badcountry_list);
        free(bc->iso_code);
        free(bc->reason);
        mowgli_free(bc);
        save_geoip_db();
        command_success_nodata(si, "Country \2%s\2 removed from blocklist.", target);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:DEL:BADCOUNTRY: \2%s\2", target);
    }
    else if (!strcasecmp(type, "BADASN"))
    {
        unsigned int asn = atoi(target);
        struct badasn *ba = find_badasn(asn);
        if (!ba)
        {
            command_fail(si, fault_nosuch_target, "ASN \2%u\2 is not blocked.", asn);
            return;
        }
        mowgli_node_delete(&ba->node, &badasn_list);
        free(ba->reason);
        mowgli_free(ba);
        save_geoip_db();
        command_success_nodata(si, "ASN \2%u\2 removed from blocklist.", asn);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:DEL:BADASN: \2%u\2", asn);
    }
}

static void
cmd_geoip_list(struct sourceinfo *si, int parc, char *parv[])
{
    mowgli_node_t *n;
    unsigned int count = 0;

    /* SRA CHECK */
    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    command_success_nodata(si, "GeoIP Blocklist (Countries):");
    MOWGLI_ITER_FOREACH(n, badcountry_list.head)
    {
        struct badcountry *bc = n->data;
        command_success_nodata(si, "%d: \2%s\2 - %s", ++count, bc->iso_code, bc->reason);
    }

    count = 0;
    command_success_nodata(si, "GeoIP Blocklist (ASNs):");
    MOWGLI_ITER_FOREACH(n, badasn_list.head)
    {
        struct badasn *ba = n->data;
        command_success_nodata(si, "%d: ASN \2%u\2 - %s", ++count, ba->asn, ba->reason);
    }
    command_success_nodata(si, "End of lists.");
}

/* Dispatch function for the parent GEOIP command */
static void
cmd_geoip_dispatch(struct sourceinfo *si, int parc, char *parv[])
{
    if (parc < 1)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP");
        command_fail(si, fault_needmoreparams, _("Available commands: ADD, DEL, LIST, EXEMPT, SCAN"));
        command_fail(si, fault_needmoreparams, _("Type \2/msg OperServ HELP GEOIP <command>\2 for more information."));
        return;
    }
    
    subcommand_dispatch_simple(si->service, si, parc, parv, geoip_cmds, "GEOIP");
}

/* --------------------------------------------------------------------- */
/* Module Init & Deinit */
/* --------------------------------------------------------------------- */

static struct command cmd_geoip_add_rec = {
    .name = "ADD",
    .desc = "Add a Country or ASN to the blocklist.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 3,
    .cmd = &cmd_geoip_add,
    .help = { .path = "oservice/geoip_add" }
};

static struct command cmd_geoip_del_rec = {
    .name = "DEL",
    .desc = "Remove a Country or ASN from the blocklist.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 2,
    .cmd = &cmd_geoip_del,
    .help = { .path = "oservice/geoip_del" }
};

static struct command cmd_geoip_list_rec = {
    .name = "LIST",
    .desc = "List blocked Countries and ASNs.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 0,
    .cmd = &cmd_geoip_list,
    .help = { .path = "oservice/geoip_list" }
};

static struct command cmd_geoip_exempt_rec = {
    .name = "EXEMPT",
    .desc = "Manage GeoIP exemptions/whitelist.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 3,
    .cmd = &cmd_geoip_exempt,
    .help = { .path = "oservice/geoip_exempt" }
};

static struct command cmd_geoip_scan_rec = {
    .name = "SCAN",
    .desc = "Scan all online users against GeoIP rules.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 0,
    .cmd = &cmd_geoip_scan,
    .help = { .path = "oservice/geoip_scan" }
};

static struct command cmd_geoip = {
    .name = "GEOIP",
    .desc = "Manage Country and ASN blocking.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 4,
    .cmd = &cmd_geoip_dispatch, /* Use dispatch function */
    .help = { .path = "oservice/geoip" }
};

void
mod_init(struct module *const restrict m)
{
    struct service *oserv = service_find("operserv");

    if (!oserv)
    {
        slog(LG_ERROR, "GEOIP: OperServ service not found!");
        m->mflags = MODFLAG_FAIL;
        return;
    }

    /* Create the subcommand table */
    geoip_cmds = mowgli_patricia_create(strcasecanon);

    /* Register Config Block */
    add_top_conf("GEOIP", geoip_config_handler);
    add_conf_item("COUNTRY_DB", &geoip_conf_table, conf_country_db);
    add_conf_item("ASN_DB", &geoip_conf_table, conf_asn_db);

    /* Register Commands to local table */
    command_add(&cmd_geoip_add_rec, geoip_cmds);
    command_add(&cmd_geoip_del_rec, geoip_cmds);
    command_add(&cmd_geoip_list_rec, geoip_cmds);
    command_add(&cmd_geoip_exempt_rec, geoip_cmds);
    command_add(&cmd_geoip_scan_rec, geoip_cmds);

    /* Register main command to OperServ's command table directly */
    command_add(&cmd_geoip, oserv->commands);

    /* Hook into user add */
    hook_add_hook("user_add", (void (*)(void *))check_user_hook);

    /* Setup Database Persistence (Keep hooks for safety, but rely on flatfile) */
    hook_add_db_write(write_geoip_db);
    db_register_type_handler("GEOIP_EXEMPT", db_h_geoip_exempt);
    db_register_type_handler("GEOIP_COUNTRY", db_h_geoip_country);
    db_register_type_handler("GEOIP_ASN", db_h_geoip_asn);

    /* Load Databases */
    const char *c_path = country_db_path ? country_db_path : "/var/lib/GeoIP/GeoLite2-Country.mmdb";
    const char *a_path = asn_db_path ? asn_db_path : "/var/lib/GeoIP/GeoLite2-ASN.mmdb";

    if (MMDB_open(c_path, MMDB_MODE_MMAP, &country_mmdb) == MMDB_SUCCESS)
    {
        slog(LG_INFO, "GeoIP: Country Database loaded from %s", c_path);
        country_db_loaded = true;
    }
    else
    {
        slog(LG_ERROR, "GeoIP: Failed to load Country DB from %s", c_path);
    }

    /* Soft fail for ASN */
    if (MMDB_open(a_path, MMDB_MODE_MMAP, &asn_mmdb) == MMDB_SUCCESS)
    {
        slog(LG_INFO, "GeoIP: ASN Database loaded from %s", a_path);
        asn_db_loaded = true;
    }
    else
    {
        slog(LG_INFO, "GeoIP: Warning: ASN Database not found at %s. ASN blocking disabled.", a_path);
    }
    
    /* LOAD DATA FROM FLATFILE */
    load_geoip_db();

    slog(LG_INFO, "GeoIP: Module loaded successfully.");
}

void
mod_deinit(const enum module_unload_intent intent)
{
    struct service *oserv = service_find("operserv");

    hook_del_hook("user_add", (void (*)(void *))check_user_hook);
    hook_del_db_write(write_geoip_db);
    db_unregister_type_handler("GEOIP_EXEMPT");
    db_unregister_type_handler("GEOIP_COUNTRY");
    db_unregister_type_handler("GEOIP_ASN");

    /* Delete subcommands from local table */
    command_delete(&cmd_geoip_add_rec, geoip_cmds);
    command_delete(&cmd_geoip_del_rec, geoip_cmds);
    command_delete(&cmd_geoip_list_rec, geoip_cmds);
    command_delete(&cmd_geoip_exempt_rec, geoip_cmds);
    command_delete(&cmd_geoip_scan_rec, geoip_cmds);

    /* Delete main command */
    if (oserv)
        command_delete(&cmd_geoip, oserv->commands);

    /* Destroy local table */
    mowgli_patricia_destroy(geoip_cmds, NULL, NULL);

    /* Remove Config items */
    del_top_conf("GEOIP");
    del_conf_item("COUNTRY_DB", &geoip_conf_table);
    del_conf_item("ASN_DB", &geoip_conf_table);

    if (country_db_loaded) MMDB_close(&country_mmdb);
    if (asn_db_loaded) MMDB_close(&asn_mmdb);

    /* Clean up lists */
    mowgli_node_t *n, *tn;
    
    MOWGLI_ITER_FOREACH_SAFE(n, tn, badcountry_list.head)
    {
        struct badcountry *bc = n->data;
        free(bc->iso_code);
        free(bc->reason);
        mowgli_free(bc);
    }

    MOWGLI_ITER_FOREACH_SAFE(n, tn, badasn_list.head)
    {
        struct badasn *ba = n->data;
        free(ba->reason);
        mowgli_free(ba);
    }

    MOWGLI_ITER_FOREACH_SAFE(n, tn, geoip_exempt_list.head)
    {
        struct geoip_exempt *e = n->data;
        free(e->mask);
        free(e->reason);
        free(e->setter);
        mowgli_free(e);
    }
}

DECLARE_MODULE_V1
(
    "operserv/geoip", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
    PACKAGE_STRING,
    "Atheme Development Group <http://www.atheme.org>"
);
