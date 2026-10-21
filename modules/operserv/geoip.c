/*
 * SPDX-License-Identifier: ISC
 *
 * modules/operserv/geoip.c
 * Services-side GeoIP & ASN Manager.
 *
 * Configuration (optional; put it AFTER the loadmodule line):
 *
 *   loadmodule "operserv/geoip";
 *
 *   geoip {
 *       country_db = "/var/lib/GeoIP/GeoLite2-Country.mmdb";
 *       asn_db     = "/var/lib/GeoIP/GeoLite2-ASN.mmdb";
 *       duration   = 1d;   (default K-Line length; 0 = permanent; default 24h)
 *   };
 *
 * The paths shown are the defaults. REHASH re-reads the block and reopens
 * the databases. Blocked countries/ASNs can also have their own duration:
 *   GEOIP ADD BADCOUNTRY XX 7d <reason>
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

/* geoip { duration = ...; } -- K-Line length for entries without their own */
#define GEOIP_BUILTIN_DURATION 86400U /* 24 hours */
static unsigned int geoip_default_duration = GEOIP_BUILTIN_DURATION;

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
/* duration: K-Line length in seconds, 0 = permanent, -1 = use geoip { duration } */
#define GEOIP_DURATION_DEFAULT (-1L)

struct badcountry {
    char *iso_code;
    char *reason;
    long duration;
    mowgli_node_t node;
};

struct badasn {
    unsigned int asn;
    char *reason;
    long duration;
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
/* Helper Functions (Defined early to avoid implicit declaration) */
/* --------------------------------------------------------------------- */

static bool
is_exempt(const char *ip)
{
    mowgli_node_t *n;
    if (!ip) return false;
    MOWGLI_ITER_FOREACH(n, geoip_exempt_list.head)
    {
        struct geoip_exempt *e = n->data;
        if (!match(e->mask, ip)) return true;
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
add_badcountry_entry(const char *iso, const char *reason, long duration)
{
    struct badcountry *bc = mowgli_alloc(sizeof(struct badcountry));
    bc->iso_code = sstrdup(iso);
    for (char *c = bc->iso_code; *c; c++)
        *c = toupper((unsigned char)*c);
    bc->reason = sstrdup(reason);
    bc->duration = duration;
    mowgli_node_add(bc, &bc->node, &badcountry_list);
}

static void
add_badasn_entry(unsigned int asn, const char *reason, long duration)
{
    struct badasn *ba = mowgli_alloc(sizeof(struct badasn));
    ba->asn = asn;
    ba->reason = sstrdup(reason);
    ba->duration = duration;
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
        if (!strcasecmp(bc->iso_code, iso)) return bc;
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
        if (ba->asn == asn) return ba;
    }
    return NULL;
}

/* Exact (case-insensitive) lookup of an exemption mask, for ADD/DEL. */
static struct geoip_exempt *
find_exempt_mask(const char *mask)
{
    mowgli_node_t *n;
    MOWGLI_ITER_FOREACH(n, geoip_exempt_list.head)
    {
        struct geoip_exempt *e = n->data;
        if (!strcasecmp(e->mask, mask)) return e;
    }
    return NULL;
}

/*
 * Strictly parse a duration token, same rules as operserv/drone:
 * "perm", "permanent" or "0" (permanent, 0), or a positive integer with an
 * optional single unit suffix s, m, h, d, w, y. Returns false if the token
 * is not a duration, so callers can tell it apart from the start of a reason.
 */
static bool
parse_duration(const char *s, long *out)
{
    char *endptr;
    long value, mult = 1;

    if (!s || !*s)
        return false;

    if (!strcasecmp(s, "perm") || !strcasecmp(s, "permanent") || !strcmp(s, "0")) {
        *out = 0;
        return true;
    }

    if (!isdigit((unsigned char)*s))
        return false;

    errno = 0;
    value = strtol(s, &endptr, 10);
    if (errno || value <= 0)
        return false;

    if (*endptr) {
        if (endptr[1] != '\0')
            return false;

        switch (tolower((unsigned char)*endptr)) {
            case 's': mult = 1; break;
            case 'm': mult = 60; break;
            case 'h': mult = 3600; break;
            case 'd': mult = 86400; break;
            case 'w': mult = 604800; break;
            case 'y': mult = 31536000; break;
            default: return false;
        }
    }

    if (value > LONG_MAX / mult)
        return false;

    *out = value * mult;
    return true;
}

/* Effective K-Line duration for an entry. */
static long
entry_duration(long duration)
{
    return duration == GEOIP_DURATION_DEFAULT ? (long)geoip_default_duration : duration;
}

/* Human-readable duration for LIST and confirmations. */
static void
format_entry_duration(long duration, char *buf, size_t len)
{
    long eff = entry_duration(duration);
    const char *suffix = (duration == GEOIP_DURATION_DEFAULT) ? " (default)" : "";

    if (eff == 0)
        snprintf(buf, len, "Permanent%s", suffix);
    else if (eff % 86400 == 0)
        snprintf(buf, len, "%ldd%s", eff / 86400, suffix);
    else if (eff % 3600 == 0)
        snprintf(buf, len, "%ldh%s", eff / 3600, suffix);
    else if (eff % 60 == 0)
        snprintf(buf, len, "%ldm%s", eff / 60, suffix);
    else
        snprintf(buf, len, "%lds%s", eff, suffix);
}

/*
 * Split "<duration> <reason...>" or "<reason...>" (the rest of the line).
 * On success *reason points into buf. Returns false (with an error already
 * sent) if a duration was given without a reason.
 */
static bool
split_duration_reason(struct sourceinfo *si, const char *cmdname, const char *rest,
                      char *buf, size_t buflen, long *duration, const char **reason)
{
    mowgli_strlcpy(buf, rest, buflen);

    char *sp = strchr(buf, ' ');
    if (sp) *sp = '\0';

    long parsed;
    if (parse_duration(buf, &parsed))
    {
        const char *r = sp ? sp + 1 : "";
        while (*r == ' ') r++;
        if (!*r)
        {
            command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, cmdname);
            command_fail(si, fault_needmoreparams, _("If you specify a duration, you must provide a reason."));
            return false;
        }
        *duration = parsed;
        *reason = r;
        return true;
    }

    if (sp) *sp = ' ';
    *duration = GEOIP_DURATION_DEFAULT;
    *reason = buf;
    return true;
}

/* --------------------------------------------------------------------- */
/* Persistence Functions (Flatfile) */
/* --------------------------------------------------------------------- */

/*
 * Write to GEOIP_DB_FILE.new and rename it over GEOIP_DB_FILE, so a crash or
 * full disk mid-save leaves the previous database intact.
 */
static void
save_geoip_db(void)
{
    const char *tmpfile = GEOIP_DB_FILE ".new";
    FILE *f = fopen(tmpfile, "w");
    mowgli_node_t *n;

    if (!f)
    {
        slog(LG_ERROR, "GEOIP: Could not open %s for writing: %s", tmpfile, strerror(errno));
        return;
    }

    MOWGLI_ITER_FOREACH(n, badcountry_list.head)
    {
        struct badcountry *bc = n->data;
        /* Entries using the default keep the original "C" record format;
         * entries with their own duration use "CD <iso> <secs> <reason>". */
        if (bc->duration == GEOIP_DURATION_DEFAULT)
            fprintf(f, "C %s %s\n", bc->iso_code, bc->reason);
        else
            fprintf(f, "CD %s %ld %s\n", bc->iso_code, bc->duration, bc->reason);
    }

    MOWGLI_ITER_FOREACH(n, badasn_list.head)
    {
        struct badasn *ba = n->data;
        if (ba->duration == GEOIP_DURATION_DEFAULT)
            fprintf(f, "A %u %s\n", ba->asn, ba->reason);
        else
            fprintf(f, "AD %u %ld %s\n", ba->asn, ba->duration, ba->reason);
    }

    MOWGLI_ITER_FOREACH(n, geoip_exempt_list.head)
    {
        struct geoip_exempt *e = n->data;
        fprintf(f, "E %s %ld %s %s\n", e->mask, (long)e->set_time, e->setter, e->reason);
    }

    bool failed = (fflush(f) != 0 || ferror(f) || fsync(fileno(f)) != 0);
    int saved_errno = errno;

    if (fclose(f) != 0 && !failed)
    {
        failed = true;
        saved_errno = errno;
    }

    if (failed)
    {
        slog(LG_ERROR, "GEOIP: Error writing %s: %s; keeping old %s",
             tmpfile, strerror(saved_errno), GEOIP_DB_FILE);
        (void) unlink(tmpfile);
        return;
    }

    if (srename(tmpfile, GEOIP_DB_FILE) < 0)
    {
        slog(LG_ERROR, "GEOIP: Could not rename %s to %s: %s",
             tmpfile, GEOIP_DB_FILE, strerror(errno));
        (void) unlink(tmpfile);
    }
}

static void
load_geoip_db(void)
{
    FILE *f = fopen(GEOIP_DB_FILE, "r");
    char line[BUFSIZE];
    char *type, *p1, *p2, *p3, *p4;

    if (!f) return;

    while (fgets(line, sizeof(line), f))
    {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;

        type = strtok(line, " ");
        if (!type) continue;

        if (!strcasecmp(type, "C"))
        {
            p1 = strtok(NULL, " ");
            p2 = strtok(NULL, "");
            if (p1 && p2) add_badcountry_entry(p1, p2, GEOIP_DURATION_DEFAULT);
        }
        else if (!strcasecmp(type, "CD"))
        {
            p1 = strtok(NULL, " ");
            p2 = strtok(NULL, " ");
            p3 = strtok(NULL, "");
            if (p1 && p2 && p3) add_badcountry_entry(p1, p3, atol(p2));
        }
        else if (!strcasecmp(type, "A"))
        {
            p1 = strtok(NULL, " ");
            p2 = strtok(NULL, "");
            if (p1 && p2) add_badasn_entry(strtoul(p1, NULL, 10), p2, GEOIP_DURATION_DEFAULT);
        }
        else if (!strcasecmp(type, "AD"))
        {
            p1 = strtok(NULL, " ");
            p2 = strtok(NULL, " ");
            p3 = strtok(NULL, "");
            if (p1 && p2 && p3) add_badasn_entry(strtoul(p1, NULL, 10), p3, atol(p2));
        }
        else if (!strcasecmp(type, "E"))
        {
            p1 = strtok(NULL, " ");
            p2 = strtok(NULL, " ");
            p3 = strtok(NULL, " ");
            p4 = strtok(NULL, "");
            if (p1 && p2 && p3 && p4) add_exempt(p1, p4, p3, (time_t)atol(p2));
        }
    }
    fclose(f);
    slog(LG_INFO, "GEOIP: Database loaded from %s", GEOIP_DB_FILE);
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

#define DEFAULT_COUNTRY_DB "/var/lib/GeoIP/GeoLite2-Country.mmdb"
#define DEFAULT_ASN_DB     "/var/lib/GeoIP/GeoLite2-ASN.mmdb"

/*
 * (Re)open one MaxMind database. On success the old handle (if any) is
 * replaced; on failure a previously loaded database is kept, so a typo in a
 * rehashed config does not silently switch GeoIP blocking off.
 */
static void
geoip_open_one(const char *what, const char *path, MMDB_s *db, bool *loaded, int fail_level)
{
    MMDB_s fresh;
    int status = MMDB_open(path, MMDB_MODE_MMAP, &fresh);

    if (status != MMDB_SUCCESS)
    {
        if (*loaded)
            slog(LG_ERROR, "GEOIP: Could not open %s DB %s (%s); keeping the previously loaded one",
                 what, path, MMDB_strerror(status));
        else
            slog(fail_level, "GEOIP: Could not open %s DB %s (%s); %s blocking disabled",
                 what, path, MMDB_strerror(status), what);
        return;
    }

    if (*loaded)
        MMDB_close(db);

    *db = fresh;
    *loaded = true;
    slog(LG_INFO, "GEOIP: %s DB loaded from %s", what, path);
}

static void
geoip_open_dbs(void)
{
    geoip_open_one("Country", country_db_path ? country_db_path : DEFAULT_COUNTRY_DB,
                   &country_mmdb, &country_db_loaded, LG_ERROR);
    geoip_open_one("ASN", asn_db_path ? asn_db_path : DEFAULT_ASN_DB,
                   &asn_mmdb, &asn_db_loaded, LG_INFO);
}

/*
 * Config lifecycle. Atheme runs a module's mod_init as soon as it reads the
 * loadmodule line, before the geoip { } block is parsed, so the databases
 * cannot be opened in mod_init. config_purge runs before every (re)parse and
 * config_ready after it; opening on config_ready means the configured paths
 * are used, and a REHASH also reopens the files (e.g. after geoipupdate).
 */
static void
geoip_config_purge(void *unused)
{
    free(country_db_path);
    free(asn_db_path);
    country_db_path = NULL;
    asn_db_path = NULL;

    /* Atheme only resets defaults for blocks that are present, so do it here:
     * removing "duration" (or the whole block) and rehashing restores 24h. */
    geoip_default_duration = GEOIP_BUILTIN_DURATION;
}

static void
geoip_config_ready(void *unused)
{
    geoip_open_dbs();
}

/* --------------------------------------------------------------------- */
/* Core Check Logic */
/* --------------------------------------------------------------------- */

/*
 * Returns the K-Line reason if the user's IP is in a blocked country or ASN
 * (and not exempted), else NULL. *duration gets the K-Line length to use.
 * The returned string is a static buffer.
 */
static const char *
get_geoip_ban_reason(struct user *u, long *duration)
{
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;
    static char reason[BUFSIZE];

    if (!u || is_internal_client(u) || !u->ip) return NULL;

    if (is_exempt(u->ip)) return NULL;

    /* Check Country */
    if (country_db_loaded)
    {
        result = MMDB_lookup_string(&country_mmdb, u->ip, &gai_error, &mmdb_error);
        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && result.found_entry)
        {
            if (MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL) == MMDB_SUCCESS)
            {
                if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING &&
                    entry_data.data_size == 2)
                {
                    char iso_code[3];
                    memset(iso_code, 0, sizeof(iso_code));
                    memcpy(iso_code, entry_data.utf8_string, 2);

                    struct badcountry *bc = find_badcountry(iso_code);
                    if (bc)
                    {
                        snprintf(reason, sizeof(reason), "Country banned (%s): %s", bc->iso_code, bc->reason);
                        *duration = entry_duration(bc->duration);
                        return reason;
                    }
                }
            }
        }
    }

    /* Check ASN */
    if (asn_db_loaded)
    {
        result = MMDB_lookup_string(&asn_mmdb, u->ip, &gai_error, &mmdb_error);
        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && result.found_entry)
        {
            if (MMDB_get_value(&result.entry, &entry_data, "autonomous_system_number", NULL) == MMDB_SUCCESS)
            {
                if (entry_data.has_data && (entry_data.type == MMDB_DATA_TYPE_UINT32 || entry_data.type == MMDB_DATA_TYPE_UINT16))
                {
                    /* Read the union member that matches the stored type. */
                    unsigned int asn = (entry_data.type == MMDB_DATA_TYPE_UINT16)
                                       ? entry_data.uint16 : entry_data.uint32;
                    struct badasn *ba = find_badasn(asn);
                    if (ba)
                    {
                        snprintf(reason, sizeof(reason), "ASN banned (%u): %s", asn, ba->reason);
                        *duration = entry_duration(ba->duration);
                        return reason;
                    }
                }
            }
        }
    }

    return NULL;
}

/*
 * K-Line a user unless an active K-Line already covers them.
 *
 * The user@host is chosen exactly as kline_add_user() does (IP when known,
 * else host; ident only with kline_with_ident). Skipping already-covered
 * targets stops a scan, or a fast-reconnecting botnet, from piling up
 * identical K-Lines. Returns true if a new K-Line was added.
 */
static bool
kline_user_if_new(struct user *u, const char *reason, long duration, const char *setby)
{
    bool use_ident = config_options.kline_with_ident &&
                     (!config_options.kline_verified_ident || *u->user != '~');
    const char *kuser = use_ident ? u->user : "*";
    const char *khost = u->ip ? u->ip : u->host;
    mowgli_node_t *n;

    MOWGLI_ITER_FOREACH(n, klnlist.head)
    {
        struct kline *k = n->data;

        if (k->duration && k->expires <= CURRTIME)
            continue;   /* expired, not yet purged */

        if (!match(k->user, kuser) && !match(k->host, khost))
            return false;
    }

    kline_add(kuser, khost, reason, duration, setby);
    return true;
}

/* Returns true if a new K-Line was placed. */
static bool
enforce_geoip(struct user *u, const char *reason, long duration)
{
    struct service *oserv = service_find("operserv");
    if (!oserv || !u || !reason) return false;

    /*
     * We ONLY place the K-Line, we do NOT call kill_user().
     * The IRCd will see the new K-Line, check the user against it, and perform the kill itself.
     * This avoids race conditions in Atheme and eliminates the assertion warning.
     */
    if (kline_user_if_new(u, reason, duration, oserv->nick))
    {
        slog(LG_INFO, "GEOIP: Klining user %s (%s) -> %s", u->nick, u->ip, reason);
        return true;
    }

    slog(LG_DEBUG, "GEOIP: %s (%s) matched (%s) but is already covered by a K-Line",
         u->nick, u->ip, reason);
    return false;
}

/* Users that are never checked: services' own clients, logged-in users, opers. */
static bool
geoip_user_exempt(struct user *u)
{
    return (!u || is_internal_client(u) || u->myuser != NULL || is_ircop(u));
}

/*
 * Deferred checking.
 *
 * user_add fires before the protocol module applies the user's umodes and
 * any burst/SASL login, so u->myuser and is_ircop(u) are always false there.
 * We queue new users and check them a moment later, once that state is in.
 */
struct geoip_pending {
    char *id;        /* UID if the IRCd uses them, else nick */
    time_t ts;       /* nick TS, used to detect nick reuse on non-UID IRCds */
    mowgli_node_t node;
};

static mowgli_list_t pending_list;
static mowgli_eventloop_timer_t *pending_timer = NULL;

#define GEOIP_CHECK_DELAY 2 /* seconds */

static void
geoip_pending_free(struct geoip_pending *p)
{
    free(p->id);
    mowgli_free(p);
}

static void
pending_check_func(void *unused)
{
    mowgli_node_t *n, *tn;

    /* One-shot timers are released by mowgli after this callback returns. */
    pending_timer = NULL;

    MOWGLI_ITER_FOREACH_SAFE(n, tn, pending_list.head)
    {
        struct geoip_pending *p = n->data;
        struct user *u = user_find(p->id);

        mowgli_node_delete(n, &pending_list);

        if (u && u->ts == p->ts && !geoip_user_exempt(u))
        {
            long duration;
            const char *reason = get_geoip_ban_reason(u, &duration);
            if (reason)
                (void) enforce_geoip(u, reason, duration);
        }

        geoip_pending_free(p);
    }
}

static void
check_user_hook(void *data)
{
    struct hook_user_nick *hdata = data;
    struct user *u;

    if (!hdata) return;
    u = hdata->u;

    if (!u || is_internal_client(u) || !u->ip) return;
    if (!country_db_loaded && !asn_db_loaded) return;
    if (!MOWGLI_LIST_LENGTH(&badcountry_list) && !MOWGLI_LIST_LENGTH(&badasn_list)) return;

    struct geoip_pending *p = mowgli_alloc(sizeof(struct geoip_pending));
    p->id = sstrdup(u->uid ? u->uid : u->nick);
    p->ts = u->ts;
    mowgli_node_add(p, &p->node, &pending_list);

    if (!pending_timer)
        pending_timer = mowgli_timer_add_once(base_eventloop, "geoip_pending_check",
                                              pending_check_func, NULL, GEOIP_CHECK_DELAY);
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

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    /* Dry run by default, like DRONE SCAN; EXEC actually places K-Lines. */
    bool execute = false;
    if (parc > 0 && parv[0])
    {
        if (strcasecmp(parv[0], "EXEC"))
        {
            command_fail(si, fault_badparams, STR_INVALID_PARAMS, "GEOIP SCAN");
            command_fail(si, fault_badparams, _("Syntax: GEOIP SCAN [EXEC]"));
            return;
        }
        execute = true;
    }

    logcommand(si, CMDLOG_ADMIN, "GEOIP:SCAN:%s", execute ? "EXEC" : "TEST");
    command_success_nodata(si, "Scanning users against GeoIP rules (%s Mode)...",
        execute ? "\2EXEC - BANNING\2" : "\2DRY RUN - REPORT ONLY\2");

    /* Collect first, act second: we must not K-Line while iterating the user list. */
    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        if (geoip_user_exempt(u)) continue;
        scanned++;

        long duration;
        if (get_geoip_ban_reason(u, &duration))
        {
            mowgli_node_add(u, mowgli_node_create(), &victim_list);
        }
    }

    int matched_count = 0, banned_count = 0;
    MOWGLI_ITER_FOREACH_SAFE(n, tn, victim_list.head)
    {
        u = (struct user *)n->data;

        long duration;
        const char *reason = get_geoip_ban_reason(u, &duration);
        if (reason) {
            matched_count++;
            if (execute) {
                if (enforce_geoip(u, reason, duration))
                    banned_count++;
            } else {
                command_success_nodata(si, "MATCH: \2%s\2 (%s) -> %s", u->nick, u->ip, reason);
            }
        }

        mowgli_node_delete(n, &victim_list);
        mowgli_node_free(n);
    }

    if (execute)
        command_success_nodata(si, "GeoIP Scan complete. Scanned: %d. Matched: %d. New K-Lines: %d.",
                               scanned, matched_count, banned_count);
    else
        command_success_nodata(si, "Dry Run complete. Scanned: %d. Found %d matches. (Use \2GEOIP SCAN EXEC\2 to ban)",
                               scanned, matched_count);
}

static void
cmd_geoip_exempt(struct sourceinfo *si, int parc, char *parv[])
{
    char *action = parv[0];
    char *mask = parv[1];
    char *reason = parv[2];
    mowgli_node_t *n, *tn;

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

        /* Compare masks as text: is_exempt() treats its argument as an IP,
         * which gave wrong answers when the new entry is itself a mask. */
        if (find_exempt_mask(mask))
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
    char *rest = parv[2];
    char buf[BUFSIZE];
    const char *reason;
    long duration;
    char dur_buf[64];

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!type || !target || !rest)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GEOIP ADD");
        command_fail(si, fault_needmoreparams, _("Usage: GEOIP ADD BADCOUNTRY <CC> [duration] <Reason>"));
        command_fail(si, fault_needmoreparams, _("       GEOIP ADD BADASN <ASN> [duration] <Reason>"));
        return;
    }

    if (!split_duration_reason(si, "GEOIP ADD", rest, buf, sizeof(buf), &duration, &reason))
        return;

    if (!strcasecmp(type, "BADCOUNTRY"))
    {
        if (strlen(target) != 2 || !isalpha((unsigned char)target[0]) || !isalpha((unsigned char)target[1]))
        {
            command_fail(si, fault_badparams, "Country code must be exactly 2 letters (ISO 3166-1 alpha-2).");
            return;
        }
        if (find_badcountry(target))
        {
            command_fail(si, fault_nochange, "Country \2%s\2 is already blocked.", target);
            return;
        }

        add_badcountry_entry(target, reason, duration);
        save_geoip_db();
        format_entry_duration(duration, dur_buf, sizeof(dur_buf));

        struct badcountry *bc = find_badcountry(target);
        command_success_nodata(si, "Country \2%s\2 added to blocklist (%s). Perform a \2GEOIP SCAN\2 to preview, \2GEOIP SCAN EXEC\2 to apply now.",
                               bc->iso_code, dur_buf);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:ADD:BADCOUNTRY: \2%s\2 (%s) (Reason: %s)", bc->iso_code, dur_buf, reason);
    }
    else if (!strcasecmp(type, "BADASN"))
    {
        /* Accept "7018" or "AS7018". */
        const char *num = target;
        if (!strncasecmp(num, "AS", 2))
            num += 2;

        char *end;
        errno = 0;
        unsigned long asn = strtoul(num, &end, 10);
        if (!isdigit((unsigned char)*num) || *end || errno || asn == 0 || asn > UINT_MAX)
        {
            command_fail(si, fault_badparams, "Invalid ASN \2%s\2 (use a number such as 7018 or AS7018).", target);
            return;
        }
        if (find_badasn((unsigned int)asn))
        {
            command_fail(si, fault_nochange, "ASN \2%lu\2 is already blocked.", asn);
            return;
        }

        add_badasn_entry((unsigned int)asn, reason, duration);
        save_geoip_db();
        format_entry_duration(duration, dur_buf, sizeof(dur_buf));
        command_success_nodata(si, "ASN \2%lu\2 added to blocklist (%s). Perform a \2GEOIP SCAN\2 to preview, \2GEOIP SCAN EXEC\2 to apply now.",
                               asn, dur_buf);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:ADD:BADASN: \2%lu\2 (%s) (Reason: %s)", asn, dur_buf, reason);
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
        /* Accept "7018" or "AS7018", matching ADD. */
        const char *num = target;
        if (!strncasecmp(num, "AS", 2))
            num += 2;
        unsigned int asn = (unsigned int)strtoul(num, NULL, 10);
        struct badasn *ba = find_badasn(asn);
        if (!ba)
        {
            command_fail(si, fault_nosuch_target, "ASN \2%s\2 is not blocked.", target);
            return;
        }
        mowgli_node_delete(&ba->node, &badasn_list);
        free(ba->reason);
        mowgli_free(ba);
        save_geoip_db();
        command_success_nodata(si, "ASN \2%u\2 removed from blocklist.", asn);
        logcommand(si, CMDLOG_ADMIN, "GEOIP:DEL:BADASN: \2%u\2", asn);
    }
    else
    {
        command_fail(si, fault_badparams, "Unknown type. Use BADCOUNTRY or BADASN.");
    }
}

static void
cmd_geoip_list(struct sourceinfo *si, int parc, char *parv[])
{
    mowgli_node_t *n;
    unsigned int count = 0;

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    command_success_nodata(si, "GeoIP Blocklist (Countries):");
    MOWGLI_ITER_FOREACH(n, badcountry_list.head)
    {
        struct badcountry *bc = n->data;
        char dur_buf[64];
        format_entry_duration(bc->duration, dur_buf, sizeof(dur_buf));
        command_success_nodata(si, "%d: \2%s\2 (%s) - %s", ++count, bc->iso_code, dur_buf, bc->reason);
    }

    count = 0;
    command_success_nodata(si, "GeoIP Blocklist (ASNs):");
    MOWGLI_ITER_FOREACH(n, badasn_list.head)
    {
        struct badasn *ba = n->data;
        char dur_buf[64];
        format_entry_duration(ba->duration, dur_buf, sizeof(dur_buf));
        command_success_nodata(si, "%d: ASN \2%u\2 (%s) - %s", ++count, ba->asn, dur_buf, ba->reason);
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
    .help = { .path = "oservice/geoip" }
};

static struct command cmd_geoip_del_rec = {
    .name = "DEL",
    .desc = "Remove a Country or ASN from the blocklist.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 2,
    .cmd = &cmd_geoip_del,
    .help = { .path = "oservice/geoip" }
};

static struct command cmd_geoip_list_rec = {
    .name = "LIST",
    .desc = "List blocked Countries and ASNs.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 0,
    .cmd = &cmd_geoip_list,
    .help = { .path = "oservice/geoip" }
};

static struct command cmd_geoip_exempt_rec = {
    .name = "EXEMPT",
    .desc = "Manage GeoIP exemptions/whitelist.",
    .access = PRIV_USER_ADMIN,
    .maxparc = 3,
    .cmd = &cmd_geoip_exempt,
    .help = { .path = "oservice/geoip" }
};

static struct command cmd_geoip_scan_rec = {
    .name = "SCAN",
    .desc = "Scan online users against GeoIP rules (dry run; EXEC to ban).",
    .access = PRIV_USER_ADMIN,
    .maxparc = 1,
    .cmd = &cmd_geoip_scan,
    .help = { .path = "oservice/geoip" }
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
    add_duration_conf_item("DURATION", &geoip_conf_table, 0, &geoip_default_duration, "s", GEOIP_BUILTIN_DURATION);

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

    /*
     * Open the MaxMind databases once the config is fully parsed (and again
     * on every REHASH), so geoip { country_db; asn_db; } is honoured.
     */
    hook_add_config_purge(geoip_config_purge);
    hook_add_config_ready(geoip_config_ready);

    /*
     * Loaded at runtime (MODLOAD) rather than at startup: config_ready will
     * not fire until the next REHASH, so open the databases now. The
     * geoip { } block is only read on that REHASH; until then the default
     * paths are used.
     */
    if (!cold_start)
        geoip_open_dbs();

    /* LOAD DATA FROM FLATFILE */
    load_geoip_db();

    slog(LG_INFO, "GeoIP: Module loaded successfully.");
}

void
mod_deinit(const enum module_unload_intent intent)
{
    struct service *oserv = service_find("operserv");

    hook_del_hook("user_add", (void (*)(void *))check_user_hook);
    hook_del_config_purge(geoip_config_purge);
    hook_del_config_ready(geoip_config_ready);

    if (pending_timer)
    {
        mowgli_timer_destroy(base_eventloop, pending_timer);
        pending_timer = NULL;
    }

    mowgli_node_t *pn, *ptn;
    MOWGLI_ITER_FOREACH_SAFE(pn, ptn, pending_list.head)
    {
        mowgli_node_delete(pn, &pending_list);
        geoip_pending_free(pn->data);
    }

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
    del_conf_item("DURATION", &geoip_conf_table);

    if (country_db_loaded) MMDB_close(&country_mmdb);
    if (asn_db_loaded) MMDB_close(&asn_mmdb);
    country_db_loaded = asn_db_loaded = false;

    free(country_db_path);
    free(asn_db_path);
    country_db_path = asn_db_path = NULL;

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
