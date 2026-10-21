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
 * - Supports Regex (/^drone-[0-9]+$/) using POSIX extended regex
 *   (case-insensitive; no \d, \w or trailing /flags)
 * - Delete Regex by ID (e.g., DRONE DEL 1)
 * - Checks: Nick, Ident (User), IP, Host
 * - Persistent Flatfile Database (etc/drone.db)
 * - Requires the user:admin privilege
 * - Regex with Delimiters (/pattern/)
 * - K-Line via kline_add_user() (falls back to host when IP is unknown)
 * - Registered User / IRCop Protection (checked shortly after connect,
 *   once burst/SASL login and umodes have been applied)
 * - Hit Counters
 * - Buffered Save (No disk thrashing)
 * - Tab-delimited DB (Supports spaces in regex; reads legacy pipe format)
 * - Regex Error Reporting (Immediate feedback)
 * - DRONE TEST command
 * - DRONE SCAN (Dry Run by default, EXEC to ban)
 * - CONFIGURABLE DURATIONS (10m, 1h, 7d, perm)
 * - SINGLE-PASS SCANNING (High Performance)
 * - RULE MODIFICATION (Edit active rules)
 * - LAST HIT TRACKING (Identify stale rules)
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

/*
 * Which user field a rule is checked against. A mask may start with
 * "nick:", "ident:" (or "user:"), "host:" or "ip:" to check only that
 * field; masks without a prefix check all four, as before.
 */
enum drone_field {
    DRONE_FIELD_ANY = 0,
    DRONE_FIELD_NICK,
    DRONE_FIELD_IDENT,
    DRONE_FIELD_HOST,
    DRONE_FIELD_IP,
};

static const char *const drone_field_names[] = { "any", "nick", "ident", "host", "ip" };

/* Next stable rule ID to hand out; persisted in drone.db as "DN <id>". */
static unsigned int next_drone_id = 1;

/*
 * Exemptions: users matching one of these are never checked by any rule.
 * The mask is matched against nick!ident@host and nick!ident@ip when it
 * contains '!' or '@', else against the host and the IP. CIDR is accepted
 * (192.0.2.0/24, *!*@2001:db8::/32).
 */
struct drone_exempt {
    char *mask;
    char *reason;
    char *setter;
    time_t set_time;
    mowgli_node_t node;
};

static mowgli_list_t drone_exempt_list;

struct drone_entry {
    unsigned int id;     /* stable rule ID: never reused or renumbered */
    char *mask;          /* as entered, including any field prefix */
    const char *pattern; /* points into mask, after the prefix */
    enum drone_field field;
    char *reason;
    char *setter;
    time_t set_time;
    time_t last_hit; /* New: Timestamp of last match */
    long duration;
    unsigned int hits;
    regex_t *regex;
    mowgli_node_t node;
};

/* --------------------------------------------------------------------- */
/* Helper Functions */
/* --------------------------------------------------------------------- */

/*
 * Strictly parse a duration token. Accepts "perm", "permanent" or "0"
 * (permanent, stored as 0), or a positive integer with an optional single
 * unit suffix: s, m, h, d, w, y (e.g. "30", "10m", "7d").
 * Returns false if the string is not a duration at all, so callers can
 * tell a duration apart from the first word of a reason.
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

static void
format_duration(long duration, char *buf, size_t len)
{
    if (duration == 0)
        mowgli_strlcpy(buf, "Permanent", len);
    else
        snprintf(buf, len, "%ld sec", duration);
}

/*
 * Split an optional "field:" prefix off a mask. Sets *field and returns a
 * pointer to the pattern that follows. Unknown prefixes are not prefixes
 * (e.g. an IPv6 mask "2001:db8::*" stays a plain any-field mask).
 */
static const char *
parse_rule_target(const char *mask, enum drone_field *field)
{
    static const struct { const char *prefix; enum drone_field field; } prefixes[] = {
        { "nick:",  DRONE_FIELD_NICK  },
        { "ident:", DRONE_FIELD_IDENT },
        { "user:",  DRONE_FIELD_IDENT },
        { "host:",  DRONE_FIELD_HOST  },
        { "ip:",    DRONE_FIELD_IP    },
    };

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
    {
        size_t len = strlen(prefixes[i].prefix);
        if (!strncasecmp(mask, prefixes[i].prefix, len))
        {
            *field = prefixes[i].field;
            return mask + len;
        }
    }

    *field = DRONE_FIELD_ANY;
    return mask;
}

/* Copy the regex body out of "/body/" (the trailing slash is optional). */
static char *
regex_body(const char *pattern)
{
    char *body = sstrdup(pattern + 1);
    size_t len = strlen(body);
    if (len > 0 && body[len - 1] == '/')
        body[len - 1] = '\0';
    return body;
}

static bool
matches_entry(const struct drone_entry *d, const char *str)
{
    if (!str) return false;

    if (d->regex)
        return (regexec(d->regex, str, 0, NULL, 0) == 0);
    if (d->pattern[0] == '/')
        return false;   /* regex that failed to compile: never match */
    return (match(d->pattern, str) == 0);
}

/* Does this rule match this user, honouring its field prefix? */
static bool
user_matches_drone(const struct drone_entry *d, const struct user *u)
{
    switch (d->field)
    {
        case DRONE_FIELD_NICK:  return matches_entry(d, u->nick);
        case DRONE_FIELD_IDENT: return matches_entry(d, u->user);
        case DRONE_FIELD_HOST:  return matches_entry(d, u->host);
        case DRONE_FIELD_IP:    return matches_entry(d, u->ip);
        case DRONE_FIELD_ANY:
        default:
            return matches_entry(d, u->nick) || matches_entry(d, u->user) ||
                   matches_entry(d, u->ip)   || matches_entry(d, u->host);
    }
}

/* Build a rule without adding it to the list (used for ADD previews too). */
static struct drone_entry *
build_drone(const char *mask, const char *reason, const char *setter, time_t t, long duration, unsigned int hits, time_t last_hit)
{
    struct drone_entry *d = mowgli_alloc(sizeof(struct drone_entry));
    d->mask = sstrdup(mask);
    d->pattern = parse_rule_target(d->mask, &d->field);
    d->reason = sstrdup(reason);
    d->setter = sstrdup(setter);
    d->set_time = t;
    d->duration = duration;
    d->hits = hits;
    d->last_hit = last_hit;
    d->regex = NULL;

    if (d->pattern[0] == '/')
    {
        char *body = regex_body(d->pattern);

        d->regex = mowgli_alloc(sizeof(regex_t));
        if (regcomp(d->regex, body, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
            slog(LG_ERROR, "DRONE: invalid regex %s in rule list; it will never match", mask);
            mowgli_free(d->regex);
            d->regex = NULL;
        }
        free(body);
    }

    return d;
}

static void
free_drone(struct drone_entry *d)
{
    if (d->regex) {
        regfree(d->regex);
        mowgli_free(d->regex);
    }
    free(d->mask);
    free(d->reason);
    free(d->setter);
    mowgli_free(d);
}

/* Add a built rule to the list. id 0 = assign the next free stable ID. */
static void
insert_drone(struct drone_entry *d, unsigned int id)
{
    if (id == 0)
        id = next_drone_id;
    d->id = id;
    if (id >= next_drone_id)
        next_drone_id = id + 1;
    mowgli_node_add(d, &d->node, &drone_list);
}

static void
add_drone(const char *mask, const char *reason, const char *setter, time_t t, long duration, unsigned int hits, time_t last_hit, unsigned int id)
{
    insert_drone(build_drone(mask, reason, setter, t, duration, hits, last_hit), id);
}

/* A rule's stable ID, as shown by DRONE LIST and used by MOD/DEL. */
static unsigned int
drone_rule_id(const struct drone_entry *d)
{
    return d->id;
}

static struct drone_entry *
find_drone_by_id(unsigned int id)
{
    mowgli_node_t *n;
    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        if (d->id == id)
            return d;
    }
    return NULL;
}

static void
add_drone_exempt(const char *mask, const char *reason, const char *setter, time_t t)
{
    struct drone_exempt *e = mowgli_alloc(sizeof(struct drone_exempt));
    e->mask = sstrdup(mask);
    e->reason = sstrdup(reason);
    e->setter = sstrdup(setter);
    e->set_time = t;
    mowgli_node_add(e, &e->node, &drone_exempt_list);
}

static void
free_drone_exempt(struct drone_exempt *e)
{
    free(e->mask);
    free(e->reason);
    free(e->setter);
    mowgli_free(e);
}

static struct drone_exempt *
find_drone_exempt_mask(const char *mask)
{
    mowgli_node_t *n;
    MOWGLI_ITER_FOREACH(n, drone_exempt_list.head)
    {
        struct drone_exempt *e = n->data;
        if (!strcasecmp(e->mask, mask))
            return e;
    }
    return NULL;
}

/* Does one exemption mask cover this user? */
static bool
exempt_mask_matches(const char *mask, const struct user *u)
{
    char full[BUFSIZE];

    if (strchr(mask, '!') || strchr(mask, '@'))
    {
        snprintf(full, sizeof(full), "%s!%s@%s", u->nick, u->user, u->host);
        if (!match(mask, full))
            return true;
        if (u->ip)
        {
            snprintf(full, sizeof(full), "%s!%s@%s", u->nick, u->user, u->ip);
            if (!match(mask, full) || (strchr(mask, '/') && !match_cidr(mask, full)))
                return true;
        }
        return false;
    }

    if (!match(mask, u->host))
        return true;
    if (u->ip)
    {
        if (!match(mask, u->ip))
            return true;
        if (strchr(mask, '/'))
        {
            char cmask[BUFSIZE];
            snprintf(cmask, sizeof(cmask), "*@%s", mask);
            snprintf(full, sizeof(full), "x@%s", u->ip);
            if (!match_cidr(cmask, full))
                return true;
        }
    }
    return false;
}

static struct drone_exempt *
find_user_drone_exempt(const struct user *u)
{
    mowgli_node_t *n;
    MOWGLI_ITER_FOREACH(n, drone_exempt_list.head)
    {
        struct drone_exempt *e = n->data;
        if (exempt_mask_matches(e->mask, u))
            return e;
    }
    return NULL;
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

/* Renamed to avoid conflict with Atheme's built-in time_ago */
static void
render_time_ago(time_t t, char *buf, size_t len)
{
    if (t == 0) {
        snprintf(buf, len, "Never");
        return;
    }
    time_t diff = CURRTIME - t;
    if (diff < 60) snprintf(buf, len, "%lds ago", (long)diff);
    else if (diff < 3600) snprintf(buf, len, "%ldm ago", (long)diff / 60);
    else if (diff < 86400) snprintf(buf, len, "%ldh ago", (long)diff / 3600);
    else snprintf(buf, len, "%ldd ago", (long)diff / 86400);
}

/* --------------------------------------------------------------------- */
/* Persistence (Tab Delimited for Safety) */
/* --------------------------------------------------------------------- */

/*
 * Write to DRONE_DB_FILE.new and rename it over DRONE_DB_FILE, so a crash or
 * full disk mid-save leaves the previous database intact.
 */
static void
save_drone_db(void)
{
    const char *tmpfile = DRONE_DB_FILE ".new";
    FILE *f = fopen(tmpfile, "w");
    mowgli_node_t *n;

    if (!f) {
        slog(LG_ERROR, "DRONE: Could not open %s: %s", tmpfile, strerror(errno));
        return;
    }

    /*
     * Format:
     *   DN <next_id>
     *   DI <id>              (stable ID of the D line that follows)
     *   D <mask> \t <time> \t <setter> \t <hits> \t <duration> \t <last_hit> \t <reason>
     *   DE <mask> \t <time> \t <setter> \t <reason>   (exemption)
     * D lines are unchanged from older versions, which ignore DN/DI/DE lines,
     * so downgrading keeps every rule (only IDs and exemptions are lost).
     */
    fprintf(f, "DN %u\n", next_drone_id);

    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        fprintf(f, "DI %u\n", d->id);
        fprintf(f, "D %s\t%ld\t%s\t%u\t%ld\t%ld\t%s\n",
            d->mask, (long)d->set_time, d->setter, d->hits, d->duration, (long)d->last_hit, d->reason);
    }

    MOWGLI_ITER_FOREACH(n, drone_exempt_list.head)
    {
        struct drone_exempt *e = n->data;
        fprintf(f, "DE %s\t%ld\t%s\t%s\n", e->mask, (long)e->set_time, e->setter, e->reason);
    }

    bool failed = (fflush(f) != 0 || ferror(f) || fsync(fileno(f)) != 0);
    int saved_errno = errno;

    if (fclose(f) != 0 && !failed) {
        failed = true;
        saved_errno = errno;
    }

    if (failed) {
        slog(LG_ERROR, "DRONE: Error writing %s: %s; keeping old %s",
             tmpfile, strerror(saved_errno), DRONE_DB_FILE);
        (void) unlink(tmpfile);
        return;
    }

    if (srename(tmpfile, DRONE_DB_FILE) < 0) {
        slog(LG_ERROR, "DRONE: Could not rename %s to %s: %s",
             tmpfile, DRONE_DB_FILE, strerror(errno));
        (void) unlink(tmpfile);
    }
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
    char *type, *p1, *p2, *p3, *p4, *p5, *p6, *p7;
    unsigned int pending_id = 0;   /* from a preceding DI line */

    if (!f) return;

    while (fgets(line, sizeof(line), f))
    {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;

        /* Auto-detect delimiter: If tab exists, use tab. Else assume Pipe (Legacy Upgrade) */
        const char *delim = strchr(line, '\t') ? "\t" : "|";

        /* First token is space-separated "D " */
        type = strtok(line, " ");

        if (type && !strcasecmp(type, "DN"))
        {
            p1 = strtok(NULL, " ");
            unsigned long v = p1 ? strtoul(p1, NULL, 10) : 0;
            if (v > next_drone_id && v < UINT_MAX)
                next_drone_id = (unsigned int)v;
            continue;
        }
        if (type && !strcasecmp(type, "DI"))
        {
            p1 = strtok(NULL, " ");
            unsigned long v = p1 ? strtoul(p1, NULL, 10) : 0;
            pending_id = (v > 0 && v < UINT_MAX) ? (unsigned int)v : 0;
            continue;
        }
        if (type && !strcasecmp(type, "DE"))
        {
            p1 = strtok(NULL, "\t"); /* Mask */
            p2 = strtok(NULL, "\t"); /* Time */
            p3 = strtok(NULL, "\t"); /* Setter */
            p4 = strtok(NULL, "");    /* Reason */
            if (p1 && p2 && p3 && p4)
                add_drone_exempt(p1, p4, p3, (time_t)atol(p2));
            continue;
        }

        if (type && !strcasecmp(type, "D"))
        {
            /* Rest is Tab or Pipe separated */
            p1 = strtok(NULL, delim); /* Mask */
            p2 = strtok(NULL, delim); /* Time */
            p3 = strtok(NULL, delim); /* Setter */
            p4 = strtok(NULL, delim); /* Hits */
            p5 = strtok(NULL, delim); /* Duration */
            p6 = strtok(NULL, delim); /* Last Hit OR Reason (Legacy) */
            p7 = strtok(NULL, "");    /* Reason (New) OR NULL (Legacy) */
            
            if (p1 && p2 && p3 && p4 && p5) 
            {
                long dur = atol(p5);
                time_t lhit = 0;
                char *reason_str;

                if (p7) {
                    /* New Format (7 fields): p6 is LastHit, p7 is Reason */
                    lhit = (time_t)atol(p6);
                    reason_str = p7;
                } else {
                    /* Legacy Format (6 fields): p6 is Reason. LastHit defaults to 0 */
                    reason_str = p6; 
                }

                /*
                 * Rules from older versions have no DI line; they get IDs in
                 * file order (1, 2, 3, ...), the same numbers DRONE LIST used
                 * to show. An ID already in use is not reused.
                 */
                unsigned int id = pending_id;
                if (id && find_drone_by_id(id))
                    id = 0;
                add_drone(p1, reason_str, p3, (time_t)atol(p2), dur, (unsigned int)atoi(p4), lhit, id);
            }
        }
        pending_id = 0;
    }
    fclose(f);
    slog(LG_INFO, "DRONE: Database loaded from %s", DRONE_DB_FILE);
}

/* --------------------------------------------------------------------- */
/* Core Check Logic (Single Pass) */
/* --------------------------------------------------------------------- */

/*
 * K-Line a user unless an active K-Line already covers them.
 *
 * The user@host is chosen exactly as kline_add_user() does: the IP when
 * known, else the host (spoofed/hidden users, so we never send a NULL host),
 * with the ident only when kline_with_ident is set. Skipping already-covered
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
    char hostbuf[128];
    mowgli_node_t *n;

    /*
     * An IPv6 address like "::1" or "::ffff:192.0.2.1" starts with ':',
     * which IRC would read as the start of the final (trailing) parameter,
     * breaking the KLINE message. Prefix a 0 ("0::1"), the same address.
     */
    if (khost[0] == ':')
    {
        snprintf(hostbuf, sizeof(hostbuf), "0%s", khost);
        khost = hostbuf;
    }

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

/*
 * Why a user is never checked, or NULL if they are checked:
 * services' own clients, logged-in users, opers, and DRONE EXEMPT masks.
 */
static const char *
drone_exempt_reason(struct user *u, char *buf, size_t len)
{
    if (!u || is_internal_client(u)) return "services client";
    if (u->myuser != NULL)           return "logged in to services";
    if (is_ircop(u))                 return "IRC operator";

    struct drone_exempt *e = find_user_drone_exempt(u);
    if (e)
    {
        snprintf(buf, len, "exemption %s (%s)", e->mask, e->reason);
        return buf;
    }
    return NULL;
}

static bool
drone_user_exempt(struct user *u)
{
    char buf[BUFSIZE];
    return drone_exempt_reason(u, buf, sizeof(buf)) != NULL;
}

/* Return the first rule matching this user (honouring field prefixes). */
static struct drone_entry *
find_matching_drone(struct user *u)
{
    mowgli_node_t *n;

    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;

        if (user_matches_drone(d, u))
            return d;
    }

    return NULL;
}

/* Short duration for alerts and previews: "Perm", "7d", "2h", "90s". */
static void
compact_duration(long duration, char *buf, size_t len)
{
    if (duration == 0)          snprintf(buf, len, "Perm");
    else if (duration % 86400 == 0) snprintf(buf, len, "%ldd", duration / 86400);
    else if (duration % 3600 == 0)  snprintf(buf, len, "%ldh", duration / 3600);
    else if (duration % 60 == 0)    snprintf(buf, len, "%ldm", duration / 60);
    else                            snprintf(buf, len, "%lds", duration);
}

/*
 * Ban alerts, rate-limited.
 *
 * Each new K-Line is logged at LG_INFO, which goes to any logfile target that
 * includes "info" (e.g. logfile "#services" { ...; info; };). To keep a botnet
 * wave from flooding that channel, at most DRONE_ALERT_MAX lines are sent per
 * DRONE_ALERT_WINDOW seconds; the rest are counted and summarised in one line
 * when the window ends. Every ban is still logged at LG_DEBUG.
 */
#define DRONE_ALERT_WINDOW 10 /* seconds */
#define DRONE_ALERT_MAX    5

static time_t alert_window_start = 0;
static unsigned int alert_sent = 0;
static unsigned int alert_suppressed = 0;
static mowgli_eventloop_timer_t *alert_timer = NULL;

static void
alert_flush(void *unused)
{
    alert_timer = NULL;   /* one-shot timers are freed by mowgli after this returns */

    if (alert_suppressed)
    {
        slog(LG_INFO, "DRONE: %u more K-Line(s) in the last %ds not shown individually (see DRONE LIST hit counts)",
             alert_suppressed, DRONE_ALERT_WINDOW);
        alert_suppressed = 0;
    }
}

static void ATHEME_FATTR_PRINTF(1, 2)
drone_alert(const char *fmt, ...)
{
    char buf[BUFSIZE];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (CURRTIME - alert_window_start >= DRONE_ALERT_WINDOW)
    {
        if (alert_timer)
        {
            mowgli_timer_destroy(base_eventloop, alert_timer);
            alert_timer = NULL;
        }
        alert_flush(NULL);
        alert_window_start = CURRTIME;
        alert_sent = 0;
    }

    if (alert_sent < DRONE_ALERT_MAX)
    {
        alert_sent++;
        slog(LG_INFO, "%s", buf);
        return;
    }

    slog(LG_DEBUG, "%s", buf);
    alert_suppressed++;
    if (!alert_timer)
        alert_timer = mowgli_timer_add_once(base_eventloop, "drone_alert_flush", alert_flush, NULL,
                                            DRONE_ALERT_WINDOW - (CURRTIME - alert_window_start) + 1);
}

/* Returns true if a new K-Line was placed. */
static bool
enforce_drone(struct user *u, struct drone_entry *d)
{
    struct service *oserv = service_find("operserv");
    if (!oserv || !u || !d) return false;

    /* Update Statistics */
    d->hits++;
    d->last_hit = CURRTIME;

    char reason[BUFSIZE];
    snprintf(reason, sizeof(reason), "Blacklisted: %s", d->reason);

    if (kline_user_if_new(u, reason, d->duration, oserv->nick))
    {
        char dur[32];
        compact_duration(d->duration, dur, sizeof(dur));
        drone_alert("DRONE: K-Lined %s!%s@%s (%s) for %s by rule #%u %s: %s",
                    u->nick, u->user, u->host, u->ip ? u->ip : "no IP",
                    dur, drone_rule_id(d), d->mask, d->reason);
        return true;
    }

    slog(LG_DEBUG, "DRONE: %s (%s) matched %s but is already covered by a K-Line",
         u->nick, u->ip ? u->ip : u->host, d->mask);
    return false;
}

/*
 * Deferred checking.
 *
 * user_add fires before the protocol module applies the user's umodes and
 * any burst/SASL login, so u->myuser and is_ircop(u) are always false there.
 * We queue new users and check them a moment later, once that state is in.
 */
struct drone_pending {
    char *id;        /* UID if the IRCd uses them, else nick */
    time_t ts;       /* nick TS, used to detect nick reuse on non-UID IRCds */
    mowgli_node_t node;
};

static mowgli_list_t pending_list;
static mowgli_eventloop_timer_t *pending_timer = NULL;

#define DRONE_CHECK_DELAY 2 /* seconds */

static void
drone_pending_free(struct drone_pending *p)
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
        struct drone_pending *p = n->data;
        struct user *u = user_find(p->id);

        mowgli_node_delete(n, &pending_list);

        if (u && u->ts == p->ts && !drone_user_exempt(u))
        {
            struct drone_entry *d = find_matching_drone(u);
            if (d)
                enforce_drone(u, d);
        }

        drone_pending_free(p);
    }
}

static void
check_user_hook(void *data)
{
    struct hook_user_nick *hdata = data;
    struct user *u;

    if (!hdata) return;
    u = hdata->u;

    if (!u || is_internal_client(u)) return;
    if (!MOWGLI_LIST_LENGTH(&drone_list)) return;

    struct drone_pending *p = mowgli_alloc(sizeof(struct drone_pending));
    p->id = sstrdup(u->uid ? u->uid : u->nick);
    p->ts = u->ts;
    mowgli_node_add(p, &p->node, &pending_list);

    if (!pending_timer)
        pending_timer = mowgli_timer_add_once(base_eventloop, "drone_pending_check",
                                              pending_check_func, NULL, DRONE_CHECK_DELAY);
}

/* --------------------------------------------------------------------- */
/* Commands */
/* --------------------------------------------------------------------- */

/*
 * Broad-rule protection.
 *
 * A rule is refused (unless FORCE is given) when either
 *  - its pattern has fewer than DRONE_MIN_LITERALS letters/digits, so it is
 *    mostly wildcards ("*", "*a*", "/./", "/^[a-z]+$/"), or
 *  - it would match at least DRONE_BROAD_MIN_USERS currently online users and
 *    at least DRONE_BROAD_PERCENT of them, or DRONE_BROAD_MAX_USERS users.
 * Exempt users (logged in, opers, services) are not counted.
 */
#define DRONE_MIN_LITERALS     3
#define DRONE_BROAD_MIN_USERS  5
#define DRONE_BROAD_PERCENT    10
#define DRONE_BROAD_MAX_USERS  50

static unsigned int
count_literals(const char *pattern)
{
    unsigned int n = 0;
    bool escaped = false;

    for (const char *c = pattern; *c; c++)
    {
        if (escaped) { escaped = false; continue; }
        if (*c == '\\') { escaped = true; continue; }
        if (isalnum((unsigned char)*c)) n++;
    }
    return n;
}

static void
count_online_matches(const struct drone_entry *d, unsigned int *matched, unsigned int *total,
                     char *examples, size_t exlen)
{
    mowgli_patricia_iteration_state_t state;
    struct user *u;
    unsigned int shown = 0;

    *matched = *total = 0;
    examples[0] = '\0';

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        if (drone_user_exempt(u)) continue;
        (*total)++;

        if (!user_matches_drone(d, u)) continue;
        (*matched)++;

        if (shown < 5)
        {
            if (shown) mowgli_strlcat(examples, ", ", exlen);
            mowgli_strlcat(examples, u->nick, exlen);
            shown++;
        }
    }
}

static void
cmd_drone_add(struct sourceinfo *si, int parc, char *parv[])
{
    char restbuf[BUFSIZE];
    const char *target, *rest;
    const char *reason;
    long duration = DEFAULT_DURATION;
    long parsed;
    bool force = false;

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    /*
     * The parent DRONE command splits into at most 4 tokens, so here we get
     * up to 3: [FORCE] <mask> <rest-of-line>. Put the rest back together and
     * split "[duration] <reason>" from it ourselves.
     */
    if (parv[0] && !strcasecmp(parv[0], "FORCE")) {
        force = true;
        target = parv[1];
        rest = parv[2];
    } else {
        target = parv[0];
        if (parv[1] && parv[2]) {
            snprintf(restbuf, sizeof(restbuf), "%s %s", parv[1], parv[2]);
            rest = restbuf;
        } else {
            rest = parv[1];
        }
    }

    if (!target || !rest) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE ADD");
        command_fail(si, fault_needmoreparams, _("Usage: DRONE ADD [FORCE] <mask> [duration] <reason>"));
        return;
    }

    char first[BUFSIZE];
    mowgli_strlcpy(first, rest, sizeof(first));
    char *sp = strchr(first, ' ');
    if (sp) *sp = '\0';

    if (parse_duration(first, &parsed)) {
        const char *r = strchr(rest, ' ');
        while (r && *r == ' ') r++;
        if (!r || !*r) {
            command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE ADD");
            command_fail(si, fault_needmoreparams, _("If you specify a duration, you must provide a reason."));
            return;
        }
        duration = parsed;
        reason = r;
    } else {
        reason = rest;
    }

    if (strchr(target, '\t') || strchr(reason, '\t')) {
        command_fail(si, fault_badparams, "Masks and reasons may not contain tab characters.");
        return;
    }

    if (find_drone_mask(target)) {
        command_fail(si, fault_nochange, "Mask \2%s\2 is already in the drone list.", target);
        return;
    }

    enum drone_field field;
    const char *pattern = parse_rule_target(target, &field);

    if (!*pattern || !strcmp(pattern, "/") || !strcmp(pattern, "//")) {
        command_fail(si, fault_badparams, "Empty pattern in \2%s\2.", target);
        return;
    }

    /* PRE-VALIDATION */
    if (pattern[0] == '/')
    {
        char *body = regex_body(pattern);

        regex_t reg_check;
        int err = regcomp(&reg_check, body, REG_EXTENDED | REG_ICASE | REG_NOSUB);
        free(body);

        if (err != 0) {
            char errbuf[256];
            regerror(err, &reg_check, errbuf, sizeof(errbuf));
            command_fail(si, fault_badparams, "Invalid Regex: %s", errbuf);
            return;
        }
        regfree(&reg_check);
    }

    struct drone_entry *d = build_drone(target, reason, get_storage_oper_name(si), CURRTIME, duration, 0, 0);

    /* Broad-rule checks (see above). */
    unsigned int matched, total;
    char examples[BUFSIZE];
    count_online_matches(d, &matched, &total, examples, sizeof(examples));

    bool few_literals = count_literals(pattern) < DRONE_MIN_LITERALS;
    bool too_many = (matched >= DRONE_BROAD_MAX_USERS) ||
                    (matched >= DRONE_BROAD_MIN_USERS && matched * 100 >= total * DRONE_BROAD_PERCENT);

    if ((few_literals || too_many) && !force)
    {
        if (few_literals)
            command_fail(si, fault_badparams, "Rule \2%s\2 is too broad: its pattern has fewer than %d letters or digits.",
                         target, DRONE_MIN_LITERALS);
        if (too_many)
            command_fail(si, fault_badparams, "Rule \2%s\2 would match \2%u\2 of %u online users (e.g. %s).",
                         target, matched, total, examples);
        command_fail(si, fault_badparams, "Check it with \2DRONE TEST\2, or add it anyway with \2DRONE ADD FORCE %s ...\2",
                     target);
        free_drone(d);
        return;
    }

    insert_drone(d, 0);
    save_drone_db();

    char dur_buf[64];
    format_duration(duration, dur_buf, sizeof(dur_buf));

    command_success_nodata(si, "Added \2%s\2 to the Drone blacklist as ID \2%u\2 (%s, checks %s). Currently matches %u of %u online users.",
                           target, d->id, dur_buf, drone_field_names[field], matched, total);
    if (matched)
        command_success_nodata(si, "Use \2DRONE SCAN\2 to preview and \2DRONE SCAN EXEC\2 to ban users already online.");
    logcommand(si, CMDLOG_ADMIN, "DRONE:ADD%s: ID %u \2%s\2 (%s) Reason: %s", force ? ":FORCE" : "", d->id, target, dur_buf, reason);
}

static void
cmd_drone_mod(struct sourceinfo *si, int parc, char *parv[])
{
    char *target_id = parv[0];
    char *action = parv[1];
    char *value = parv[2];

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!target_id || !action || !value) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE MOD");
        command_fail(si, fault_needmoreparams, _("Usage: DRONE MOD <ID> <DURATION|REASON> <NewValue>"));
        return;
    }

    if (!is_numeric_string(target_id)) {
        command_fail(si, fault_badparams, "Target must be a numeric ID (check DRONE LIST).");
        return;
    }

    unsigned int id = (unsigned int)strtoul(target_id, NULL, 10);
    struct drone_entry *d = find_drone_by_id(id);
    if (!d) {
        command_fail(si, fault_nosuch_target, "Drone ID \2%u\2 not found.", id);
        return;
    }

    if (!strcasecmp(action, "DURATION") || !strcasecmp(action, "TIME")) {
        long new_dur;
        if (!parse_duration(value, &new_dur)) {
            command_fail(si, fault_badparams, "Invalid duration \2%s\2 (use e.g. 30, 10m, 1h, 7d, perm).", value);
            return;
        }
        d->duration = new_dur;

        char dur_buf[64];
        format_duration(new_dur, dur_buf, sizeof(dur_buf));

        command_success_nodata(si, "Updated ID \2%u\2 (%s) duration to: %s", id, d->mask, dur_buf);
        logcommand(si, CMDLOG_ADMIN, "DRONE:MOD:DURATION: ID %u (%s) -> %s", id, d->mask, dur_buf);
    }
    else if (!strcasecmp(action, "REASON")) {
        if (strchr(value, '\t')) {
            command_fail(si, fault_badparams, "Reasons may not contain tab characters.");
            return;
        }
        free(d->reason);
        d->reason = sstrdup(value);
        command_success_nodata(si, "Updated ID \2%u\2 (%s) reason to: %s", id, d->mask, d->reason);
        logcommand(si, CMDLOG_ADMIN, "DRONE:MOD:REASON: ID %u (%s) -> %s", id, d->mask, d->reason);
    }
    else {
        command_fail(si, fault_badparams, "Unknown action. Use DURATION or REASON.");
        return;
    }

    save_drone_db();
}

static void
cmd_drone_del(struct sourceinfo *si, int parc, char *parv[])
{
    char *target = parv[0];

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!target) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE DEL");
        return;
    }

    /* A number is a stable ID; anything else (or an unknown number) is a mask. */
    struct drone_entry *d = NULL;
    if (is_numeric_string(target))
        d = find_drone_by_id((unsigned int)strtoul(target, NULL, 10));
    if (!d)
        d = find_drone_mask(target);

    if (!d) {
        command_fail(si, fault_nosuch_target, "Target \2%s\2 not found.", target);
        return;
    }

    mowgli_node_delete(&d->node, &drone_list);

    command_success_nodata(si, "Removed \2%s\2 (ID: %u).", d->mask, d->id);
    logcommand(si, CMDLOG_ADMIN, "DRONE:DEL: \2%s\2 (ID: %u)", d->mask, d->id);

    free_drone(d);
    save_drone_db();
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

    /* If it is the nick of an online user, test that user properly first. */
    struct user *u = user_find_named(test_str);
    if (u && !is_internal_client(u))
    {
        struct drone_entry *d = find_matching_drone(u);

        char why_buf[BUFSIZE];
        const char *why = drone_exempt_reason(u, why_buf, sizeof(why_buf));

        if (!d)
            command_success_nodata(si, "User \2%s\2 (%s@%s, %s) matches no rule%s%s.",
                u->nick, u->user, u->host, u->ip ? u->ip : "no IP",
                why ? "; also exempt: " : "", why ? why : "");
        else if (why)
            command_success_nodata(si, "User \2%s\2 matches rule #%u \2%s\2 but is exempt: %s.",
                u->nick, drone_rule_id(d), d->mask, why);
        else
            command_success_nodata(si, "User \2%s\2 (%s@%s, %s) matches rule #%u \2%s\2 and would be K-Lined.",
                u->nick, u->user, u->host, u->ip ? u->ip : "no IP", drone_rule_id(d), d->mask);
    }

    /* Then test the plain string against every rule's pattern. */
    unsigned int idx = 0;
    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        idx++;
        if (matches_entry(d, test_str))
        {
            command_success_nodata(si, "MATCH: String \2%s\2 matches rule \2%s\2 (ID: %u, checks %s, set by %s)",
                test_str, d->mask, idx, drone_field_names[d->field], d->setter);
            return;
        }
    }

    command_success_nodata(si, "NO MATCH: String \2%s\2 matches no rule pattern.", test_str);
}

static void
cmd_drone_list(struct sourceinfo *si, int parc, char *parv[])
{
    const char *pattern = (parc > 0 && parv[0]) ? parv[0] : NULL;

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    mowgli_node_t *n;
    unsigned int shown = 0, total = 0;
    char buf[BUFSIZE];
    char ago_buf[64];
    struct tm tm;

    if (pattern)
        command_success_nodata(si, "Drone Blacklist (matching \2%s\2 in mask, reason or setter):", pattern);
    else
        command_success_nodata(si, "Drone Blacklist:");

    MOWGLI_ITER_FOREACH(n, drone_list.head)
    {
        struct drone_entry *d = n->data;
        total++;

        if (pattern && match(pattern, d->mask) && match(pattern, d->reason) && match(pattern, d->setter))
            continue;
        shown++;

        tm = *localtime(&d->set_time);
        strftime(buf, BUFSIZE, TIME_FORMAT, &tm);
        render_time_ago(d->last_hit, ago_buf, sizeof(ago_buf));

        char dur_str[32];
        compact_duration(d->duration, dur_str, sizeof(dur_str));

        command_success_nodata(si, "%u: \2%s\2 (Hits: %u) (Last: %s) (Dur: %s) (Set: %s on %s) - %s",
            d->id, d->mask, d->hits, ago_buf, dur_str, d->setter, buf, d->reason);
    }

    if (pattern)
        command_success_nodata(si, "End of list (%u of %u rules shown).", shown, total);
    else
        command_success_nodata(si, "End of list (%u rules).", total);
}

static void
cmd_drone_exempt(struct sourceinfo *si, int parc, char *parv[])
{
    char *action = parv[0];
    char *mask = parv[1];
    char *reason = parv[2];

    if (!is_sra(si->smu)) {
        command_fail(si, fault_noprivs, STR_NOT_AUTHORIZED);
        return;
    }

    if (!action)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE EXEMPT");
        command_fail(si, fault_needmoreparams, _("Usage: DRONE EXEMPT ADD <mask> <reason>"));
        command_fail(si, fault_needmoreparams, _("       DRONE EXEMPT DEL <mask|number>"));
        command_fail(si, fault_needmoreparams, _("       DRONE EXEMPT LIST"));
        return;
    }

    if (!strcasecmp(action, "ADD"))
    {
        if (!mask || !reason)
        {
            command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE EXEMPT ADD");
            command_fail(si, fault_needmoreparams, _("Usage: DRONE EXEMPT ADD <mask> <reason>"));
            return;
        }
        if (strchr(mask, '\t') || strchr(reason, '\t'))
        {
            command_fail(si, fault_badparams, "Masks and reasons may not contain tab characters.");
            return;
        }
        /* An exemption like "*" or "*@*" would switch the scanner off. */
        if (count_literals(mask) < DRONE_MIN_LITERALS)
        {
            command_fail(si, fault_badparams, "Exemption \2%s\2 is too broad: it needs at least %d letters or digits.",
                         mask, DRONE_MIN_LITERALS);
            return;
        }
        if (find_drone_exempt_mask(mask))
        {
            command_fail(si, fault_nochange, "Mask \2%s\2 is already exempted.", mask);
            return;
        }

        add_drone_exempt(mask, reason, get_storage_oper_name(si), CURRTIME);
        save_drone_db();

        /* Show how many online users this covers, as a sanity check. */
        mowgli_patricia_iteration_state_t state;
        struct user *u;
        unsigned int covered = 0;
        MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
        {
            if (!is_internal_client(u) && exempt_mask_matches(mask, u))
                covered++;
        }

        command_success_nodata(si, "Added \2%s\2 to the Drone exemption list. It currently covers %u online user(s).",
                               mask, covered);
        logcommand(si, CMDLOG_ADMIN, "DRONE:EXEMPT:ADD: \2%s\2 (Reason: %s)", mask, reason);
    }
    else if (!strcasecmp(action, "DEL"))
    {
        if (!mask)
        {
            command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE EXEMPT DEL");
            return;
        }

        struct drone_exempt *e = find_drone_exempt_mask(mask);
        if (!e && is_numeric_string(mask))
        {
            unsigned int want = (unsigned int)strtoul(mask, NULL, 10), idx = 0;
            mowgli_node_t *n;
            MOWGLI_ITER_FOREACH(n, drone_exempt_list.head)
            {
                if (++idx == want) { e = n->data; break; }
            }
        }
        if (!e)
        {
            command_fail(si, fault_nosuch_target, "Exemption \2%s\2 not found.", mask);
            return;
        }

        mowgli_node_delete(&e->node, &drone_exempt_list);
        command_success_nodata(si, "Removed \2%s\2 from the Drone exemption list.", e->mask);
        logcommand(si, CMDLOG_ADMIN, "DRONE:EXEMPT:DEL: \2%s\2", e->mask);
        free_drone_exempt(e);
        save_drone_db();
    }
    else if (!strcasecmp(action, "LIST"))
    {
        mowgli_node_t *n;
        unsigned int count = 0;
        char buf[BUFSIZE];
        struct tm tm;

        command_success_nodata(si, "Drone Exemption List:");
        MOWGLI_ITER_FOREACH(n, drone_exempt_list.head)
        {
            struct drone_exempt *e = n->data;
            tm = *localtime(&e->set_time);
            strftime(buf, BUFSIZE, TIME_FORMAT, &tm);
            command_success_nodata(si, "%u: \2%s\2 (Set by: %s on %s) - %s", ++count, e->mask, e->setter, buf, e->reason);
        }
        command_success_nodata(si, "End of list (%u exemptions).", count);
    }
    else
    {
        command_fail(si, fault_badparams, STR_INVALID_PARAMS, "DRONE EXEMPT");
        command_fail(si, fault_badparams, _("Use ADD, DEL or LIST."));
    }
}

struct drone_scan_hit {
    struct user *u;
    struct drone_entry *d;
    mowgli_node_t node;
};

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
    int new_klines = 0;

    logcommand(si, CMDLOG_ADMIN, "DRONE:SCAN:%s", execute ? "EXEC" : "TEST");
    command_success_nodata(si, "Scanning users against Drone blacklist (%s Mode)...", 
        execute ? "\2EXEC - BANNING\2" : "\2DRY RUN - REPORT ONLY\2");

    /*
     * Collect first, act second: we must not K-Line while iterating the
     * user list. Store the matching rule alongside each user.
     */
    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        if (drone_user_exempt(u)) continue;
        scanned++;

        struct drone_entry *d = find_matching_drone(u);
        if (d)
        {
            struct drone_scan_hit *h = mowgli_alloc(sizeof(struct drone_scan_hit));
            h->u = u;
            h->d = d;
            mowgli_node_add(h, &h->node, &victim_list);
        }
    }

    MOWGLI_ITER_FOREACH_SAFE(n, tn, victim_list.head)
    {
        struct drone_scan_hit *h = n->data;
        u = h->u;

        matches++;
        if (execute) {
            if (enforce_drone(u, h->d))
                new_klines++;
        } else
            command_success_nodata(si, "MATCH: \2%s\2 (%s@%s) matches rule \2%s\2",
                u->nick, u->user, u->ip ? u->ip : u->host, h->d->mask);

        mowgli_node_delete(n, &victim_list);
        mowgli_free(h);
    }

    if (execute)
        command_success_nodata(si, "Scan complete. Scanned: %d. Matched: %d. New K-Lines: %d.",
                               scanned, matches, new_klines);
    else
        command_success_nodata(si, "Dry Run complete. Scanned: %d. Found %d matches. (Use \2SCAN EXEC\2 to ban)", scanned, matches);
}

static void
cmd_drone_dispatch(struct sourceinfo *si, int parc, char *parv[])
{
    if (parc < 1) {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DRONE");
        command_fail(si, fault_needmoreparams, _("Available: ADD, MOD, DEL, LIST, EXEMPT, SCAN, TEST"));
        return;
    }
    subcommand_dispatch_simple(si->service, si, parc, parv, drone_cmds, "DRONE");
}

/* --------------------------------------------------------------------- */
/* Init / Deinit */
/* --------------------------------------------------------------------- */

static struct command cmd_drone_add_rec = {
    .name = "ADD", .desc = "Add a drone rule.", .access = PRIV_USER_ADMIN,
    .maxparc = 3, .cmd = &cmd_drone_add, .help = { .path = "oservice/drone" }
};
static struct command cmd_drone_mod_rec = {
    .name = "MOD", .desc = "Modify a drone rule.", .access = PRIV_USER_ADMIN,
    .maxparc = 3, .cmd = &cmd_drone_mod, .help = { .path = "oservice/drone" }
};
static struct command cmd_drone_del_rec = {
    .name = "DEL", .desc = "Remove a drone rule.", .access = PRIV_USER_ADMIN,
    .maxparc = 1, .cmd = &cmd_drone_del, .help = { .path = "oservice/drone" }
};
static struct command cmd_drone_list_rec = {
    .name = "LIST", .desc = "List drone rules (optionally matching a pattern).", .access = PRIV_USER_ADMIN,
    .maxparc = 1, .cmd = &cmd_drone_list, .help = { .path = "oservice/drone" }
};
static struct command cmd_drone_exempt_rec = {
    .name = "EXEMPT", .desc = "Manage drone exemptions.", .access = PRIV_USER_ADMIN,
    .maxparc = 3, .cmd = &cmd_drone_exempt, .help = { .path = "oservice/drone" }
};
static struct command cmd_drone_scan_rec = {
    .name = "SCAN", .desc = "Scan users (default: Dry Run).", .access = PRIV_USER_ADMIN,
    .maxparc = 1, .cmd = &cmd_drone_scan, .help = { .path = "oservice/drone" }
};
static struct command cmd_drone_test_rec = {
    .name = "TEST", .desc = "Test a string against rules.", .access = PRIV_USER_ADMIN,
    .maxparc = 1, .cmd = &cmd_drone_test, .help = { .path = "oservice/drone" }
};
static struct command cmd_drone = {
    .name = "DRONE", .desc = "Manage local IP blacklist.", .access = PRIV_USER_ADMIN,
    .maxparc = 4, .cmd = &cmd_drone_dispatch, .help = { .path = "oservice/drone" }
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
    command_add(&cmd_drone_mod_rec, drone_cmds); 
    command_add(&cmd_drone_del_rec, drone_cmds);
    command_add(&cmd_drone_list_rec, drone_cmds);
    command_add(&cmd_drone_scan_rec, drone_cmds);
    command_add(&cmd_drone_test_rec, drone_cmds);
    command_add(&cmd_drone_exempt_rec, drone_cmds); 
    command_add(&cmd_drone, oserv->commands);

    hook_add_hook("user_add", (void (*)(void *))check_user_hook);

    load_drone_db();

    save_timer = mowgli_timer_add(base_eventloop, "drone_save_db", 
                                  save_timer_func, NULL, 300);

    slog(LG_INFO, "DRONE: Module loaded (Buffered Save | Tab DB | Regex Check | Safe Scan | Duration | LastHit)");
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

    if (pending_timer) {
        mowgli_timer_destroy(base_eventloop, pending_timer);
        pending_timer = NULL;
    }

    mowgli_node_t *pn, *ptn;
    MOWGLI_ITER_FOREACH_SAFE(pn, ptn, pending_list.head) {
        mowgli_node_delete(pn, &pending_list);
        drone_pending_free(pn->data);
    }
    
    command_delete(&cmd_drone_add_rec, drone_cmds);
    command_delete(&cmd_drone_mod_rec, drone_cmds);
    command_delete(&cmd_drone_del_rec, drone_cmds);
    command_delete(&cmd_drone_list_rec, drone_cmds);
    command_delete(&cmd_drone_scan_rec, drone_cmds);
    command_delete(&cmd_drone_test_rec, drone_cmds);
    command_delete(&cmd_drone_exempt_rec, drone_cmds);

    if (oserv) command_delete(&cmd_drone, oserv->commands);

    mowgli_patricia_destroy(drone_cmds, NULL, NULL);

    mowgli_node_t *n, *tn;
    MOWGLI_ITER_FOREACH_SAFE(n, tn, drone_list.head) {
        mowgli_node_delete(n, &drone_list);
        free_drone(n->data);
    }

    MOWGLI_ITER_FOREACH_SAFE(n, tn, drone_exempt_list.head) {
        mowgli_node_delete(n, &drone_exempt_list);
        free_drone_exempt(n->data);
    }

    if (alert_timer) {
        mowgli_timer_destroy(base_eventloop, alert_timer);
        alert_timer = NULL;
    }
}

DECLARE_MODULE_V1
(
    "operserv/drone", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
    PACKAGE_STRING,
    "Atheme Development Group <http://www.atheme.org>"
);
