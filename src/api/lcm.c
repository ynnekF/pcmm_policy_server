#include "lcm.h"

/*
 * There should only be a single LCM defined when running in server mode. To prevent race
 * conditions within the LCM, this lock has been defined to lock shared LCM resources (client
 * list, coutner, etc.)
 */
static pthread_mutex_t lcm_internal_lock;

#if defined(RCFILE)

#define RC      ".connectrc"
#define RC_COL0 "count"
#define RC_COL1 "cmts_ip"
#define RC_COL2 "handle"
#define RC_OK   F_OK
#define RC_IC   1

static int rcw_hdr(void);
static int rcw_row(uint8_t id, ps_session_t* ps);
static int rc_init(void);

static struct {
        const char rcp[200];
} glob_rc;

static int
rcw_hdr(void) {
#define H_FMT "%s,%s\n"

        FILE* fp = fopen(glob_rc.rcp, "w");

        if (fp == NULL)
                return RC_IC;

        if (fprintf(fp, H_FMT, RC_COL0, RC_COL1) < 0)
                return RC_IC;

        fflush(fp);
        fclose(fp);

        return RC_OK;
}

static int
rcw_row(uint8_t id, ps_session_t* ps) {
#define R_FMT "%i,%s\n"

        FILE* fp = fopen(glob_rc.rcp, "a");
        if (fp == NULL)
                return RC_IC;

        if (fprintf(fp, R_FMT, id, ps->cmts_addr) < 0)
                return RC_IC;

        fflush(fp);
        fclose(fp);

        return RC_OK;
}

static int
rc_init(void) {
        size_t filename_sz = strlen(RC);
        char cwd[100];
        char rcp[sizeof(cwd) + filename_sz];

        memset(cwd, 0, sizeof(cwd));
        memset(rcp, 0, sizeof(rcp));
        getcwd(cwd, sizeof(cwd));

        strncat(rcp, cwd, sizeof(rcp) + filename_sz - strlen(rcp) - 1);
        strncat(rcp, "/data/", sizeof(char) * 6 + 1);
        strncat(rcp, RC, filename_sz);

        if (access(rcp, F_OK) == 0) {
                debug("resource control file exists, attempting purge");

                fclose(fopen(rcp, "w"));
        }

        memcpy((char*)glob_rc.rcp, rcp, sizeof(rcp));

        if (rcw_hdr() == RC_IC) {
                error("failed to write rc header row");

                return RC_IC;
        }
        return RC_OK;
}
#endif

/*
 * LCM Helper function which logs the given string, the current errno's description and any
 * other variable args. passed in. Then returns NULL. Just here to reduce dup. code
 *
 * @str Char. array we want written to the error log.
 * @... Variable arguments - if the `str` contains a format type, this can be used to populate it.
 */
static void* lcm_mutex_lock_err(char* str, ...);

static void*
lcm_mutex_lock_err(char* str, ...) {
        va_list args;
        va_start(args, str);

        error(str, args);
        error("detail: %i (%s)", errno, strerror(errno));

        va_end(args);
        return NULL;
}

lcm_t*
lcm_init(int maxpep) {
#if defined(RCFILE)
        /*
         * Initialize the connect RC file - if it exists, open and close it to remove all existing
         * contents, otherwise continue to write the header row, if successful continue with init.
         */
        if (rc_init() != F_OK)
                error("failed to intitalize rc file: %i::%i", errno, strerror(errno));
#endif

        lcm_t* self = ALLOC_T(lcm_t);

        self->maxpep = maxpep;
        self->count = 0;

        if (maxpep > MAXROOM) {
                fatal("max. cmts connections exceeding hard limit.");

                return NULL;
        }

        if (pthread_mutex_init(&lcm_internal_lock, NULL) != 0)
                return lcm_mutex_lock_err("failed to init lcm lock");

        info("initialized local connection manager");
        return self;
}

ps_session_t*
lcm_getps(lcm_t* self, const char* ip) {
        if (!self) {
                error("lcm query attempt without lcm");
                return NULL;
        }

        ps_session_t* ps = NULL;
        int err;

        if ((err = pthread_mutex_lock(&lcm_internal_lock)) != 0) {
                pthread_mutex_unlock(&lcm_internal_lock);

                return lcm_mutex_lock_err("failed to acquire lcm lock (code=%i)", err);
        }

        /*
         * Mutex acquired - check current LCM size. If the current size of our ONLY
         * LCM object is zero, return NULL, indicating no client (w/ ip) was found.
         */
        if (self->count == 0) {
                pthread_mutex_unlock(&lcm_internal_lock);

                return ps;
        }

        for (size_t i = 0; i < self->count; i++) {
                ps_session_t* temp = self->clients[i];

                if ((err = pthread_mutex_lock(&temp->evnt_lock)) != 0) {
                        /*
                         * Failed to acquire the client's event lock and process didn't block
                         * until it was available, unlock if possible and return NULL.
                         */
                        pthread_mutex_unlock(&temp->evnt_lock);
                        return lcm_mutex_lock_err("failed to acquire event lock (code=%i)", err);
                }

                if (!temp->cmts_addr || !ip) {
                        /*
                         * Encountered a NULL IP address in either the client or the given target.
                         * It's possible the client was destroyed somehow. Log and continue.
                         */
                        warning("encountered null cmts ip at pos=%i", i);
                        pthread_mutex_unlock(&temp->evnt_lock);
                        continue;
                }

                if (strcmp(temp->cmts_addr, ip) == 0) {
                        ps = temp;
                        pthread_mutex_unlock(&temp->evnt_lock);
                        break;
                }

                pthread_mutex_unlock(&temp->evnt_lock);
        }
        pthread_mutex_unlock(&lcm_internal_lock);

        return ps;
}

int
lcm_alloc_ok(lcm_t* self) {
        if (pthread_mutex_lock(&lcm_internal_lock) != 0) {
                lcm_mutex_lock_err("failed to acquire lcm lock %s", strerror(errno));

                return LCM_ERR;
        }

        int stat = (self->count >= self->maxpep) ? LCM_ERR : LCM_OK;

        pthread_mutex_unlock(&lcm_internal_lock);
        return stat;
}

int
lcm_set(lcm_t* self, ps_session_t* conn) {
        if (pthread_mutex_lock(&lcm_internal_lock) != 0) {
                lcm_mutex_lock_err("failed to acquire lcm lock %s", strerror(errno));

                return LCM_ERR;
        }

        size_t i = self->count;

        /* Allocate and set the pointer. */
        self->clients[i] = conn;

#if defined(RCFILE)
        /*
         * Attempt to append a resource control entry to the .connectrc
         * file. This file can be used for recovery scenarios if need be.
         */
        if (rcw_row((self->count + 1), conn) != F_OK)
                error("failed to add conenction to rc");
#endif

        ++self->count;
        pthread_mutex_unlock(&lcm_internal_lock);

        return i;
}
