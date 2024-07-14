#ifndef SETTINGS_H
#define SETTINGS_H

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "log.h"
#include "yyjson.h"

#define RUN_SERVER        0   /* Primary Server + API mode. */
#define RUN_UNITTEST      2   /* Secondary unittest execution. */
#define PATH_SIZE         256 /* Current working directory max. */
#define BUILD_UUID_FILE   "data/.bid"
#define ORPHAN_ENTRY_FILE "data/__orphan__"

typedef struct options {
        /* Maximum size a log file can reach before it's removed. */
        unsigned long long log_max_fsize;

        int log_purge;  /* Remove existing log files.   */
        int log_level;  /* Logging level verbosity.     */
        int log_thread; /* Toggle thread local logging. */
        int log_stdout; /* Toggle stdout logging.       */

        char** preflight; /* Set of preflight CMTS connections.  */
        int pflen;        /* Length of the preflight CMTS array. */
        int mode;         /* Run mode (server or unittest).      */
        int max_pep;      /* Maximum number of CMTS connections. */
} opts_t;

opts_t conf_read(int argc, char const** argv);

int conf_clean_dirs(void);                  /* Clear ephemeral files. */
int conf_get_ACtimer(void);                 /* Return configured Accounting timer. */
int conf_get_KAtimer(void);                 /* Return configured Keep-Alive timer. */
int conf_get_log_level(void);               /* Return configured log level. */
int conf_get_ulfius_af_type(void);          /* Return Ulfius network type. */
int conf_get_maxconnect_secs(void);         /* Get maximum connect times. */
uint16_t conf_get_cmts_tcp_port(void);      /* Return default (const) IANA CMTS port. */
uint16_t conf_get_ulfius_server_port(void); /* Return default (const) Ulfius server port. */
#endif
