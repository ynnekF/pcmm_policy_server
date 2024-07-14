#include "conf.h"

#if defined(__clang__)
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wformat-overflow="
#endif

#define DATA_DIR    "data"
#define OPT_UNKOWN  "unknown argument"
#define OPT_MAXPEP  "max_pep"
#define OPT_LOGLVL  "log_level"
#define OPT_LOGSTD  "log_stdout"
#define OPT_LOGMAX  "log_max_fsize"
#define OPT_TIMEOUT "connect_timeout"
#define OPT_KATIMER "ka_timer"
#define OPT_ACTIMER "ac_timer"
#define assert(expr)                                                                          \
        if (!(expr)) {                                                                        \
                fprintf(stderr, "%s:%d Assertion '%s' failed.\n", __FILE__, __LINE__, #expr); \
                abort();                                                                      \
        }

/* Settings parser util. - Read a string value. */
static void conf_argparse_str(void* arg, char* dst);
/*
 * Settings parser util. - Read some value into the opts struct
 *
 * @opts        Option struct which maintains parsed settings
 * @arg         A string representing the value's corresponding key (i.e., "log_level") OR when
 *              parsing args. direct from a CLI, this represents the value itself (i.e. ..="INFO")
 * @val         The value from a JSON config file (when parsing CLI args., this is NULL)
 */
static void conf_argparse_opt(opts_t* opts, void* arg, void* val);

/*
 * Settings parser util. - Return an integer value
 *
 * @arg         Name of the argument currently being processed.
 * @type        If ARGPARSE_CONFIG_INT, calls yyjson_get_int to return an integer value defined
 *              in a config. file, otherwise reads and separates a key/value pair (key=value),
 *              then calls atoi to convert the value to an integer before returning.
 */
static int conf_argparse_get(void* arg, int type);
static opts_t conf_get_defaults(void);            /* Return an OPTS object populated with the default values. */
static opts_t conf_read_file(const char* path);   /* Internal util to read sys settings from a JSON config. file */
static int conf_set_unittest(void);               /* Define UNIT_TEST and return 2. */
static void conf_clean_dangling_log(void);        /* Purge the existing dropped/orphan entries. */
static void conf_set_ka_timer(int val);           /* Set the GLOBAL settings 'ka_timer' field. */
static void conf_set_ac_timer(int val);           /* Set the GLOBAL settings 'ac_timer' field. */
static void conf_set_log_level(int val);          /* Set the GLOBAL settings 'thread_log_level' field. */
static void conf_set_connect_timeout(int val);    /* Set the GLOBAL settings 'connect_timeout' field. */
static void conf_set_ulfius_af_type(int val);     /* Set the GLOBAL settings `ulfius_af_type` field. */
static void conf_set_ulfius_server_port(int val); /* Set the GLOBAL settings `ulfius_port` field. */
static void conf_set_cmts_tcp_port(int val);      /* Set the GLOBAL settings `cmts_port` field. */
static void conf_set_client_defaults(void);       /* THIS MUST ALWAYS BE CALLED AT THE BEGINNING OF `conf_read`. */

static struct {
        int ka_timer;         /* Keep-alive timer. */
        int ac_timer;         /* Accounting timer. */
        int thread_log_level; /* Thread-log level. */
        int connect_timeout;  /* Maximum amount of time before timing out on CMTS connects. */
        int ulfius_af_type;   /* Opt to bind Ulfius framework to (IPv4, IPv6 or both). */
        int ulfius_port;      /* Ulfius bind port. */
        int cmts_port;        /* IANA assigned port. */
        int app_id;           /* Application Manager ID. */
} CLIENT_SETTINGS;

enum argparse_opts {
        ARGPARSE_CONFIG_INT, /* From config. file - parse yyjson integer. */
        ARGPARSE_CONFIG_STR, /* From config. file - parse yyjson string. */
        ARGPARSE_CLI_INT,    /* From CLI string - parse key=value pair. */
        ARGPARSE_CLI_STR,    /* From CLI string - parse key=value pair. */
};

static const uint16_t IANA_TCP_PORT = 3918; /* Default IANA-assigned port the CMTS listens on (DO NOT CHANGE). */
static const uint16_t SERV_API_PORT = 8000; /* Default port Ulfius listens on. */

int
conf_get_KAtimer(void) {
        if (!CLIENT_SETTINGS.ka_timer)
                return 60;

        return CLIENT_SETTINGS.ka_timer;
}

int
conf_get_ACtimer(void) {
        return CLIENT_SETTINGS.ac_timer;
}

int
conf_get_log_level(void) {
        return CLIENT_SETTINGS.thread_log_level;
}

int
conf_get_maxconnect_secs(void) {
        return CLIENT_SETTINGS.connect_timeout;
}

int
conf_get_ulfius_af_type(void) {
        return CLIENT_SETTINGS.ulfius_af_type;
}

uint16_t
conf_get_ulfius_server_port(void) {
        return CLIENT_SETTINGS.ulfius_port;
}

uint16_t
conf_get_cmts_tcp_port(void) {
        return CLIENT_SETTINGS.cmts_port;
}

static void
conf_set_ka_timer(int val) {
        CLIENT_SETTINGS.ka_timer = val;
}

static void
conf_set_ac_timer(int val) {
        CLIENT_SETTINGS.ac_timer = val;
}

static void
conf_set_log_level(int val) {
        CLIENT_SETTINGS.thread_log_level = val;
}

static void
conf_set_connect_timeout(int val) {
        CLIENT_SETTINGS.connect_timeout = val;
}

static void
conf_set_ulfius_af_type(int val) {
        CLIENT_SETTINGS.ulfius_af_type = val;
}

static void
conf_set_ulfius_server_port(int val) {
        CLIENT_SETTINGS.ulfius_port = val;
}

static void
conf_set_cmts_tcp_port(int val) {
        CLIENT_SETTINGS.cmts_port = val;
}

static void
conf_set_app_id(int val) {
        CLIENT_SETTINGS.app_id = val;
}

static void
conf_set_client_defaults(void) {
        conf_set_connect_timeout(4);
        conf_set_ulfius_af_type(AF_INET);
        conf_set_ulfius_server_port(SERV_API_PORT);
        conf_set_cmts_tcp_port(IANA_TCP_PORT);
        conf_set_app_id(3474);
}

static opts_t
conf_get_defaults(void) {
        opts_t opts;
        /* Set default log settings. */
        opts.log_max_fsize = (2 * 1024 * 1024);
        opts.log_level = LogLevel_INFO;
        opts.log_stdout = true;
        opts.log_thread = true;
        opts.log_purge = true;
        /* Set default API/LCM settings. */
        opts.mode = RUN_SERVER;
        opts.max_pep = 4;
        /* Initialize preflight. */
        opts.preflight = NULL;
        opts.pflen = 0;
        return opts;
}

static void
conf_clean_dangling_log(void) {
        if (fclose(fopen(ORPHAN_ENTRY_FILE, "w")) != 0)
                perror("failed to clear orphan file");
}

static int
conf_set_unittest(void) {
#if !defined(UNIT_TEST)
#define UNIT_TEST
#endif
        /* Return run mode (=2) indicating unittest exec. */
        return RUN_UNITTEST;
}

static void
conf_argparse_str(void* arg, char* dst) {
        char* token = strsep((char**)&arg, "=");
        token = strsep((char**)&arg, "=");
        sscanf(token, "%s", dst);
}

static int
conf_argparse_get(void* arg, int type) {
        if (type == ARGPARSE_CONFIG_INT)
                return yyjson_get_int(arg);

        char* token = NULL;
        token = strsep((char**)&arg, "=");
        token = strsep((char**)&arg, "=");

        int dst = 0;
        sscanf(token, "%d", &dst);
        return dst;
}

static void
conf_argparse_opt(opts_t* opts, void* arg, void* val) {
        errno = 0;
        if (val == NULL)
                val = arg;

        int type = (strstr(val, "=")) ? ARGPARSE_CLI_INT : ARGPARSE_CONFIG_INT;
        int rval = conf_argparse_get(val, type);

        if (strstr(arg, OPT_MAXPEP)) {
                assert(rval <= 1000);
                opts->max_pep = rval;
        } else if (strstr(arg, OPT_LOGLVL)) {
                assert(0 <= rval && rval < 6);
                opts->log_level = rval;
                conf_set_log_level(opts->log_level);
        } else if (strstr(arg, OPT_LOGSTD)) {
                assert(rval == 0 || rval == 1);
                opts->log_stdout = rval;
        } else if (strstr(arg, OPT_LOGMAX)) {
                assert(rval > 0 && (unsigned long long)rval < (1024ULL * 1024ULL * 1024ULL));
                opts->log_max_fsize = (unsigned long long)rval;
        } else if (strstr(arg, OPT_KATIMER)) {
                conf_set_ka_timer(rval);
        } else if (strstr(arg, OPT_ACTIMER)) {
                conf_set_ac_timer(rval);
        } else if (strstr(arg, OPT_TIMEOUT)) {
                conf_set_connect_timeout(rval);
        } else {
                perror(OPT_UNKOWN);
                exit(__LINE__);
        }
}

static opts_t
conf_read_file(const char* path) {
        yyjson_read_flag flg = YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_TRAILING_COMMAS;
        yyjson_read_err err;
        yyjson_doc* doc = yyjson_read_file(path, flg, NULL, &err);
        if (!doc) {
                perror("target configuration file not found");
                exit(__LINE__);
        }
        yy_val* obj = yy_root(doc);
        yy_val *key, *val;
        yy_iter iter;
        yy_init(obj, &iter);

        opts_t opts = conf_get_defaults();
        char* arg = NULL;

        while ((key = yy_next(&iter))) {
                arg = (char*)yy_str(key);
                val = yy_nval(key);

                if (MATCHES(arg, "connect")) {
                        size_t len = yyjson_get_len(val);
                        opts.preflight = (char**)malloc(len * sizeof(char*));
                        for (size_t i = 0; i < len; i++) {
                                /* Read raw IP address. */
                                yy_val* raw = yyjson_arr_get(val, i);
                                const char* ip = yy_str(raw);

                                /* Allocate space and store. */
                                opts.preflight[i] = (char*)malloc(strlen(ip) * sizeof(char*));
                                memcpy(opts.preflight[i], ip, strlen(ip) * sizeof(char*));
                        }
                        opts.pflen = len;

                } else if (MATCHES(arg, "mode")) {
                        const char* mode = yy_str(val);
                        if (strstr(mode, "unittest"))
                                opts.mode = conf_set_unittest();
                } else {
                        conf_argparse_opt(&opts, arg, val);
                }
        }
        yyjson_doc_free(doc);

        /* Assert the number of preflight connections
         * does not exceed the LCM's proposed limit. */
        assert(opts.max_pep >= opts.pflen);

        return opts;
}

int
conf_clean_dirs(void) {
        DIR* logs = opendir(LOG_FILE_DIR);
        DIR* data = opendir(DATA_DIR);

        struct dirent* f;
        char path[PATH_SIZE];
        memset(path, 0, sizeof(path));

        while ((f = readdir(logs)) != NULL) {
                sprintf(path, "%s/%s", "logs", f->d_name);
                if (strstr(path, LOG_FILE_EXT) == NULL)
                        continue;

                /* ONLY if the path contains .log, attempt
                 * to remove the file from the LOG_FILE_DIR. */
                info("removing '%s'", path);
                if (strstr(ERROR_LOG_FILE, path)) {
                        info("clearing the error log");
                        fclose(fopen(ERROR_LOG_FILE, "w"));
                        continue;
                }
                if (remove(path) == 0)
                        continue;

                error("failed to remove file '%s'", path);
                return 1;
        }
        while ((f = readdir(data)) != NULL) {
                sprintf(path, "%s/%s", "data", f->d_name);
                if (strstr(path, "IGNORE") == NULL && strstr(path, "yrpt") == NULL)
                        continue;

                info("removing '%s'", path);
                if (remove(path) == 0)
                        continue;

                error("failed to remove file '%s'", path);
                return 1;
        }
        closedir(logs);
        closedir(data);
        conf_clean_dangling_log();
        return 0;
}

opts_t
conf_read(int argc, char const** argv) {
        assert(argc > 1) opts_t opts = conf_get_defaults();
        conf_set_client_defaults();

        for (int i = 1; i < argc; i++) {
                char* arg = (char*)*(argv + i);

                if (strstr(arg, "config")) {
                        char path[PATH_SIZE];
                        memset(path, 0, sizeof(path));
                        conf_argparse_str(arg, path);
                        return conf_read_file(path);
                }

                if (MATCHES(arg, "unittest"))
                        opts.mode = conf_set_unittest();
                else if (MATCHES(arg, "server"))
                        continue;
                else
                        conf_argparse_opt(&opts, arg, NULL);
        }
        return opts;
}
