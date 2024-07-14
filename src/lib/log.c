#if defined(__clang__)
#pragma clang diagnostic ignored "-Wformat"
#endif

#include <log.h>

#if defined(NO_COLOR)
#define HEADER_FMT "%s %i:%li %-6s %-10s"
#else
#define HEADER_FMT "%s%s %i:%li%s %s%-6s%s %-10s%s"
#endif
#define BASE_HEADER_FMT "%s %i:%li %-6s %-10s"

/*
 * Global level logging options provide the ability to disable thread-specific logs,
 * console logging, log level and the maximum size of log files before removal.
 */
static struct {
        int level;
        int depth;
        bool thread_write;
        bool stdout_write;
        unsigned long max_file_size;
} GLOBAL_LOGGER;

/*
 * Thread local storage key (opaque object) used to locate thread-specific data.
 * The values bound to this key are maintained on a per-thread basis for the life-
 * span of that thread. Note this keys MUST be intialized before use.
 */
static pthread_key_t pthread_local_key;

/*
 * Replace characters in a char. array with the given char. Used to convert a CMTS IP address into
 * a valid log file name
 *
 * @s           Character array to search for the target character.
 * @targ        Target character to replace.
 * @repl        Replacement character.
 */
static char* pthread_specific_iptof(char* s, char targ, char repl);

/*
 * Return the size of the file, in bytes, referenced by the path.
 *
 * @path Path to the file we want to get the size (bytes) of.
 */
static unsigned long pthread_specific_fsize(const char* path);

/*
 * Check the file's size, defined by the given path, doesn't exceed the globally configured value.
 * If it does, purge all contents and return a new pointer to the file. Otherwise return the
 * orignal file pointer given.
 *
 * @path        Path to the file to check (ERROR_LOG_FILE or logs*.log).
 * @fp          File pointer which corresponds to the given path.
 */
static FILE* log_getfsize(char* path, FILE* fp);

/*
 * Only use lcolor and lreprs when developing locally and outputting to non-log file destinations.
 * lcolor maintains level-specific colors, while lreprs maintains the level-specific string reprs.
 */
static const char* lcolor[] = {GRN, CYN, BLU, YEL, RED, RED};
static const char* lreprs[] = {"INFO", "DEBUG", "DEV", "WARN", "ERROR", "FATAL"};

static char*
pthread_specific_iptof(char* ip, char targ, char repl) {
        for (unsigned long i = 0; i < strlen(ip); i++) {
                if (ip[i] == targ)
                        ip[i] = repl;
        }
        return ip;
}

static unsigned long
pthread_specific_fsize(const char* filename) {
        FILE* fp;

        if ((fp = fopen(filename, "rb")) == NULL) {
                fclose(fp);
                return -1UL;
        }

        /* Seek file end and store current pos. */
        fseek(fp, 0L, SEEK_END);
        long size = ftell(fp);

        /* Close ephemeral ptr and return. */
        fclose(fp);
        return size;
}

void
pthread_specific_local_destroy(void* p) {
        errno = 0;

        tlog* t = (tlog*)p;

        warning("destroying %s", t->path);

        if (access(t->path, F_OK) != 0)
                debug("thread specific file doesn't exist");

        if (fclose(t->loc) != 0)
                perror("failed to close stream: ");

        if (remove(t->path) != 0)
                perror("failed to remove");

        free(t);
        t = NULL;
}

void
pthread_logspecific(int level, const char* cmts_ip) {
        size_t f_size = strlen(cmts_ip) + 1;
        size_t p_size = f_size + 10;

        char file[f_size];
        char path[p_size];

        memset(file, 0, sizeof(file));
        memset(path, 0, sizeof(file));
        memcpy(file, cmts_ip, f_size);

        pthread_specific_iptof(file, '.', '_');
        snprintf(path, p_size, LOG_PATH_FORMAT, file);

        /* Instantiate a new thread-specific object to store thread-specific log details */
        tlog* t = (tlog*)malloc(sizeof(tlog));
        t->level = level;

        memset(t->path, 0, sizeof(t->path));
        memcpy(t->path, path, sizeof(path));

        if ((t->loc = fopen(path, "w")) == NULL) {
                error("failed to open %s: %s", path, strerror(errno));
        }

        /* Set a unique object for this thread using the pthread key. */
        pthread_setspecific(pthread_local_key, t);

        info("thread log created '%s' by thread %li", path, pthread_self());
}

void
global_logconf(int level, int max_fsize, bool stdout_w, bool thfile_w) {
        GLOBAL_LOGGER.level = level;
        GLOBAL_LOGGER.max_file_size = max_fsize;
        GLOBAL_LOGGER.stdout_write = stdout_w;
        GLOBAL_LOGGER.thread_write = thfile_w;

        /*
         * The pthread_key_create() function shall create a thread-specific data key visible to all
         * threads in the process. The same key value may be used by different threads, but the
         * values bound to the key by pthread_setspecific() are maintained on a per-thread basis.
         */
        if ((pthread_key_create(&pthread_local_key, pthread_specific_local_destroy)) < 0)
                perror("pthread_key init failed");
}

static FILE*
log_getfsize(char* path, FILE* fp) {
        if (pthread_specific_fsize(path) < GLOBAL_LOGGER.max_file_size)
                return fp;

        /*
         * When this thread's log file exceeds the maximum file size configured in the global
         * settings, flush the output stream, clear the file and re-establish the local pointer.
         */
        fflush(fp);
        fclose(fp);

        fclose(fopen(path, "w"));
        return fopen(path, "w");
}

#ifdef __x86_64__

void
_log(FILE* dst, LogLevel level, const char* file, int ln, const char* msg, va_list args) {
        char buf[16];
        memset(buf, 0, sizeof(buf));

        /* Store current time. */
        time_t t = time(NULL);
        struct tm* time = localtime(&t);
        buf[strftime(buf, sizeof(buf), "%H:%M:%S", time)] = '\0';

        /* Collect log attrs. */
        pthread_t tid = pthread_self();
        const char* name = basename((char*)file);
        const char* repr = lreprs[level];

        va_list args2;
        va_copy(args2, args);

        va_list args3;
        va_copy(args3, args);

        if (GLOBAL_LOGGER.stdout_write) {
                /*
         * ONLY executed if console logging has been enabled in the GLOBAL_LOGGER
         * settings. Otherwise continue on to thread-specific logging checks.
         *
         * IF !defined(NO_COLOR) Take the level integer and find the corresponding
         * indicator color. (i.e., INFO is green, ERROR is red, etc)
         */
#if defined(NO_COLOR)
                fprintf(dst, "%s %i:%li %-6s %-10s", buf, getpid(), tid, repr, name);
#else
                const char* lvl_color = lcolor[level];
                fprintf(dst, "%s%s %i:%li%s %s%-6s%s %-10s%s ", GRY, buf, getpid(), tid, RESET, lvl_color, repr, GRY,
                        name, RESET);
#endif
                /* Log the vargs, add a newline and flush. */
                vfprintf(dst, msg, args);
                fprintf(dst, "\n");
                fflush(dst);
        }

        /*
     * Thread specific logging requires the global setting to be toggled and the
     * pthread_key_t to identify a reference to the thread's log settings object.
     */
        tlog* tfile = (tlog*)pthread_getspecific(pthread_local_key);

        if (GLOBAL_LOGGER.thread_write && tfile != NULL) {
                tfile->loc = check_log_file_size(tfile->path, tfile->loc);
                fprintf(tfile->loc, "%s %i:%li %-6s %-10s ", buf, getpid(), tid, repr, name);
                vfprintf(tfile->loc, msg, args3);
                va_end(args3);

                fprintf(tfile->loc, "\n");
                fflush(tfile->loc);
        }

        if (level == LogLevel_ERROR || level == LogLevel_FATAL || level == LogLevel_WARN) {
                /*
         * If the log level for the entry is greater than DEV (2), write the log to the
         * error.log file. Prevents error logs from getting lost.
         */
                FILE* fp = NULL;

                if (access(ERROR_LOG_FILE, F_OK) == 0)
                        fp = fopen(ERROR_LOG_FILE, "a");
                else
                        fp = fopen(ERROR_LOG_FILE, "w");

                fp = check_log_file_size(ERROR_LOG_FILE, fp);

                fprintf(fp, "%s %i:%li %-6s %-10s ", buf, getpid(), tid, repr, name);

                vfprintf(fp, msg, args2);
                va_end(args2);
                fprintf(fp, "\n");
                fflush(fp);
                fclose(fp);
        }
        (void)ln;
}

#else /* ifdef __x86_64__ */

void
log_body_and_flush(FILE* dst, const char* msg, va_list args) {
        vfprintf(dst, msg, args);
        fprintf(dst, "\n");
        fflush(dst);
}

void
_log(FILE* dst, LogLevel level, const char* file, int ln, const char* msg, va_list args) {
        char buf[16];
        memset(buf, 0, sizeof(buf));

        /* Store current time. */
        time_t t = time(NULL);
        struct tm* time = localtime(&t);
        buf[strftime(buf, sizeof(buf), "%H:%M:%S", time)] = '\0';

        /* Collect log attrs. */
        pthread_t tid = pthread_self();
        pid_t pid = getpid();
        const char* name = basename((char*)file);
        const char* repr = lreprs[level];

        if (GLOBAL_LOGGER.stdout_write) {
                /*
                 * ONLY executed if console logging has been enabled in the GLOBAL_LOGGER
                 * settings. Otherwise continue on to thread-specific logging checks.
                 *
                 * IF !defined(NO_COLOR) Take the level integer and find the corresponding
                 * indicator color. (i.e., INFO is green, ERROR is red, etc)
                 */
#if defined(NO_COLOR)
                fprintf(dst, HEADER_FMT, buf, getpid(), tid, repr, name);
#else
                const char* lvl_color = lcolor[level];
                fprintf(dst, HEADER_FMT, GRY, buf, pid, tid, RESET, lvl_color, repr, GRY, name, RESET);
#endif
                log_body_and_flush(dst, msg, args);
        }

        /*
         * Thread specific logging requires the global setting to be toggled and the
         * pthread_key_t to identify a reference to the thread's log settings object.
         */
        tlog* tk = (tlog*)pthread_getspecific(pthread_local_key);

        if (GLOBAL_LOGGER.thread_write && tk != NULL) {
                tk->loc = log_getfsize(tk->path, tk->loc);
                fprintf(tk->loc, BASE_HEADER_FMT, buf, pid, tid, repr, name);
                log_body_and_flush(tk->loc, msg, args);
        }

        if (level == LogLevel_ERROR || level == LogLevel_FATAL || level == LogLevel_WARN) {
                /*
                 * If the log level for the entry is greater than DEV (2), write the log to the
                 * error.log file. Prevents error logs from getting lost.
                 */
                FILE* fp = NULL;

                if (access(ERROR_LOG_FILE, F_OK) == 0)
                        fp = fopen(ERROR_LOG_FILE, "a");
                else
                        fp = fopen(ERROR_LOG_FILE, "w");

                fp = log_getfsize(ERROR_LOG_FILE, fp);

                fprintf(fp, BASE_HEADER_FMT, buf, pid, tid, repr, name);

                log_body_and_flush(fp, msg, args);
                fclose(fp);
        }
        (void)ln;
}

#endif /* ifdef __x86_64__ / else */

void
log_wrap(LogLevel level, const char* file, int line, const char* message, ...) {
        if (level < LogLevel_WARN && (int)level > GLOBAL_LOGGER.level)
                return;

        va_list args;
        va_start(args, message);
        _log(stdout, level, file, line, message, args);
}

void
debug_raw(char* s, int len, char* ident) {
        char buf[16];
        memset(buf, 0, sizeof(buf));

        /* Store current time. */
        time_t t = time(NULL);
        struct tm* time = localtime(&t);

        /* Pack the destination buffer with the formatted time. */
        buf[strftime(buf, sizeof(buf), "%H:%M:%S", time)] = '\0';

        /* Collect log attrs. */
        pthread_t tid = pthread_self();
        const char* name = "unknown";
        const char* repr = lreprs[LogLevel_DEBUG];

        size_t iter_len;

        if (len == 0)
                iter_len = sizeof(s);
        else
                iter_len = len;

        FILE* fp = NULL;

        if (access("logs/error.log", F_OK) == 0) {
                fp = fopen("logs/error.log", "a");
        } else {
                fp = fopen("logs/error.log", "w");
        }

        if (GLOBAL_LOGGER.stdout_write) {
                fprintf(fp, "%s %i:%li %-6s %-10s ", buf, getpid(), tid, repr, name);
                fprintf(fp, "_%s=", ident);

                for (size_t i = 0; i < iter_len; i++) {
                        if (i == (iter_len - 1))
                                fprintf(fp, "%02x", (uint8_t)s[i]);
                        else
                                fprintf(fp, "%02x-", (uint8_t)s[i]);
                }
                fprintf(fp, "\n");
                fflush(fp);
                fclose(fp);
        }
}

void
debug_common_cops_object(uint8_t* data, const char* id, size_t i, const char* extra) {
        uint16_t len = unpack_u16_it((uint8_t*)data, &i);
        uint8_t sc_n = data[i + 0];
        uint8_t sc_t = data[i + 1];

        i += 2;

        if (MATCHES(id, DEBUG_HANDLE)) {
                OLOG_32(id, len, sc_n, sc_t, extra);

        } else if (MATCHES(id, DEBUG_CSI)) {
                i = 32;
                uint8_t vers = unpack_u16_it((uint8_t*)data, &i);
                OLOG_HEAD(id, vers, sc_n, sc_t);

        } else if (strstr(id, "SUB")) {
                int tot = 0;
                for (int j = 0; j < 16; j++) {
                        tot += data[i + j];
                }
                info("| (%s) Len = %-4i | C-Num = %-5i | C-Type = %-5u | SubscriberID = %-8d |", id, len, sc_n, sc_t,
                     tot);
        } else {
                uint16_t r1 = unpack_u16_it((uint8_t*)data, &i);
                uint16_t r2 = unpack_u16_it((uint8_t*)data, &i);

                OLOG_16x2(id, len, sc_n, sc_t, r1, r2)
        }
        info("-------------------------------------------------------------------------------");
}

void
debug_message(uint8_t* data, const char* handle) {
        uint8_t vers = *&data[0];
        uint8_t opcd = *&data[1];

        size_t i = 2;
        uint16_t clt = unpack_u16_it((uint8_t*)data, &i);
        uint32_t len = unpack_u32_it((uint8_t*)data, &i);

        info("-------------------------------------------------------------------------------");
        info("| Version = %-6u | Opcode = %-4u | Client = %-5u | Len = %-17u |", vers, opcd, clt, len);
        info("-------------------------------------------------------------------------------");

        debug_common_cops_object(data, DEBUG_HANDLE, i, handle);
        debug_common_cops_object(data, DEBUG_CONTEXT, 16, NULL);
        debug_common_cops_object(data, DEBUG_DECISION, 24, NULL);
        debug_common_cops_object(data, DEBUG_CSI, 32, NULL);
        debug_common_cops_object(data, "TXN", 36, NULL);
        debug_common_cops_object(data, "APP", 44, NULL);
        debug_common_cops_object(data, "SUB", 52, NULL);
}
