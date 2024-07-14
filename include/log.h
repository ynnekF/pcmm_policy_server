#ifndef LOG_H
#define LOG_H

#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pack.h"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#define ERROR_LOG_FILE    "logs/error.log"
#define LOG_PATH_FORMAT   "logs/%s.log"
#define LOG_FILE_DIR      "logs"
#define LOG_FILE_EXT      ".log"

#define info(fmt, ...)    log_wrap(LogLevel_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define debug(fmt, ...)   log_wrap(LogLevel_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define warning(fmt, ...) log_wrap(LogLevel_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define error(fmt, ...)   log_wrap(LogLevel_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define fatal(fmt, ...)   log_wrap(LogLevel_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/* Colors for perty stdout logs. */
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define GRY   "\x1b[90m"
#define RESET "\x1B[0m"

typedef enum {
        LogLevel_INFO,
        LogLevel_DEBUG,
        LogLevel_DEV,
        LogLevel_WARN,
        LogLevel_ERROR,
        LogLevel_FATAL,
} LogLevel;

typedef struct tlog {
        int level;
        char path[100];
        FILE* loc;
} tlog;

/*
 * Set the Global "logger" configuration options.
 *
 * @level       Represents the highest level of logs surfaced during execution
 *              ex. If the level is set as INFO, DEBUG and DEV logs are omitted.
 *                  If the level is set to DEBUG, just DEV logs are omitted.
 *                  WARN/ERROR/FATAL are always logged and can't be toggled off.
 * @max_fsize   Represents the maximum log file size allowed before it is purged.
 *              After the file reaches X bytes, it will be closed and reopened.
 * @stdout_w    Toggle logging to console
 * @thfile_w    Toggle thread-specific file logs
 */
void global_logconf(int level, int max_fsize, bool stdout_w, bool thfile_w);

/*
 * Establish thread local data and logging settings. After a new thread is started, this function
 * must be called to enable thread-specific logging. If thread-specific logging is enabled globally,
 * a new pthread_key_t is allocated which points at a THREAD_LOGGER object, containing the calling
 * thread's specific log file.
 *
 * @level       Thread-specific logging level
 * @cmts_ip     CMTS IP the thread corresponds to (converts to <ip>.log)
 */
void pthread_logspecific(int level, const char* cmts_ip);

/*
 * Var. log wrapper to accept/reject log requests given the global log level
 * called by the macros defined above. DO NOT CALL THIS DIRECTLY
 */
void log_wrap(LogLevel level, const char* file, int line, const char* message, ...);

/*==============================================================================
 * DEBUG logging helpers (DEVELOPMENT ONLY)
 *============================================================================*/

#define LOG_COPS(id, obj, len)    debug_log_cops_wrapper(LogLevel_DEV, __FILE__, __LINE__, id, obj, len);
#define DEBUG_HANDLE              "HND"
#define DEBUG_CONTEXT             "CTX"
#define DEBUG_DECISION            "DEC"
#define DEBUG_CSI                 "CSI"
#define MATCHES(x, v)             strcmp(x, v) == 0
#define OLOG_HEAD(a1, a2, a3, a4) info("| (%s) VER = %-4i | C-Num = %-5i | C-Type = %-5u |", a1, a2, a3, a4);

#define OLOG_32(i, l, v1, v2, v3) \
        info("| (%s) Len = %-4i | C-Num = %-5i | C-Type = %-5u | Handle = %-14s |", i, l, v1, v2, v3);

#define OLOG_16x2(a1, a2, a3, a4, a5, a6) \
        info("| (%s) Len = %-4i | C-Num = %-5i | C-Type = %-5u | V1 = %-6i | V2 = %-4i |", a1, a2, a3, a4, a5, a6);

/*
 * Output a string of `len` characters as hex values
 *
 * @s           Char. array to print as hex values
 * @len         Length of the char. array being printed
 * @ident       Unique identifier to prefix the hex values with
 */
void debug_raw(char* s, int len, char* ident);

void debug_log_cops_wrapper(LogLevel level, const char* file, int line, const char* id, const char* object, int length);

void debug_report_object(uint8_t* s, int len, uint64_t snum, uint64_t stype);
void debug_message(uint8_t* data, const char* handle);
#endif /* ifndef log_H */
