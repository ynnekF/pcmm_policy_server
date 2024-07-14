#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "conf.h"
#include "log.h"
#include "pack.h"
#include "routes.h"
#include "yyjson.h"

static uint32_t
ps_version(void) {
        FILE* bid = fopen(BUILD_UUID_FILE, "r");
        int ret = 0;

        if (bid != NULL)
                if (fscanf(bid, "%d", &ret) <= 0)
                        warning("failed to read build version");

        fclose(bid);
        return ret;
}

__attribute__((constructor())) static void
preprocess_check_definitions(void) {
#if defined(UNIT_TEST)
        info("service exec modifier: Unit test");
#else
        info("service exec modifier: none");
#endif
}

__attribute__((constructor(102))) static void
preprocess(void) {
        global_logconf(LogLevel_INFO, 0, 1, 0);
        info("Build Version v%s-%d ", RELEASE_VER, ps_version());
        info("GCC Version %s", __VERSION__);
        switch (__STDC_VERSION__) {
                case 199409L: info("__STDC_VERSION__ (C94)"); break;
                case 199901L: info("__STDC_VERSION__ (C99)"); break;
                case 201112L: info("__STDC_VERSION__ (C11)"); break;
                case 201710L: info("__STDC_VERSION__ (C17)"); break;
                default:
                        info("__STDC_VERSION__ ");
                        __STDC_VERSION__ > 201710L ? info(" (std=c++2a)") : info(" Unknown standard");
        }
}

#if !defined(UNIT_TEST)
/* Unittest run function was called without having defined the `-DUNIT_TEST`
 * GNU make flag, cannot execute without having compiled the source code.
 * Exit with fail and see the unittest startup documentation. */
#define exec_unittest() return __LINE__;
#else
/* Unittest option was defined and source test code was compiled. Include the
 * primary C unit test runner file, and define the unittest call function.
 *
 * if defined(UNIT_TEST) is true, API and pserver functionality is altered to write
 * unittest data files for validation under `data/IGNORE_tp_*`. */
#include "runners.h"
#define exec_unittest() return unittest_executor();
#endif

int
main(int argc, char const** argv) {
        srand(time(NULL));

        opts_t opts = conf_read(argc, argv);
        global_logconf(opts.log_level, opts.log_max_fsize, opts.log_stdout, opts.log_thread);
        if (opts.log_purge)
                if (conf_clean_dirs() != 0)
                        return EXIT_FAILURE;

        if (opts.mode == RUN_UNITTEST)
                exec_unittest();

        if (opts.mode == RUN_SERVER)
                return gctl_webapi_init(opts.max_pep, opts.preflight, opts.pflen);

        return EXIT_SUCCESS;
}
