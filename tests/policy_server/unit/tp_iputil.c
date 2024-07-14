#include "tp_iputil.h"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wint-to-pointer-cast"
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-macros"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#endif

void
tp_iputil_ip6_check(void) {
        info("TEST: %s", __func__);
        TP_ASSERT(is_ip6("2600:6ce1:0:51:7e8f:deff:fefb:3224"));
        TP_ASSERT(!(is_ip6("172.20.1.1\0")));
}

void
tp_iputil_prefixlen(void) {
        info("TEST: %s", __func__);
        TP_ASSERT(prefixlen("2600:6ce1:0:51:7e8f:deff:fefb:3224/32") == 32)
        TP_ASSERT(prefixlen("2600/16") == 16);
        TP_ASSERT(prefixlen("2600:0:0:0/64") == 64);
        TP_ASSERT(prefixlen("1.1.1.1") == 0);
}

void
tp_iputil_ito_ip4(void) {
        int int_repr = ip4_toi("1.1.1.1");
        const char* str_repr = ito_ip4(int_repr);
        TP_ASSERT(MATCHES(str_repr, "1.1.1.1"))
}
