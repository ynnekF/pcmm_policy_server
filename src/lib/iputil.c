#include <iputil.h>

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wpointer-to-int-cast"
#endif

int
ip6_toi(const char* ip) {
        struct in6_addr addr;

        /* Convert an IPv6 network order address from std string
         * to the numeric binary form. Then return host order long. */
        inet_pton(AF_INET6, ip, &addr);

#if defined(IP6_TOI_OVERRIDE)
        return ntohl((uint32_t)addr.s6_addr);
#endif
        return 0;
}

int
ip4_toi(const char* ip) {
        struct in_addr addr;

        /* Convert an IPv4 network order address from std string
         * to the numeric binary form. Then return host order long. */
        inet_pton(AF_INET, ip, &addr);
        return ntohl(addr.s_addr);
}

int
itoi(const char* ip, int type) {
        if (type == AF_INET)
                return ip4_toi(ip);
        else
                return ip6_toi(ip);
}

const char*
ito_ip4(int ip_int) {
        struct in_addr addr;
        addr.s_addr = htonl(ip_int);

        return inet_ntoa(addr);
}

int
is_ip4(const char* ip) {
        struct sockaddr_in addr;

        return inet_pton(AF_INET, ip, &addr) != 0;
}

int
is_ip6(const char* ip) {
        struct in6_addr v4_or6;

        return inet_pton(AF_INET6, ip, &v4_or6);
}

uint8_t
prefixlen(const char* ip) {
        if (!strstr(ip, "/"))
                return 0;

        const char* res = ip;
        while ((res = strchr(res, '/')) != NULL) {
                ++res;

                uint8_t prefix_len = atoi(res);
                return prefix_len;
        }

        return 0;
}

void
pack_ip6(unsigned char* dst, const char* ip6) {
        char* token = strtok((char*)ip6, ":");

        int i = 0;
        char* endptr;

        unsigned long t = strtoul(token, &endptr, 16);
        dst[2 * i] = (t >> 8) & 0xFF;
        dst[2 * i + 1] = t & 0xFF;
        i++;

        while (token != NULL) {
                token = strtok(NULL, ":");
                if (token == NULL)
                        break;
                unsigned long tl = strtoul(token, &endptr, 16);
                dst[2 * i] = (tl >> 8) & 0xFF;
                dst[2 * i + 1] = tl & 0xFF;
                i++;
        }
}
