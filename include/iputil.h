#ifndef IPLIB_H
#define IPLIB_H

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Return an integer indicating whether the given IP is an IPv4 address.
 *
 * @ip Valid string representation of an IPv4 address
 */
int is_ip4(const char* ip);

/*
 * Return an integer indicating whether the given IP is an IPv6 address.
 *
 * @ip Valid string representation of an IPv6 address
 */
int is_ip6(const char* ip);

/*
 * Pack an IPv6 address into the destination buffer. (note: this could be defined under 'pack.c'
 * but since it's IP related it's defined here.)
 *
 * @dst Destination buffer where the IPv6 address will be stored
 * @ip6 Valid string representation of an IPv6 address
 */
void pack_ip6(unsigned char* dst, const char* ip6);

/*
 * Return the prefix length from an IPv6 address.
 * ex.
 *      2600:0:0:0:/64 returns 64
 *
 * @ip Valid string representation of an IPv6 address
 */
uint8_t prefixlen(const char* ip);

/*
 * Convert an IPv4 address to an integer.
 *
 * @ip  Valid string representation of an IPv4 address
 */
int ip4_toi(const char* ip);

/*
 * Convert an IPv6 address to an integer.
 * WARNING: Don't use this.
 *
 * @ip Valid string representation of an IPv6 address
 */
int ip6_toi(const char* ip);

/*
 * Handler function which determines whether to call ip4_toi() or ip6_toi()
 * Note: AF_INET6 shouldn't be used here and is untested/unused.
 *
 * WARNING: Don't use AF_INET6
 *
 * @ip      String representation of an IPv4 OR IPv6 address
 * @type    AF_INET or AF_INET6 depending on expected result.
 */
int itoi(const char* ip, int type);

/*
 * Convert a u32 integer into a IPv4 address string representation.
 * Note: Generally the value comes from ip4_toi().
 *
 * @ip_int Integer representation of a valid IPv4 address
 */
const char* ito_ip4(int ip_int);

#endif /* ifndef IPLIB_H */
