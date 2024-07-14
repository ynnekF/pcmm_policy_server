#ifndef PACK_COPS_PCMM_H
#define PACK_COPS_PCMM_H

#include <stdint.h>
#include <stdlib.h>
#include "iputil.h"

uint32_t unpack_u32(uint32_t* src);
uint32_t unpack_u32(uint32_t* src);

/* Unpack a u16 from a char buffer. */
uint16_t unpack_u16(char* src);

/* Unpack a u16 from a u8 buffer. */
uint16_t unpack_u8(uint8_t* src);

/* Unpack a u8 from a u8 buffer while incrementing the pointer. */
uint8_t unpack_u8_it(uint8_t* src, size_t* ptr);

/* Unpack a u16 from a u8 buffer while incrementing the pointer. */
uint16_t unpack_u16_it(uint8_t* src, size_t* ptr);

/* Unpack a u32 from a u8 buffer while incrementing the pointer. */
uint32_t unpack_u32_it(uint8_t* src, size_t* ptr);

/* Pack an unsigned char (octet) value. */
void pack_u8(uint8_t* dst, uint16_t val);

/* Pack an unsigned long (32-bit) in "network", big-endian order. */
void pack_u32_be(uint8_t* dst, uint32_t val);

/* Pack an unsigned short (16-bit) in "network", big-endian order. */
void pack_u16_be(uint8_t* dst, uint16_t val);

/* Concatenate. */
void concat(uint8_t* dst, size_t* sz_ptr, const uint8_t* src, size_t n);

/* Concat but from a uint8_t array. */
void concat_c8(uint8_t* dst, size_t* sz_ptr, uint8_t* src, size_t n);

/* Pack an IPCC header with the length (8) and the given num/type. */
void pack_ipcc_header(uint8_t* dst, uint8_t num, uint8_t type);

/* Pack a float value into the detination buffer in reverse order */
void pack_reverse(unsigned char* dst, size_t* iter, float value);
#endif
