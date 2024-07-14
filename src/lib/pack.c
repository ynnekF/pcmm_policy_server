#include "pack.h"

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wvarargs"
#endif

uint16_t
unpack_u16(char* src) {
        uint8_t* ptr = (uint8_t*)src;

        /*
         * Shift the first byte to a higher order byte position,
         * then a bitwise OR will combine it with the next byte.
         */
        return *(ptr) << 8 | *(ptr + 1);
}

uint32_t
unpackN(uint32_t* src) {
        uint8_t* ptr = (uint8_t*)src;

        return *(ptr) << 24 |     /* Left shift first byte by 24 bits */
               *(ptr + 1) << 16 | /* Left shift second byte by 16 bits */
               *(ptr + 2) << 8 |  /* Left shift third byte by 8 bits */
               *(ptr + 3);        /* Use fourth byte as is */
}

uint16_t
unpack_u8(uint8_t* src) {
        uint8_t* ptr = (uint8_t*)src;
        /*
         * Shift the first byte to a higher order byte position,
         * then a bitwise OR will combine it with the next byte.
         */
        return *(ptr) << 8 | *(ptr + 1);
}

uint32_t
unpack_u32(uint32_t* src) {
        uint8_t* ptr = (uint8_t*)src;

        return *(ptr) << 24 |     /* Left shift first byte by 24 bits */
               *(ptr + 1) << 16 | /* Left shift second byte by 16 bits */
               *(ptr + 2) << 8 |  /* Left shift third byte by 8 bits */
               *(ptr + 3);        /* Use fourth byte as is */
}

__attribute__((warning("not implemented")))
int8_t
unpack_i8_iter(uint8_t* src, size_t* ptr) {
        int8_t value = src[*ptr];

        *ptr += 1;
        return value;
}

__attribute__((warning("not implemented")))
int16_t
unpack_i16_iter(uint8_t* src, size_t* ptr) {
        int16_t value = unpack_u16((char*)src + *(ptr));

        *ptr += 2;
        return value;
}

__attribute__((warning("not implemented")))
int32_t
unpack_i32_iter(uint8_t* src, size_t* ptr) {
        int32_t value = unpackN((uint32_t*)&src[*ptr]);

        *ptr += 4;
        return value;
}

uint8_t
unpack_u8_it(uint8_t* src, size_t* ptr) {
        uint8_t value = src[*ptr];

        *ptr += 1;
        return value;
}

uint16_t
unpack_u16_it(uint8_t* src, size_t* ptr) {
        uint16_t value = unpack_u16((char*)src + *(ptr));

        *ptr += 2;
        return value;
}

uint32_t
unpack_u32_it(uint8_t* src, size_t* ptr) {
        uint32_t value = unpackN((uint32_t*)&src[*ptr]);

        *ptr += 4;
        return value;
}

void
pack_u8(uint8_t* dst, uint16_t val) {
        uint8_t* ptr = (uint8_t*)dst;

        /* Store. */
        *(ptr) = val;
}

void
pack_u32_be(uint8_t* dest, uint32_t val) {
        uint8_t* ptr = (uint8_t*)dest;

        /* Store the most significant byte. */
        *(ptr) = (val >> 24) & 0xFF;

        /* Store the next byte. */
        *(ptr + 1) = (val >> 16) & 0xFF;

        /* Store the next byte. */
        *(ptr + 2) = (val >> 8) & 0xFF;

        /* Store the least significant byte. */
        *(ptr + 3) = val & 0xFF;
}

void
pack_u16_be(uint8_t* dest, uint16_t val) {
        uint8_t* ptr = (uint8_t*)dest;

        /* Store the most significant byte. */
        *(ptr) = (val >> 8) & 0xFF;

        /* Store the least significant byte. */
        *(ptr + 1) = val & 0xFF;
}

void
concat_c8(uint8_t* dst, size_t* sz_ptr, uint8_t* src, size_t n) {
        size_t i;
        size_t j = 0;

        /* Append the source bytes to the dst starting at the pointer. */
        for (i = *sz_ptr; i < (*sz_ptr + n); i++) {
                *(dst + i) = *(src + (j++));
        }
        dst[i] = '\0';

        *sz_ptr += (int)n;
}

void
concat(uint8_t* dst, size_t* sz_ptr, const uint8_t* src, size_t n) {
        size_t i;
        size_t j = 0;

        /* Append the source bytes to the dst starting at the pointer. */
        for (i = *sz_ptr; i < (*sz_ptr + n); i++) {
                *(dst + i) = *(src + (j++));
        }
        dst[i] = '\0';

        *sz_ptr += (int)n;
}

void
pack_reverse(unsigned char* dst, size_t* iter, float value) {
        char tbuf[4];
        char revr[4];

        /* Zero out buffers. */
        memset(tbuf, 0, sizeof(tbuf));
        memset(revr, 0, sizeof(revr));

        /* Store the value. */
        memcpy(tbuf, &value, sizeof(float));

        for (int i = 0; i < 4; i++) revr[i] = tbuf[3 - i];

        memcpy(dst + (*iter), revr, sizeof(float));

        /* Update the iterator. */
        *iter += 4;
}
