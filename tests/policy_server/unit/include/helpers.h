#ifndef TP_HELPERS
#define TP_HELPERS

#include <fcntl.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "iputil.h"
#include "lcm.h"
#include "log.h"
#include "routes.h"
#include "ulfius.h"
#include "ps.h"
#include "yyjson.h"
/* yyjson and aliases. */
#include "routes.h"

#define TP_ASSERT(expr)                                                                       \
        debug("\tASSERT %s", #expr);                                                          \
        if (!(expr)) {                                                                        \
                fprintf(stderr, "%s:%d Assertion '%s' failed.\n", __FILE__, __LINE__, #expr); \
                abort();                                                                      \
        }
#define TP_ASSERT_EQ_ITER(data, i, expected)                                      \
        debug("\tASSERT data[%i]=%u is %i", *i, data[*i], expected);              \
        if (data[*i] != expected) {                                               \
                fprintf(stderr, "%s:%d Assertion failed.\n", __FILE__, __LINE__); \
                abort();                                                          \
        }                                                                         \
        *i += 1;

#define LOCAL_SET  "http://localhost:8000/gate-set"
#define LOCAL_GET  "http://localhost:8000/gate-info"
#define LOCAL_DEL  "http://localhost:8000/gate-delete"
#define LOCAL_CCAP "http://localhost:8000/connect"

#define MOCK_CMTS  "88.7.88.9"

typedef struct {
        /* Gate Spec. */
        uint8_t gate_spec_snum;
        uint8_t gate_spec_stype;
        uint8_t gate_spec_flags;
        uint8_t gate_spec_dtos_ow;
        uint8_t gate_spec_dtos_mk;
        uint8_t gate_spec_session;
        uint8_t gate_spec_timer1;
        uint8_t gate_spec_timer2;
        uint8_t gate_spec_timer3;
        uint8_t gate_spec_timer4;
        const char* gate_spec_direction;
        const char* traffic_profile_name;

        /* Classifier Src/Dst IP/Masks. */
        uint32_t class_src_int;
        uint32_t class_dst_int;
        uint32_t class_src_mask_int;
        uint32_t class_dst_mask_int;

        /* Classifier Ports. */
        uint16_t class_src_port_start;
        uint16_t class_dst_port_start;
        uint16_t class_src_port_end;
        uint16_t class_dst_port_end;

        /* Classifier DSCP/Tos fields. */
        uint8_t class_dtos_ow;
        uint8_t class_dtos_mk;

        uint16_t class_protocol;
        uint16_t class_id;
        uint8_t class_priority;
        uint8_t class_activation_state;
        uint8_t class_action;

        uint8_t class_len;

        /* Envelope. */
        uint8_t envelope_svcn;
        uint8_t envelope_size;
        uint8_t envelope_stype;

        /* v6 classifier. */
        uint32_t flow_label;
        uint16_t protocol;
        uint16_t nh_type;
        uint8_t tc_low;
        uint8_t tc_high;
        uint8_t tc_mask;
        uint8_t src_prefix_len;
        uint8_t dst_prefix_len;
        char* src_ip6;
        char* dst_ip6;
} EXP;

/*
 * Read a file's contents into the given destination buffer.
 * Returns 0 on any failure, otherwise returns the size of the contents.
 *
 * @dst         Final desintaion of the content in the file given.
 * @filepath    Path to the file a user wants to store in the buffer.
 */
size_t util_read_result(uint8_t* dst, const char* filepath);

/*
 * Read a JSON file's contents into the destination buffer. This is very similar to
 * the above function so one or the other may be redundant. Returns the esize of the
 * read contents and logs and errors.
 *
 * @filepath    Path to the file a user wants to store in the buffer.
 * @dst         Final desintaion of the content in the file given.
 */
size_t util_read_body(const char* file_path, char* dst);

/*
 * Given a yyjson root object (from a yyjson_doc type) build an `EXP` object.
 * The `EXP` object contains numerous top-level fields used to compare a test's
 * expected output, against what the actual values from data/ *_tp_*.txt files.
 */
EXP* util_build_expected(yy_val* root);

/*
 * This function reads a JSON-like text file into a yyjson_doc type, then calls
 * and returns the result of `util_build_expected`.
 */
EXP* util_get_expected(yyjson_doc* doc);
#endif
