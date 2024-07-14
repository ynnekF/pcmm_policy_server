#ifndef PCMM_H
#define PCMM_H

#include <stdint.h>
#include <stdlib.h>
#include "log.h"
#include "pack.h"

#define PCMM_CLIENT_TYPE    32778
#define GATE_SET            4
#define GATE_INFO           7
#define GATE_DEL            10

#define GATE_SNUM           5            /* Gate S-Num */
#define GATE_STYPE          1            /* Gate S-Type */
#define GATE_SPEC_LEN       16           /* Standard Gate object length */
#define GATE_DIR_UPSTREAM   "upstream"   /* Upstream direction */
#define GATE_DIR_DOWNSTREAM "downstream" /* Downstream direction */
#define MAX_CLASSIFIER_LEN  320          /* Maximum packed classifier length */

#define CLFLEG_LEN          24 /* Legacy Classifier length */
#define CLFLEG_SNUM         6  /* Legacy Classifier S-Num */
#define CLFLEG_STYPE        1  /* Legacy Classifier S-Type */
#define CLFEXT_LEN          40 /* Extended Classifier length */
#define CLFEXT_SNUM         6  /* Extended Classifier S-Num */
#define CLFEXT_STYPE        2  /* Extended Classifier S-Type */
#define CLFV6_LEN           64 /* IPv6 Classifier length */
#define CLFV6_SNUM          6  /* IPv6 Classifier S-Num */
#define CLFV6_STYPE         3  /* IPv6 Classifier S-Type */

#define ENVELOPE_LEN        92
#define DOCSIS_SCN_LEN      24 /* Speedboost envelope length */
#define DOCSIS_SCN_SNUM     7  /* Speedboost envelope S-Num value */
#define DOCSIS_SCN_STYPE    2  /* Speedboost envelope S-Type value */
#define FLOW_SPEC_LEN       0  /* Flow Spec envelope length */
#define FLOW_SPEC_SNUM      7  /* Flow Spec envelope S-Num value */
#define FLOW_SPEC_STYPE     1  /* Flow Spec Envelope S-Type value */

#define MATCHES(x, v)       strcmp(x, v) == 0

#define RESPONSE_GATE_SPEC_LEGACY_CLASSIFIER                                                    \
        "{\"output\": {\"cops-gate-id\": %lu, \"GateCmd\": \"%s\", \"ApplicationId\": %u, "     \
        "\"spec\": {\"flags\": %u, \"class\": %u, \"t1\": %u, \"t2\": %u, \"t3\": %u, \"t4\": " \
        "%u, \"classifier_id\": %u, "                                                           \
        "\"src_port_start\": %u, \"src_port_end\": %u}}"

#define RESPONSE_GATE_SPEC_EXTENDED_CLASSIFIER                                                  \
        "{\"output\": {\"cops-gate-id\": %lu, \"GateCmd\": \"%s\", \"ApplicationId\": %u, "     \
        "\"spec\": {\"flags\": %u, \"class\": %u, \"t1\": %u, \"t2\": %u, \"t3\": %u, \"t4\": " \
        "%u, \"classifier_id\": %u, \"src_port_start\": %u, \"src_port_end\": %u, "             \
        "\"dst_port_start\": %u, \"dst_port_end\": %u, \"priority\": %u, "                      \
        "\"state\": %u, \"action\": %u}}"

#define RESPONSE_ERROR                                                                      \
        "{\"output\": {\"cops-gate-id\": %lu, \"GateCmd\": \"%s\", \"ApplicationId\": %u, " \
        "\"PacketCableError\": \"%u::%u, '%s'\"}"

#define RESPONSE_DEFAULT "{\"output\": {\"cops-gate-id\": %lu, \"GateCmd\": \"%s\", \"ApplicationId\": %hu}"

#define RESPONSE_DRYRUN                                                                 \
        "{\"output\": {\"cops-gate-id\": %lu, \"GateCmd\": \"%s\", \"ApplicationId\": " \
        "%hu}, \"build-time\": %f, \"wait-time\": %f}"

struct _rpt {
        char* packetcable_err_descr;
        uint16_t packetcable_err_subcode;
        uint16_t packetcable_err_code;
        uint16_t transaction_id;
        uint16_t application_id;
        uint16_t application_tag;
        uint32_t gate_id;
        char* gate_cmd;

        /* Gate Specification Fields. */
        uint8_t flags;
        uint8_t class;

        uint16_t t1, t2, t3, t4;

        /* Classifier fields. */
        uint8_t tosf;
        uint8_t tosm;

        uint32_t src_ip;
        uint32_t dst_ip;
        uint32_t src_mk;
        uint32_t dst_mk;
        uint16_t proto_id;
        uint16_t src_port_start;
        uint16_t dst_port_start;
        uint16_t src_port_end;
        uint16_t dst_port_end;
        uint16_t classifier_id;
        uint8_t priority;
        uint8_t state;
        uint8_t action;
};

/* Alias report type */
typedef struct _rpt pcmm_rpt_t;
int write_report(FILE* fp, pcmm_rpt_t rpt, int ct);
/* Major/minor to ID */
char* pcmm_mmtoid(unsigned char* major, unsigned char* minor);
/* Opcode to action */
char* pcmm_otoact(unsigned char code);
/* Opcode to error */
char* pcmm_otoerr(unsigned char opcode);
/* Returns true if the major/minor values are 4/1. */
int pcmm_is_gateid(uint8_t major, uint8_t minor);

/* Returns true if the major/minor values are 5/1. */
int pcmm_is_gatespec(uint8_t major, uint8_t minor);

/* Returns true if the major value is 6. */
int pcmm_is_classifier(uint8_t major);
/* Char stream to gate id */
uint64_t atog(char* stream);

/*
 * Convert the direction, DSCP/TOS enable and persistence fields to a 1-byte field.
 * Bit 0:       direction bit, MUST be either zero for a downstream gate or one
 *              for an upstream gate.
 * Bit 1:       DSCP/TOS enable bit, MUST be either zero to disable DSCP overwrite
 *              or one to enable.
 * Bit 2:       MUST be either zero (default)to diasble gate persistence.
 * Bits 3-7:    Reserved, must be zero.
 *
 *   0      1       2       3       4       5       6         7
 * +-------------------------------------------+----------+--------+
 * | Differentiated Services Code Point (DSCP) | Not used | Enable |
 * +-------------------------------------------+----------+--------+
 * | IP Precedence              | IP TOS                  | Enable |
 * |----------------------------+-------------------------+--------+
 *
 * @direction        Direction field must be "upstream" or "downstream".
 * @dscp_enable_bit  Not a bit but a 1 or 0.
 * @persistence_bit  Not implemented.
 */
uint8_t vtof(char* direction, uint8_t dscp_enable_bit, uint8_t persistence_bit);

/*
 * Convert the priority, preemption and configurable bits to the session class ID
 *
 * Bit 0-2: Priority, a number from 0 to 7, where 0 is low priority and 7 is high.
 * Bit 3:   Preemption, set to enable preemption of bandwidth allocated to lower
 *          priority sessions if necessary (if supported).
 * Bit 4-7: Configurable, default to 0
 *
 * @priority_bit    The priority field describes the relative importance of the session
 *                  as compared to other sessions generated by the same PDP
 * @preemption_bit  The preemption bit is used to by a PDP to direct the PEP to apply
 *                  a priority-based admission control
 * @conf_bit        Default to zero
 */
uint8_t vtoc(uint8_t priority_bit, uint8_t preemption_bit, uint8_t conf_bit);

/*
 * Build the Transaction ID object S-Num = 1, S-Type = 1
 *
 * @dst                 Destination character array the built COPS object is stored.
 * @transaction_id      TransactionID is a 2-byte unsigned integer quantity, which
 *                      contains a token that is used by the Application Manager to
 *                      match responses from the Policy Server and by the Policy Server
 *                      to match responses from the CMTS to the previous requests.
 * @gate_command_type   Gate Command Type is a 2-byte unsigned integer value which
 *                      identifies the Gate Control message type.
 *
 *      +--------------+--------------+--------------+
 *      | Length = 8   | S-Num = 1    | S-Type = 1   |
 *      +--------------+-------+------+--------------+
 *      |   Transaction ID     |  Gate Command Type  |
 *      +--------------------------------------------+
 */
void pcmm_transaction_identifier(uint8_t* dst, uint16_t transaction_id, uint16_t gate_command_type);

/*
 * Build the Application ID object S-Num = 2, S-Type = 1
 *
 * @dst         Destination character array the built COPS object is stored
 * @app_tag     The Application Manager Tag is a 2-byte unsigned integer value which
 *              identifies the Application Manager responsible for handling the session.
 * @app_type    The Application Type is a 2-byte unsigned integer value which identifies
 *              the type of application that this gate is associated with.
 *
 *      +--------------+--------------+--------------+
 *      | Length = 8   | S-Num = 2    | S-Type = 1   |
 *      +--------------+-------+------+--------------+
 *      |   Application Type   |  Application Tag    |
 *      +--------------------------------------------+
 */
void pcmm_application_identifier(uint8_t* dst, uint16_t app_tag, uint16_t app_type);

/*
 * Build the IPv4 subscriber ID object S-Num = 3, S-Type = 1
 *
 * @dst         Destination character array the built COPS object is stored.
 * @ip_repr     SubscriberID object contains a 4-byte value giving the IPv4 address
 *              (represented as four concatenated octet values) of the subscriber for
 *              this service request.
 *
 *      +--------------+--------------+--------------+
 *      | Length = 8   | S-Num = 3    | S-Type = 1   |
 *      +--------------+--------------+--------------+
 *      |     SubscriberID (4-octet IPv4 Address)    |
 *      +--------------------------------------------+
 */
void pcmm_subscriber4_identifier(uint8_t* dst, uint32_t ip_repr);

/*
 * Build the IPv6 subscriber ID object S-Num = 3, S-Type = 2
 *
 * @dst         Destination character array the built COPS object is stored
 * @sub_id      SubscriberID object contains a 16-byte value giving the IPv6 address
 *              (represented as 16 concatenated octet values) of the subscriber for
 *              this service request.
 * @ip_len      Length of the Subsctiber ID
 *
 *      +--------------+--------------+--------------+
 *      | Length = 8   | S-Num = 3    | S-Type = 2   |
 *      +--------------+--------------+--------------+
 *      |     SubscriberID (16-octet IPv6 Address)   |
 *      +--------------------------------------------+
 */
void pcmm_subscriber6_identifier(uint8_t* dst, const char* sub_id, int ip_len);

/*
 * Build the Gate ID object S-Num = 4, S-Type = 1
 *
 * @dst         Destination character array the built COPS object is stored.
 * @gate_id     GateID is a 4-byte unsigned integer value which identifies the Gate referenced
 *              in the command message, or referenced by the CMTS for a response message.
 *
 *      +--------------+--------------+--------------+
 *      | Length = 8   | S-Num = 4    | S-Type = 1   |
 *      +--------------+--------------+--------------+
 *      |                   GateID                   |
 *      +--------------------------------------------+
 */
void pcmm_gate_identifier(uint8_t* dst, uint32_t gate_id);

/*
 * Build and return an encoded IPCablecom Multimedia Gate
 *
 * The DSCP/TOS Overwrite is a 1-byte bit field [IETF RFC 2474], depending upon network
 * management strategy. This field, combined with the 1-byte DSCP/TOS Mask, is used to
 * identify particular bits within the IPv4 DSCP/TOS byte.
 *
 * +----------------------------------------------------------------------+
 * |  Length = 16   |         S-Num = 5         |        S-Type = 1       |
 * ------------------------------------------------------------------------
 * | Flags          | DSCP/TOS Field   | DSCP/TOS Mask | Session Class ID |
 * ------------------------------------------------------------------------
 * | Timer T1                       |                    Timer T2         |
 * ------------------------------------------------------------------------
 * | Timer T3                       |                    Timer T4         |
 * ------------------------------------------------------------------------
 *
 * Timers T1, T2, T3, and T4 are 2-byte unsigned integers specified in seconds. A value
 * of zero for T1 indicates that the CMTS provisioned value for the timer MUST be used.
 * T2 corresponds to the DOCSIS Admitted timer and T3 corresponds to the  DOCSIS Active
 * timer. A zero value for these timers indicates that the timer MUST be disabled.
 */
int pcmm_gate(unsigned char* dst, char* dir, uint8_t, uint8_t, uint8_t, uint8_t, int, int, int, int);

/*
 * Build and return an eight-tuple (legacy) Classifier
 *
 * +-------------------+-----------------------------------------+
 * |  Length = 24      |   S-Num = 6   |   S-Type = 1            |
 * ---------------------------------------------------------------
 * |  Protocol ID      |   DSCP/TOS Field     |   DSCP/TOS Mask  |
 * ---------------------------------------------------------------
 * |  Source IP Address (4-octets)                               |
 * ---------------------------------------------------------------
 * |  Destination IP Address (4-octets)                          |
 * ---------------------------------------------------------------
 * |  Source Port            |          Destination Port         |
 * ---------------------------------------------------------------
 * |  Priority               |          Reserved                 |
 * +-------------------------------------------------------------+
 *
 * The Classifier object is retained for legacy purposes. That being said, the
 * legacy Classifier object will be deprecated from the specification in a
 * future release.
 */
void pcmm_legacy_classifier(unsigned char* dst, uint16_t, int, int, char*, char*, int, int, int, int);

/*
 * Build and return an extended classifier
 *
 * ---------------------------------------------------------------
 * |  Length = 40      |   S-Num = 6   |   S-Type = 1            |
 * ---------------------------------------------------------------
 * |  Protocol ID      |   DSCP/TOS Field     |   DSCP/TOS Mask  |
 * ---------------------------------------------------------------
 * |  Source IP Address (4-octets)                               |
 * ---------------------------------------------------------------
 * |  Source IP Mask (4-octets)                                  |
 * ---------------------------------------------------------------
 * |  Destination IP Address (4-octets)                          |
 * ---------------------------------------------------------------
 * |  Destination IP Mask (4-octets)                             |
 * ---------------------------------------------------------------
 * |  Source Port Start         |       Source Port End          |
 * ---------------------------------------------------------------
 * |  Destination Port Start    |       Destination Port End     |
 * ---------------------------------------------------------------
 * |  ClassifierID      |    Priority     |    Activation State  |
 * ---------------------------------------------------------------
 * |  Action                    |          Reserved              |
 * ---------------------------------------------------------------
 */
void pcmm_extended_classifier(unsigned char* dst, uint16_t, char*, char*, int, int, char*, char*, int, int, int, int,
                              int, int, int, int);

/*
 * Build and return an ipv6 classifier
 *
 * ---------------------------------------------------------------
 * |  Length = 64      |   S-Num = 6   |   S-Type = 3            |
 * ---------------------------------------------------------------
 * |  Reserved  |  Flags  |  tc-low  |   tc-high   |   tc-mask   |
 * ---------------------------------------------------------------
 * |  Flow Label                                                 |
 * ---------------------------------------------------------------
 * |  Next Header Type  |  Src Prefix Len   |  Dst Prefix Len    |
 * ---------------------------------------------------------------
 * |  IPv6 Source Address (16-octets)                            |
 * ---------------------------------------------------------------
 * |  IPv6 Destination Address (16-octets)                       |
 * ---------------------------------------------------------------
 * |  Source Port Start         |       Source Port End          |
 * ---------------------------------------------------------------
 * |  Destination Port Start    |       Destination Port End     |
 * ---------------------------------------------------------------
 * |  ClassifierID      |    Priority     |    Activation State  |
 * ---------------------------------------------------------------
 * |  Action                    |          Reserved              |
 * ---------------------------------------------------------------
 */
void pcmm_ipv6_classifier(unsigned char* dst, int tc_low, int tc_high, int tc_mask, int flow_label, int nh_type,
                          const char* src_ip6, const char* dst_ip6, int src_port_s, int src_port_e, int dst_port_s,
                          int dst_port_e, int class_id, int priority, int actstate, int action);

/*
 * Pack the destination buffer with TSpec and RSpec values in order to
 * perform authorization, reservation, commit operations on the CMTS.
 *
 * Fields
 *  token_bucket_rate   IEEE Floating point number  10,000
 *  token_bucket_size   IEEE Floating point number  200
 *  peak_data_rate      IEEE Floating point number  10,000
 *  rate                IEEE Floating point number  10,000
 *  min_policed_unit    Integer                     200
 *  max_packet_size     Integer                     200
 *  slack_term          Integer                     2000
 *
 * @dst                 Buffer where the spec is packed
 */
void bitrates(unsigned char* dst);

/*
 * Pack the DOCSIS Service Class Name object with the given SCN
 * to be associated with the gate.
 *
 * @dst     Buffer wherer the SCN will be packed
 * @scn     Service Class Name value (i.e., 'dSMI001'). The Service Class Name
 * is shall be 2-16 bytes of null-terminated ASCII string. (Refer to clause C.2
 * of [1]). This name shall be padded with null bytes to align on a 4-byte
 * boundary.
 */
void pcmm_scn_envelope(unsigned char* dst, const unsigned char* scn);

/*
 * Pack the Flow Spec object that defines the Traffic Profile associated
 * with the gate.
 */
void pcmm_flowspec_envelope(unsigned char* dst, int service_number);

/*
 * Populate rpt_t transaction ID fields (transaction ID, gate command type)
 *
 * @report  Report object to store unpacked data
 * @id     Transaction ID value read in report-state message
 * @action REQ gate command type (set, get or delete)
 */
void pcmm_decode_transaction(pcmm_rpt_t* report, uint16_t id, uint16_t action);

/*
 * Populate rpt_t application manager fields.
 *
 * @report  Report object to store unpacked data
 * @app_tag Application manager tag value
 * @app_id  Application manager ID value
 **/
void pcmm_decode_application(pcmm_rpt_t* report, uint16_t app_tag, uint16_t app_id);

/*
 * Populate rpt_t error fields (description, error code, error sub-code)
 *
 * @report  Report object to store unpacked data
 * @error   Primary error code read in report-state message
 * @subcode Secondary error code read in report-state message
 */
void pcmm_decode_error(pcmm_rpt_t* report, uint16_t error, uint16_t subcode);

/*
 * Populate rpt_t gate specification fields
 *
 * @report  Report object to store unpacked data
 * @block   Slice of report-state data containing gate spec. object
 */
int pcmm_decode_gate(pcmm_rpt_t* report, char* block);

/*
 * Populate rpt_t classifier specification fields
 *
 * @report  Report object to store unpacked data
 * @block   Slice of report-state data containing classifier spec. object
 */
int pcmm_decode_classifier(pcmm_rpt_t* report, char* block);

/*
 * Populate rpt_t extended classifier specification fields
 *
 * @report  Report object to store unpacked data
 * @block   Slice of report-state data containing extended classifier spec. object
 */
int pcmm_decode_extended(pcmm_rpt_t* report, char* block);

/*
 * Reason is a 2-byte unsigned integer field which MUST indicate one
 * of the following reasons for this update (NIL on no match/default).
 *
 * Note: Return NIL when no match is found or other on 65535
 */
char* pcmm_gatestate_rpt_reason(int value);

/*
 * State is a 2-byte unsigned integer field which MUST indicate
 * one of the following states (NIL on no match/default).
 *
 * Note: Return NIL when no match is found
 */
char* pcmm_gatestate_rpt_state(int value);

/*
 * Create a Gate State Report log
 */
int pcmm_gatestate_rpt(uint16_t state, uint16_t reason);

#endif
