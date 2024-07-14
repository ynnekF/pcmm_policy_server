#include "pcmm.h"

__attribute__((deprecated("wip"))) void pcmm_decode_classifier_alt(char* block);
__attribute__((deprecated("wip"))) void pcmm_decode_extclass_alt(char* block);

/*
 * COPS Common Object format utility - Populate the given destination buffer (uint8_t) with the
 * provided S-Num and S-Type OR C-Num and C-Type values. The buffer should expect the first two
 * bytes be populated by the length given, while the next two bytes are reserved for the unique
 * object ID S/C ID values.
 */
static void pcmm_oid_vlen(uint8_t* dst, uint8_t num, uint8_t type, uint8_t len);

/*
 * COPS Common Object format utility - Populate the given destination buffer (uint8_t) with the
 * provided S-Num and S-Type OR C-Num and C-Type values. The buffer should expect the first two
 * bytes be populated by a default length of 8, while the next two bytes are reserved for the
 * unique object ID S/C ID values.
 */
static void pcmm_oid(uint8_t* dst, uint8_t num, uint8_t type);

uint8_t
vtof(char* direction, uint8_t dscp_enable_bit, uint8_t persistence_bit) {
        uint8_t flags = 0;
        uint8_t direction_bit = 0;

        if (MATCHES(direction, GATE_DIR_UPSTREAM))
                direction_bit = 1;

        flags |= (direction_bit & 0x01) << 0;
        flags |= (dscp_enable_bit & 0x01) << 1;
        flags |= (persistence_bit & 0x01) << 2;
        return flags;
}

uint8_t
vtoc(uint8_t priority_bit, uint8_t preemption_bit, uint8_t conf_bit) {
        uint8_t session_class_id = 0;

        session_class_id |= (priority_bit & 0x07) << 0;
        session_class_id |= (preemption_bit & 0x01) << 3;
        session_class_id |= (conf_bit & 0x0F) << 4;

        return session_class_id;
}

uint64_t
atog(char* stream) {
        uint64_t gate_id;
        memcpy(&gate_id, stream, sizeof(gate_id));
        return ntohl(gate_id);
}

int
pcmm_is_gateid(uint8_t major, uint8_t minor) {
        return (major == 4 && minor == 1);
}

int
pcmm_is_gatespec(uint8_t major, uint8_t minor) {
        return (major == 5 && minor == 1);
}

int
pcmm_is_classifier(uint8_t major) {
        return major == 6;
}

char*
pcmm_otoact(unsigned char code) {
        switch ((int)code) {
                case 1:  return "GATE-ALLOC";
                case 2:  return "GATE-ALLOC-ACK";
                case 3:  return "GATE-ALLOC-ERR";
                case 4:  return "GATE-SET";
                case 5:  return "GATE-SET-ACK";
                case 6:  return "GATE-SET-ERR";
                case 7:  return "GATE-INFO";
                case 8:  return "GATE-INFO-ACK";
                case 9:  return "GATE-INFO-ERR";
                case 10: return "GATE-DELETE";
                case 11: return "GATE-DELETE-ACK";
                case 12: return "GATE-DELETE-ERR";
                case 13: return "GATE-OPEN";
                case 14: return "GATE-CLOSE";
                default: return "NIL";
        }
}

char*
pcmm_otoerr(unsigned char opcode) {
        switch ((int)opcode) {
                case 1:   return "Insufficient resources";
                case 2:   return "Unknown Gate ID";
                case 3:   return "Unknown";
                case 4:   return "Unknown";
                case 5:   return "Unknown";
                case 6:   return "Missing Required Object";
                case 7:   return "Invalid Object";
                case 8:   return "Volume based usage limit exceeded";
                case 9:   return "Time based usage limit exceeded";
                case 10:  return "Session Class Limit Exceeded";
                case 11:  return "Undefined Service Class Name";
                case 12:  return "Incompatible Envelope";
                case 13:  return "Invalid subscriber identifier";
                case 14:  return "Unauthorized AMID";
                case 15:  return "Number of Classifiers not supported";
                case 16:  return "Policy Exception";
                case 17:  return "Invalid field value in object";
                case 18:  return "Transport Error";
                case 19:  return "Unknown gate command";
                case 20:  return "DOCSIS 1.0 CM";
                case 21:  return "Number of SIDs exceeded in CM";
                case 22:  return "Number of SIDs exceeded in CMTS";
                case 23:  return "Unauthorized PSID";
                case 24:  return "No state for PDPD";
                case 25:  return "Unsupport Sync Type";
                case 26:  return "State data incomplete";
                case 127: return "Other, Unspecified Error";
                default:  return "NIL";
        }
}

char*
pcmm_mmtoid(unsigned char* major, unsigned char* minor) {
        int oc = (uint64_t)major;
        int _minor = (uint64_t)minor;

        switch (oc) {
                case 1:  return "Transaction Identifier";
                case 2:  return "Application Manager Identifier";
                case 3:  return "Subscriber Identifier";
                case 4:  return "Gate Identifier";
                case 5:  return "Gate Specification";
                case 9:  return "Volume Based Usage Limit";
                case 10: return "Time Based Usage Limit";
                case 11: return "Opaque Data";
                case 12: return "Gate Time Info";
                case 13: return "Gate Usage Info";
                case 14: return "Packet Cable Error";
                case 15: return "Gate State";
                case 16: return "Version Info";
                case 17: return "Policy Server Identifier";
                case 18: return "Synch Options";
                case 19: return "Msg Receipt Keys";
                case 8:  return (_minor == 1) ? "Event-Generation-Info" : "NIL";
                case 6:
                        switch (_minor) {
                                case 1:  return "Classifier";
                                case 2:  return "Extended Classifier";
                                case 3:  return "IPv6 Classifier";
                                default: return "NIL";
                        }
                case 7:
                        switch (_minor) {
                                case 1:  return "Subscriber Identifier";
                                case 2:  return "Flow Spec";
                                case 3:  return "DOCSIS Service Class Name";
                                case 4:  return "Best Effort Service";
                                case 5:  return "Non-Real-Time Polling Service";
                                case 6:  return "Real-Time Polling Service";
                                case 7:  return "Unsolicited Grant Service";
                                case 8:  return "Unsolicited Grant Service with Activity Detection";
                                case 9:  return "Downstream";
                                default: return "NIL";
                        }
                default: return "NIL";
        }
}

static inline void
pcmm_oid_vlen(uint8_t* dst, uint8_t num, uint8_t type, uint8_t len) {
        /* Store variable length. */
        pack_u16_be(dst, len);

        /* Store identifiers. */
        *(dst + 2) = num;
        *(dst + 3) = type;
}

static inline void
pcmm_oid(uint8_t* dst, uint8_t num, uint8_t type) {
        /* Store common length 8. */
        pack_u16_be(dst, 8);

        /* Store identifiers. */
        *(dst + 2) = num;
        *(dst + 3) = type;
}

void
pcmm_transaction_identifier(uint8_t* dst, uint16_t transaction_id, uint16_t gate_command_type) {
        /* Pack transaction ID object S-Num = 1, S-Type = 1. */
        pcmm_oid(dst, 1, 1);

        /* 2-byte token to match Policy Server responses. */
        pack_u16_be(dst + 4, transaction_id);

        /* 2-byte token which IDs Gate Control Type. */
        pack_u16_be(dst + 6, gate_command_type);
}

void
pcmm_application_identifier(uint8_t* dst, uint16_t app_tag, uint16_t app_type) {
        /* Pack Application Manager object, S-Num = 2, S-Type = 1. */
        pcmm_oid(dst, 2, 1);

        /* 2-byte token used to ID App. Mgr. responses. */
        pack_u16_be(dst + 4, app_tag);

        /* 2-byte token to ID gate-related application. */
        pack_u16_be(dst + 6, app_type);
}

void
pcmm_subscriber4_identifier(uint8_t* dst, uint32_t ip_repr) {
        /* Pack Subscriber ID object, S-Num = 3, S-Type = 1. */
        pcmm_oid(dst, 3, 1);

        /* Pack the 32-bit repr. of the IPv4 addr. */
        pack_u32_be(dst + 4, ip_repr);
}

void
pcmm_subscriber6_identifier(uint8_t* dst, const char* sub_id, int ip_len) {
        /* Pack Subscriber ID object, S-Num = 3, S-Type = 2. */
        pcmm_oid_vlen(dst, 3, 2, ip_len);

        /* Pack the IPv6 addr. */
        uint8_t* ptr = (uint8_t*)(dst + 4);
        pack_ip6(ptr, sub_id);
}

void
pcmm_gate_identifier(uint8_t* dst, uint32_t gate_id) {
        /* Pack Gate ID object S-Num = 4, S-Type = 1. */
        pcmm_oid(dst, 4, 1);

        /* 4-byte value which IDs referenced gate. */
        pack_u32_be(dst + 4, gate_id);
}

int
pcmm_gate(unsigned char* dst, char* dir, uint8_t pri, uint8_t preempt, uint8_t overwrite, uint8_t mask, int t1, int t2,
          int t3, int t4) {

        /* Create the flags and session class ID bit-fields. */
        uint8_t flags = vtof(dir, overwrite, 0);
        uint8_t class = vtoc(pri, preempt, 0);

        /* Pack length and S-numbers. */
        pack_u16_be(dst, GATE_SPEC_LEN); /* GateSpec length = 16. */
        pack_u8(dst + 2, GATE_SNUM);     /* GateSpec S-Num = 5.   */
        pack_u8(dst + 3, GATE_STYPE);    /* GateSpec S-Type = 1.  */

        /* Pack DSCP/ToS fields. */
        pack_u8(dst + 4, flags);
        pack_u8(dst + 5, overwrite);
        pack_u8(dst + 6, mask);
        pack_u8(dst + 7, class);

        /* Pack timers. */
        pack_u16_be(dst + 8, t1);
        pack_u16_be(dst + 10, t2);
        pack_u16_be(dst + 12, t3);
        pack_u16_be(dst + 14, t4);
        return 16;
}

void
pcmm_legacy_classifier(unsigned char* dst, uint16_t protocol, int field, int mask, char* src_ip, char* dst_ip,
                       int src_port, int dst_port, int priority, int reserved) {
        unsigned int srcip_int = ip4_toi(src_ip);
        unsigned int dstip_int = (dst_ip) ? itoi(dst_ip, AF_INET) : 0;

        /* Legacy classifier: length = 24, S-Num = 6, S-Type = 1*/
        pack_u16_be(dst, 24);
        pack_u8(dst + 2, 6);
        pack_u8(dst + 3, 1);
        pack_u16_be(dst + 4, protocol);

        /* Pack DSCP/TOS fields. */
        pack_u8(dst + 6, field);
        pack_u8(dst + 7, mask);

        /* Pack source/destination fields. */
        pack_u32_be(dst + 8, srcip_int);
        pack_u32_be(dst + 12, dstip_int);
        pack_u16_be(dst + 16, src_port);
        pack_u16_be(dst + 18, dst_port);
        pack_u8(dst + 20, priority);
        pack_u8(dst + 21, reserved);
        pack_u8(dst + 22, reserved);
        pack_u8(dst + 23, reserved);
}

void
pcmm_extended_classifier(unsigned char* dst, uint16_t protocol, char* src_ip, char* src_mask, int src_port_s,
                         int src_port_e, char* dst_ip, char* dst_mask, int dst_port_s, int dst_port_e, int priority,
                         int field, int mask, int class_id, int act_state, int action) {

        /* Convert the source/destination IPs to integers. */
        unsigned int srcip_int = ip4_toi(src_ip);
        unsigned int dstip_int = (dst_ip) ? itoi(dst_ip, AF_INET) : 0;

        /* Conver the source/destination masks to integers. */
        unsigned int smask_int = ip4_toi(src_mask);
        unsigned int dmask_int = ip4_toi(dst_mask);

        pack_u16_be(dst, 40); /* Extended classifier length = 24. */
        pack_u8(dst + 2, 6);  /* Extended classifier S-Num = 6. */
        pack_u8(dst + 3, 2);  /* Extended classifier S-Type = 2. */

        pack_u16_be(dst + 4, protocol);

        /* Pack DSCP/TOS fields. */
        pack_u8(dst + 6, field);
        pack_u8(dst + 7, mask);

        /* Pack source/destination IPs and masks. */
        pack_u32_be(dst + 8, srcip_int);
        pack_u32_be(dst + 12, smask_int);
        pack_u32_be(dst + 16, dstip_int);
        pack_u32_be(dst + 20, dmask_int);

        /* Pack source/destination ports. */
        pack_u16_be(dst + 24, src_port_s);
        pack_u16_be(dst + 26, src_port_e);
        pack_u16_be(dst + 28, dst_port_s);
        pack_u16_be(dst + 30, dst_port_e);
        pack_u16_be(dst + 32, class_id);
        pack_u8(dst + 34, priority);
        pack_u8(dst + 35, act_state);
        pack_u8(dst + 36, action);
}

void
pcmm_ipv6_classifier(unsigned char* dst, int tc_low, int tc_high, int tc_mask, int flow_label, int nh_type,
                     const char* src_ip6, const char* dst_ip6, int src_port_s, int src_port_e, int dst_port_s,
                     int dst_port_e, int class_id, int priority, int actstate, int action) {

        pack_u16_be(dst, CLFV6_LEN);   /* IPv6 classifier length = 64. */
        pack_u8(dst + 2, CLFV6_SNUM);  /* IPv6 classifier S-Num = 6. */
        pack_u8(dst + 3, CLFV6_STYPE); /* IPv6 classifier S-Type = 3. */

        dst[4] = 0; /* Reserved. */

        dst[5] = tc_low;  /* IPv6 classifier traffic class range. */
        dst[6] = tc_high; /* IPv6 classifier traffic class range. */
        dst[7] = tc_mask; /* IPv6 classifier traffic class mask. */

        pack_u32_be(dst + 8, flow_label); /* IPv6 Flow Label. */

        /*
         * IPv6 Classifier Next Header Type field
         * "256": Matches all IPv6 traffic regardless.
         * "257": Matches both TCP and UDP traffic.
         */
        pack_u16_be(dst + 12, nh_type);

        /*
         * IPv6 classifier Source/Destination Prefix lengths
         * The value of these fields specify the most significant bits of an
         * IPv6 address that are used to determine address range and subnetID.
         * If this pararmeter is omitted, then assume a default value of 128.
         */
        uint8_t src_prefix_len = 0, dst_prefix_len = 0;

        if (!(MATCHES(src_ip6, "::/0")) && (!(MATCHES(src_ip6, "")))) {
                src_prefix_len = prefixlen(src_ip6);
        }
        if (!(MATCHES(dst_ip6, "::/0")) && (!(MATCHES(dst_ip6, "")))) {
                dst_prefix_len = prefixlen(dst_ip6);
        }

        pack_u8(dst + 14, src_prefix_len);
        pack_u8(dst + 15, dst_prefix_len);

        /*
         * IPv6 classifier Source/Destination addresses.
         * The value of the field specifies the matching value for the IPv6 source/destination
         * address. An IPv6 packet with IPv6 source/destination address "ip6-src/dst" matches
         * this if (src AND smask) = (ip6-src AND smask) OR (dst AND dmask) = (ip6-dst AND dmask)
         * "smask" and "dmask" are computed by setting the most significant 'n' bits of smask to
         * 1, where 'n' is IPv6 Source Prefix Length in bits.
         */
        if (strcmp(src_ip6, "0.0.0.0") != 0 || strcmp(src_ip6, "::/0") != 0)
                pack_ip6(dst + 16, src_ip6);

        if (strcmp(dst_ip6, "0.0.0.0") != 0 || strcmp(dst_ip6, "::/0") != 0)
                pack_ip6(dst + 32, dst_ip6);

        pack_u16_be(dst + 48, src_port_s);
        pack_u16_be(dst + 50, src_port_e);
        pack_u16_be(dst + 52, dst_port_s);
        pack_u16_be(dst + 54, dst_port_e);

        pack_u16_be(dst + 56, class_id);

        pack_u8(dst + 58, priority);
        pack_u8(dst + 59, actstate);
        pack_u8(dst + 60, action);

        pack_u16_be(dst + 62, 0); /* Reserved. */
}

void
bitrates(unsigned char* dst) {
        size_t iter = 0;

        for (int i = 0; i < 3; i++) {
                /* Token bucket rate. */
                pack_reverse(dst, &iter, 10000);

                /* Token bucket size. */
                pack_reverse(dst, &iter, 200);

                /* Peak data rate. */
                pack_reverse(dst, &iter, 10000);

                /* Minimum policed unit. */
                pack_u32_be(dst + iter, 200);
                iter += 4;

                /* Maximum packet size. */
                pack_u32_be(dst + iter, 200);
                iter += 4;

                /* Rate. */
                pack_reverse(dst, &iter, 10000);

                /* Slack-term. */
                pack_u32_be(dst + iter, 2000);
                iter += 4;
        }
}

void
pcmm_flowspec_envelope(unsigned char* dst, int service_number) {
        pack_u16_be(dst, 92);
        pack_u8(dst + 2, FLOW_SPEC_SNUM);  /* Flow Spec envelope S-Num = 7. */
        pack_u8(dst + 3, FLOW_SPEC_STYPE); /* Flow Spec envelope S-Type = 1. */
        pack_u8(dst + 4, 7);
        /*
         * Corresponds to the RSVP FlowSpec service number. If service number
         * is set to five, this indicates Controlled Load service and the CMTS
         * must utilize TSpec values (token bucket params.). If service number
         * is set to two, this signals Guaranteed service and the CMTS must ut-
         * ilize both TSpec and RSpec values to perform auth., reserve., commit.
         */
        pack_u8(dst + 5, service_number);
        pack_u8(dst + 6, 0); /* Reserved. */
        pack_u8(dst + 7, 0); /* Reserved. */

        /* Store the envelope bitrates. */
        bitrates(dst + 8);
}

void
pcmm_scn_envelope(unsigned char* dst, const unsigned char* scn) {
        pack_u16_be(dst, 20);
        pack_u8(dst + 2, DOCSIS_SCN_SNUM);  /* SCN envelope S-Num = 7. */
        pack_u8(dst + 3, DOCSIS_SCN_STYPE); /* SCN envelope S-Type = 2. */
        pack_u8(dst + 4, 7);
        pack_u8(dst + 5, 0); /* Reserved. */
        pack_u8(dst + 6, 0); /* Reserved. */
        /*
         * Message Length is a 4-byte unsigned integer value giving the
         * size of the overall message in octets. Messages MUST be aligned
         * on 4-byte boundaries, so the length MUST be a multiple of four.
         */
        int alignment = (strlen((const char*)scn) + 1) % 4;
        int j = 7;

        for (int i = 0; i < alignment; i++) pack_u8(dst + j++, 0);

        for (int i = 0; i < 8; i++) pack_u8(dst + j++, scn[i]);
}

void
pcmm_decode_classifier_alt(char* block) {
        size_t i = 0;
        uint8_t* ptr = (uint8_t*)block;
        uint16_t ipp = unpack_u16_it(ptr, &i);

        /* Unpack DSCP/ToS fields. */
        uint8_t tosf = unpack_u8_it(ptr, &i);
        uint8_t tosm = unpack_u8_it(ptr, &i);

        /* Unpack src/dst IPs and ports. */
        uint32_t sip = unpack_u32_it(ptr, &i);
        uint32_t dip = unpack_u32_it(ptr, &i);
        uint16_t sps = unpack_u16_it(ptr, &i);
        uint16_t dps = unpack_u16_it(ptr, &i);

        info("Classifier: IPID=%i, ToS=%i/%i, IPs=%i/%i, Ports=%i/%i", ipp, tosf, tosm, sip, dip, sps, dps);
}

void
pcmm_decode_extclass_alt(char* block) {
        size_t i = 0;
        uint8_t* ptr = (uint8_t*)block;
        uint16_t ip_proto = unpack_u16_it(ptr, &i);
        uint8_t tosf = unpack_u8_it(ptr, &i);
        uint8_t tosm = unpack_u8_it(ptr, &i);
        uint32_t src_ip = unpack_u32_it(ptr, &i);
        uint32_t src_mk = unpack_u32_it(ptr, &i);
        uint32_t dst_ip = unpack_u32_it(ptr, &i);
        uint32_t dst_mk = unpack_u32_it(ptr, &i);
        uint16_t sps = unpack_u16_it(ptr, &i);
        uint16_t spe = unpack_u16_it(ptr, &i);
        uint16_t dps = unpack_u16_it(ptr, &i);
        uint16_t dpe = unpack_u16_it(ptr, &i);
        uint16_t cid = unpack_u16_it(ptr, &i);
        uint8_t prior = unpack_u8_it(ptr, &i);
        uint8_t state = unpack_u8_it(ptr, &i);
        uint8_t action = unpack_u8_it(ptr, &i);

        info("EClassifier: IPProtocolId=%i, ToS=%i/%i, SrcIp=%i, DstIp=%i, Masks=%i/%i, "
             "SrcPorts=%i/%i, DstPorts=%i/%i",
             ip_proto, tosf, tosm, src_ip, dst_ip, src_mk, dst_mk, sps, spe, dps, dpe);
        info("EClassifier: ClassifierId=%i, Priority=%i, State=%i, Action=%i", cid, prior, state, action);
}

int
pcmm_decode_gate(pcmm_rpt_t* report, char* block) {
        size_t i = 0;
        uint8_t* ptr = (uint8_t*)block;

        report->flags = unpack_u8_it(ptr, &i);

        /* Gate TOS Fields. */
        report->tosf = unpack_u8_it(ptr, &i);
        report->tosm = unpack_u8_it(ptr, &i);
        report->class = unpack_u8_it(ptr, &i);

        /* Gate Timers .*/
        report->t1 = unpack_u16_it(ptr, &i);
        report->t2 = unpack_u16_it(ptr, &i);
        report->t3 = unpack_u16_it(ptr, &i);
        report->t4 = unpack_u16_it(ptr, &i);

        return 0;
}

int
pcmm_decode_classifier(pcmm_rpt_t* report, char* block) {
        size_t i = 0;
        uint8_t* ptr = (uint8_t*)block;

        report->proto_id = unpack_u16_it(ptr, &i);

        report->tosf = unpack_u8_it(ptr, &i);
        report->tosm = unpack_u8_it(ptr, &i);
        report->src_ip = unpack_u32_it(ptr, &i);
        report->dst_ip = unpack_u32_it(ptr, &i);
        report->src_port_start = unpack_u16_it(ptr, &i);
        report->dst_port_start = unpack_u16_it(ptr, &i);

        info("src_ip=%s", ito_ip4(report->src_ip));
        info("dst_ip=%s", ito_ip4(report->dst_ip));
        return 0;
}

int
pcmm_decode_extended(pcmm_rpt_t* report, char* block) {
        size_t i = 0;
        uint8_t* ptr = (uint8_t*)block;

        report->proto_id = unpack_u16_it(ptr, &i);
        report->tosf = unpack_u8_it(ptr, &i);
        report->tosm = unpack_u8_it(ptr, &i);
        report->src_ip = unpack_u32_it(ptr, &i);
        report->src_mk = unpack_u32_it(ptr, &i);
        report->dst_ip = unpack_u32_it(ptr, &i);
        report->dst_mk = unpack_u32_it(ptr, &i);
        report->src_port_start = unpack_u16_it(ptr, &i);
        report->src_port_end = unpack_u16_it(ptr, &i);
        report->dst_port_start = unpack_u16_it(ptr, &i);
        report->dst_port_end = unpack_u16_it(ptr, &i);
        report->classifier_id = unpack_u16_it(ptr, &i);
        report->priority = unpack_u8_it(ptr, &i);
        report->state = unpack_u8_it(ptr, &i);
        report->action = unpack_u8_it(ptr, &i);

        return 1;
}

void
pcmm_decode_error(pcmm_rpt_t* report, uint16_t error, uint16_t subcode) {
        char* description = pcmm_otoerr(error);

        report->packetcable_err_code = error;
        report->packetcable_err_subcode = subcode;
        report->packetcable_err_descr = description;

        warning("Report-State with error-code %u::%u, %s", report->packetcable_err_code,
                report->packetcable_err_subcode, report->packetcable_err_descr);
}

void
pcmm_decode_transaction(pcmm_rpt_t* report, uint16_t transaction_id, uint16_t gate_cmd) {
        report->transaction_id = transaction_id;
        report->gate_cmd = pcmm_otoact(gate_cmd);
}

void
pcmm_decode_application(pcmm_rpt_t* report, uint16_t app_tag, uint16_t app_id) {
        report->application_tag = app_tag;
        report->application_id = app_id;
}

char*
pcmm_gatestate_rpt_state(int value) {
        switch (value) {
                case 1:  return "Idle/Closed"; break;
                case 2:  return "Authorized"; break;
                case 3:  return "Reserved"; break;
                case 4:  return "Committed"; break;
                case 5:  return "Committed Recovery"; break;
                default: return "NIL";
        }
}

char*
pcmm_gatestate_rpt_reason(int value) {
        switch (value) {
                case 1:     return "Close Initiated by CMTS because of reservation reassignment";
                case 2:     return "Close Initiated by CMTS because of lack of DOCSIS responses";
                case 3:     return "Close Initiated by CMTS because of timer T1 expiry";
                case 4:     return "Close Initiated by CMTS because of timer T2 expiry";
                case 5:     return "Inactivity timer (T3) expired";
                case 6:     return "Close Initiated by CMTS because of lack of reservation maintenance";
                case 7:     return "Gate state unchanged, but volume limit reached";
                case 8:     return "Close Initiated by CMTS because of timer T4 expiry";
                case 9:     return "Gate State unchanged, but T2 expiry caused reservation reduction";
                case 10:    return "Gate State unchanged, but time limit reached";
                case 11:    return "Close Initiated by PS or CMTS, volume limit reached";
                case 12:    return "Close Initiated by PS or CMTS, time limit reached";
                case 13:    return "Close Initiated by CMTS, other";
                case 14:    return "Gate state unchanged, but SharedResourceID updated";
                case 15:    return "Close initiated by CMTS due to loss of shared resource";
                case 16:    return "Persistent Gate idle due to cable modem going offline";
                case 17:    return "Persistent Gate recreated by CMTS due to cm coming online";
                case 18:    return "Persistent Gate deleted from CMTS gate database";
                case 65535: return "Other";
                default:    return "NIL";
        }
}

int
pcmm_gatestate_rpt(uint16_t state, uint16_t reason) {
        if (!reason || reason == 65535)
                return 0;

        char* convs = pcmm_gatestate_rpt_state(state);
        char* convr = pcmm_gatestate_rpt_reason(reason);

        info("GateState (%u::%u) %s: %s", state, reason, convs, convr);
        return 1;
}

int
write_report(FILE* fp, pcmm_rpt_t rpt, int ct) {
        unsigned long gate_id = rpt.gate_id;

        int stat = -1;

        if (!rpt.packetcable_err_descr || strcmp(rpt.packetcable_err_descr, "NIL") == 0) {
                if (ct == 0) {
                        stat = fprintf(fp, RESPONSE_GATE_SPEC_LEGACY_CLASSIFIER, gate_id, rpt.gate_cmd,
                                       rpt.application_id, rpt.flags, rpt.class, rpt.t1, rpt.t2, rpt.t3, rpt.t4,
                                       rpt.classifier_id, rpt.src_port_start, rpt.dst_port_start);

                } else if (ct == 1) {
                        stat = fprintf(fp, RESPONSE_GATE_SPEC_EXTENDED_CLASSIFIER, gate_id, rpt.gate_cmd,
                                       rpt.application_id, rpt.flags, rpt.class, rpt.t1, rpt.t2, rpt.t3, rpt.t4,
                                       rpt.classifier_id, rpt.src_port_start, rpt.src_port_end, rpt.dst_port_start,
                                       rpt.dst_port_end, rpt.priority, rpt.state, rpt.action);
                } else {
                        stat = fprintf(fp, RESPONSE_DEFAULT, gate_id, rpt.gate_cmd, rpt.application_id);
                }
        } else {
                stat = fprintf(fp, RESPONSE_ERROR, gate_id, rpt.gate_cmd, 0, rpt.packetcable_err_code,
                               rpt.packetcable_err_subcode, rpt.packetcable_err_descr);
        }
        fflush(fp);
        return stat;
}
