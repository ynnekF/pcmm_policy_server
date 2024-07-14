#include "tp_pcmm.h"

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
tp_pcmm_report_state_major_minor(void) {
        info("TEST: %s", __func__);
        /* clang-format off */
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)1, (uch*)1), "Transaction Identifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)2, (uch*)1), "Application Manager Identifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)3, (uch*)1), "Subscriber Identifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)4, (uch*)1), "Gate Identifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)5, (uch*)1), "Gate Specification"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)6, (uch*)1), "Classifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)6, (uch*)2), "Extended Classifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)6, (uch*)3), "IPv6 Classifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)1), "Subscriber Identifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)2), "Flow Spec"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)3), "DOCSIS Service Class Name"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)4), "Best Effort Service"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)5), "Non-Real-Time Polling Service"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)6), "Real-Time Polling Service"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)7), "Unsolicited Grant Service"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)8), "Unsolicited Grant Service with Activity Detection"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)7, (uch*)9), "Downstream"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)8, (uch*)1), "Event-Generation-Info"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)9, (uch*)1), "Volume Based Usage Limit"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)10, (uch*)1), "Time Based Usage Limit"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)11, (uch*)1), "Opaque Data"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)12, (uch*)1), "Gate Time Info"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)13, (uch*)1), "Gate Usage Info"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)14, (uch*)1), "Packet Cable Error"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)15, (uch*)1), "Gate State"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)16, (uch*)1), "Version Info"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)17, (uch*)1), "Policy Server Identifier"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)18, (uch*)1), "Synch Options"));
        TP_ASSERT(MATCHES(pcmm_mmtoid((uch*)19, (uch*)1), "Msg Receipt Keys"));
        /* clang-format on */
}

void
tp_pcmm_report_state_opcode_to_error(void) {
        info("TEST: %s", __func__);
        TP_ASSERT(MATCHES(pcmm_otoerr(1), "Insufficient resources"));
        TP_ASSERT(MATCHES(pcmm_otoerr(2), "Unknown Gate ID"));
        TP_ASSERT(MATCHES(pcmm_otoerr(3), "Unknown"));
        TP_ASSERT(MATCHES(pcmm_otoerr(4), "Unknown"));
        TP_ASSERT(MATCHES(pcmm_otoerr(5), "Unknown"));
        TP_ASSERT(MATCHES(pcmm_otoerr(6), "Missing Required Object"));
        TP_ASSERT(MATCHES(pcmm_otoerr(7), "Invalid Object"));
        TP_ASSERT(MATCHES(pcmm_otoerr(8), "Volume based usage limit exceeded"));
        TP_ASSERT(MATCHES(pcmm_otoerr(9), "Time based usage limit exceeded"));
        TP_ASSERT(MATCHES(pcmm_otoerr(10), "Session Class Limit Exceeded"));
        TP_ASSERT(MATCHES(pcmm_otoerr(11), "Undefined Service Class Name"));
        TP_ASSERT(MATCHES(pcmm_otoerr(12), "Incompatible Envelope"));
        TP_ASSERT(MATCHES(pcmm_otoerr(13), "Invalid subscriber identifier"));
        TP_ASSERT(MATCHES(pcmm_otoerr(14), "Unauthorized AMID"));
        TP_ASSERT(MATCHES(pcmm_otoerr(15), "Number of Classifiers not supported"));
        TP_ASSERT(MATCHES(pcmm_otoerr(16), "Policy Exception"));
        TP_ASSERT(MATCHES(pcmm_otoerr(17), "Invalid field value in object"));
        TP_ASSERT(MATCHES(pcmm_otoerr(18), "Transport Error"));
        TP_ASSERT(MATCHES(pcmm_otoerr(19), "Unknown gate command"));
        TP_ASSERT(MATCHES(pcmm_otoerr(20), "DOCSIS 1.0 CM"));
        TP_ASSERT(MATCHES(pcmm_otoerr(21), "Number of SIDs exceeded in CM"));
        TP_ASSERT(MATCHES(pcmm_otoerr(22), "Number of SIDs exceeded in CMTS"));
        TP_ASSERT(MATCHES(pcmm_otoerr(23), "Unauthorized PSID"));
        TP_ASSERT(MATCHES(pcmm_otoerr(24), "No state for PDPD"));
        TP_ASSERT(MATCHES(pcmm_otoerr(25), "Unsupport Sync Type"));
        TP_ASSERT(MATCHES(pcmm_otoerr(26), "State data incomplete"));
}

void
tp_pcmm_report_state_opcode_to_action(void) {
        info("TEST: %s", __func__);
        TP_ASSERT(MATCHES(pcmm_otoact(1), "GATE-ALLOC"));
        TP_ASSERT(MATCHES(pcmm_otoact(2), "GATE-ALLOC-ACK"));
        TP_ASSERT(MATCHES(pcmm_otoact(3), "GATE-ALLOC-ERR"));
        TP_ASSERT(MATCHES(pcmm_otoact(4), "GATE-SET"));
        TP_ASSERT(MATCHES(pcmm_otoact(5), "GATE-SET-ACK"));
        TP_ASSERT(MATCHES(pcmm_otoact(6), "GATE-SET-ERR"));
        TP_ASSERT(MATCHES(pcmm_otoact(7), "GATE-INFO"));
        TP_ASSERT(MATCHES(pcmm_otoact(8), "GATE-INFO-ACK"));
        TP_ASSERT(MATCHES(pcmm_otoact(9), "GATE-INFO-ERR"));
        TP_ASSERT(MATCHES(pcmm_otoact(10), "GATE-DELETE"));
        TP_ASSERT(MATCHES(pcmm_otoact(11), "GATE-DELETE-ACK"));
        TP_ASSERT(MATCHES(pcmm_otoact(12), "GATE-DELETE-ERR"));
        TP_ASSERT(MATCHES(pcmm_otoact(13), "GATE-OPEN"));
        TP_ASSERT(MATCHES(pcmm_otoact(14), "GATE-CLOSE"));
}

void
tp_pcmm_report_state_gate_state_lookup(void) {
        info("TEST: %s", __func__);
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_state(0), "NIL"))
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_state(1), "Idle/Closed"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_state(2), "Authorized"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_state(3), "Reserved"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_state(4), "Committed"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_state(5), "Committed Recovery"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_state(6), "NIL"));
}

void
tp_pcmm_report_state_gate_state_reason(void) {
        info("TEST: %s", __func__);
        /* clang-format off */
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(0), "NIL"))
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(1), "Close Initiated by CMTS because of reservation reassignment"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(2), "Close Initiated by CMTS because of lack of DOCSIS responses"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(3), "Close Initiated by CMTS because of timer T1 expiry"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(4), "Close Initiated by CMTS because of timer T2 expiry"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(5), "Inactivity timer (T3) expired"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(6), "Close Initiated by CMTS because of lack of reservation maintenance"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(7), "Gate state unchanged, but volume limit reached"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(8), "Close Initiated by CMTS because of timer T4 expiry"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(9), "Gate State unchanged, but T2 expiry caused reservation reduction"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(10), "Gate State unchanged, but time limit reached"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(11), "Close Initiated by PS or CMTS, volume limit reached"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(12), "Close Initiated by PS or CMTS, time limit reached"));
        TP_ASSERT(MATCHES(pcmm_gatestate_rpt_reason(13), "Close Initiated by CMTS, other"));
        /* clang-format on */
}

void
tp_pcmm_common_transaction_id(void) {
        info("TEST: %s", __func__);

        u8 transaction[8];
        memset(transaction, 0, sizeof(transaction));

        int ops[3] = {GATE_SET, GATE_INFO, GATE_DEL};

        for (int i = 0; i < 3; i++) {
                info("TEST: %s:%i", __func__, ops[i]);

                /* Pack transaction ID. */
                u16 id = rand();

                pcmm_transaction_identifier(transaction, id, ops[i]);

                u16 len = unpack_u16((char*)transaction);     /* Pos. 0-3. */
                u16 tid = unpack_u16((char*)transaction + 4); /* Pos. 4-5. */
                u16 gct = unpack_u16((char*)transaction + 6); /* Pos. 6-7. */

                TP_ASSERT(len == 8);            /* Object length of 8. */
                TP_ASSERT(transaction[2] == 1); /* Txn object S-Num = 1. */
                TP_ASSERT(transaction[3] == 1); /* Txn object S-Type = 1. */
                TP_ASSERT(id == tid);           /* Given Transaction ID. */
                TP_ASSERT(gct == ops[i]);       /* Command OP. (4,7,10). */
        }
}

void
tp_pcmm_common_application_id(void) {
        info("TEST: %s", __func__);

        u8 application[8];
        memset(application, 0, sizeof(application));
        pcmm_application_identifier(application, 32778, 1);

        /* Unpack object. */
        u16 len = unpack_u16((char*)application);
        u16 app_tag = unpack_u16((char*)application + 4);
        u16 app_type = unpack_u16((char*)application + 6);

        /* Assert. */
        TP_ASSERT(len == 8);
        TP_ASSERT(application[2] == 2);
        TP_ASSERT(application[3] == 1);
        TP_ASSERT(app_tag == 32778);
        TP_ASSERT(app_type == 1);
}

void
tp_pcmm_common_subscriber_v4(void) {
        info("TEST: %s", __func__);

        u16 ip_length = 8;
        u8 subscriber[ip_length];
        memset(subscriber, 0, sizeof(subscriber));

        /* Pack object. */
        char ipv4_sid[13] = "10.0.129.144\0";
        pcmm_subscriber4_identifier(subscriber, ip4_toi(ipv4_sid));

        /* Unpack object. */
        u16 len = unpack_u16((char*)subscriber);

        /* Assert. */
        TP_ASSERT(len == ip_length);
        TP_ASSERT(subscriber[2] == 3);
        TP_ASSERT(subscriber[3] == 1);
}

void
tp_pcmm_common_subscriber_v6(void) {
        info("TEST: %s", __func__);

        /* Prepare input params. */
        u16 ip_length = 20;
        u8 subscriber[ip_length];
        memset(subscriber, 0, sizeof(subscriber));

        /* Pack object. */
        char ipv6_sid[35] = "2600:6ce1:0:51:7e8f:deff:fefb:3224";
        pcmm_subscriber6_identifier(subscriber, ipv6_sid, ip_length);

        /* Unpack object. */
        u16 len = unpack_u16((char*)subscriber);

        /* Assert. */
        TP_ASSERT(len == ip_length);
        TP_ASSERT(subscriber[2] == 3);
        TP_ASSERT(subscriber[3] == 2);
}

void
tp_pcmm_common_gate_id(void) {
        info("TEST: %s", __func__);
        /* Prepare input params. */
        u8 gate[8];
        u32 gid = 1234567;

        /* Pack object. */
        pcmm_gate_identifier(gate, gid);

        /* Unpack object. */
        u16 len = unpack_u16((char*)gate);
        u32 _gid = unpack_u32(gate + 4);

        /* Assert. */
        TP_ASSERT(len == 8);
        TP_ASSERT(gate[2] == 4);
        TP_ASSERT(gate[3] == 1);
        TP_ASSERT(_gid == gid);
}

void
tp_pcmm_gate_spec_flags_ds_dscp_disabled(void) {
        info("TEST: %s", __func__);
        u8 flags = vtof("downstream", 0, 0);
        TP_ASSERT(((flags & (1 << 0)) >> 0) == 0);
        TP_ASSERT(((flags & (1 << 1)) >> 1) == 0);
}

void
tp_pcmm_gate_spec_flags_us_dscp_disabled(void) {
        info("TEST: %s", __func__);
        u8 flags = vtof("upstream", 0, 0);
        TP_ASSERT(((flags & (1 << 0)) >> 0) == 1);
        TP_ASSERT(((flags & (1 << 1)) >> 1) == 0);
}

void
tp_pcmm_gate_spec_flags_ds_dscp_enabled(void) {
        info("TEST: %s", __func__);
        u8 flags = vtof("downstream", 1, 0);
        TP_ASSERT(((flags & (1 << 0)) >> 0) == 0);
        TP_ASSERT(((flags & (1 << 1)) >> 1) == 1);
}

void
tp_pcmm_gate_spec_flags_us_dscp_enabled(void) {
        info("TEST: %s", __func__);
        u8 flags = vtof("upstream", 1, 0);
        TP_ASSERT(((flags & (1 << 0)) >> 0) == 1);
        TP_ASSERT(((flags & (1 << 1)) >> 1) == 1);
}

void
tp_pcmm_gate_spec_flags(void) {
        info("TEST: %s", __func__);

        /* Downstream, DSCP disabled, Persistence disabled. */
        u8 flags = vtof("downstream", 0, 0);
        u8 dir_bit = (flags & (1 << 0)) >> 0;
        u8 tos_bit = (flags & (1 << 1)) >> 1;
        TP_ASSERT(dir_bit == 0);
        TP_ASSERT(tos_bit == 0);

        /* Upstream, DSCP disabled, Persistence disabled. */
        flags = vtof("upstream", 0, 0);
        dir_bit = (flags & (1 << 0)) >> 0;
        tos_bit = (flags & (1 << 1)) >> 1;
        TP_ASSERT(dir_bit == 1);
        TP_ASSERT(tos_bit == 0);

        /* Downstream, DSCP enabled, Persistence disabled. */
        flags = vtof("downstream", 1, 0);
        dir_bit = (flags & (1 << 0)) >> 0;
        tos_bit = (flags & (1 << 1)) >> 1;
        TP_ASSERT(dir_bit == 0);
        TP_ASSERT(tos_bit == 1);

        /* Upstream, DSCP enabled, Persistence disabled. */
        flags = vtof("upstream", 1, 0);
        dir_bit = (flags & (1 << 0)) >> 0;
        tos_bit = (flags & (1 << 1)) >> 1;
        TP_ASSERT(dir_bit == 1);
        TP_ASSERT(tos_bit == 1);
}

void
tp_pcmm_gate_spec_session(void) {
        info("TEST: %s", __func__);

        u8 session = vtoc(0, 0, 0);
        u8 priority_bit = (session & (1 << 0)) >> 0;
        u8 preemption_bit = (session & (1 << 3)) >> 3;

        TP_ASSERT(priority_bit == 0);
        TP_ASSERT(preemption_bit == 0);

        session = vtoc(1, 0, 0);
        priority_bit = (session & (1 << 0)) >> 0;
        preemption_bit = (session & (1 << 3)) >> 3;

        TP_ASSERT(priority_bit == 1);
        TP_ASSERT(preemption_bit == 0);

        session = vtoc(0, 1, 0);
        priority_bit = (session & (1 << 0)) >> 0;
        preemption_bit = (session & (1 << 3)) >> 3;

        TP_ASSERT(priority_bit == 0);
        TP_ASSERT(preemption_bit == 1);

        session = vtoc(1, 1, 0);
        priority_bit = (session & (1 << 0)) >> 0;
        preemption_bit = (session & (1 << 3)) >> 3;

        TP_ASSERT(priority_bit == 1);
        TP_ASSERT(preemption_bit == 1);
}

void
tp_pcmm_envelope_all_scn_types(void) {
        info("TEST: %s", __func__);
        int sz = 20;

        /* Define SCN value. */
        const uch* scns[] = {(const uch*)"usSMI001", (const uch*)"usSMI002", (const uch*)"dsSMI001",
                             (const uch*)"dsSMI002"};

        for (int i = 0; i < 4; i++) {
                const uch* scn = scns[i];

                uch envelope[sz];
                memset(envelope, 0, sz);
                pcmm_scn_envelope(envelope, scn);

                for (int k = 0; k < 8; k++) {
                        TP_ASSERT(*(envelope + 8 + k) == scn[k]);
                }
        }
}

void
tp_pcmm_scn_gate_envelope_ds(void) {
        info("TEST: %s", __func__);
        int sz = 20;

        /* Create buffer. */
        uch envelope[sz];
        memset(envelope, 0, sz);

        /* Define SCN value. */
        const uch scn[9] = "dsSMI001\0";
        pcmm_scn_envelope(envelope, scn);

        /* SCN Envelope length. */
        u16 len = unpack_u16((char*)envelope);
        TP_ASSERT(len == sz);

        /* SCN Envelope assertions. */
        TP_ASSERT(envelope[2] == 7); /* SCN Envelope S-Num. */
        TP_ASSERT(envelope[3] == 2); /* SCN Envelope S-Type. */
        TP_ASSERT(envelope[4] == 7); /* ? */
        TP_ASSERT(envelope[5] == 0); /* Reserved. */
        TP_ASSERT(envelope[6] == 0); /* Reserved.*/

        /* SCN downstream value. */
        int alignment = (strlen((const char*)scn) + 1) % 4;
        int start = 7 + alignment;
        int end = start + 8;
        int j = 0;
        for (int i = start; i < end; i++) {
                TP_ASSERT(envelope[i] == scn[j++]);
        }
}

void
tp_pcmm_scn_gate_envelope_us(void) {
        info("TEST: %s", __func__);
        int sz = 20;

        /* Create buffer. */
        uch envelope[sz];
        memset(envelope, 0, sz);

        /* Define SCN value. */
        const uch scn[9] = "usSMI001\0";
        pcmm_scn_envelope(envelope, scn);

        /* SCN Envelope length. */
        u16 len = unpack_u16((char*)envelope);
        TP_ASSERT(len == sz);

        /* SCN Envelope assertions. */
        TP_ASSERT(envelope[2] == 7); /* SCN Envelope S-Num. */
        TP_ASSERT(envelope[3] == 2); /* SCN Envelope S-Type. */
        TP_ASSERT(envelope[4] == 7); /* Envelope. */
        TP_ASSERT(envelope[5] == 0); /* Reserved. */
        TP_ASSERT(envelope[6] == 0); /* Reserved. */

        /* SCN upstream value. */
        int alignment = (strlen((const char*)scn) + 1) % 4;
        int start = 7 + alignment;
        int end = start + 8;
        int j = 0;
        for (int i = start; i < end; i++) {
                TP_ASSERT(envelope[i] == scn[j++]);
        }
}

void
tp_pcmm_flow_spec_envelope_basic(void) {
        info("TEST: %s", __func__);

        /* Define size and service number. */
        int sz = 92;
        int svc = 2;

        /* Create buffer. */
        uch fls[sz];
        memset(fls, 0, sz);

        /* Pack envelope. */
        pcmm_flowspec_envelope(fls, svc);

        /* Flow Spec length. */
        u16 len = unpack_u16((char*)fls);
        TP_ASSERT(len == sz);

        /* Flow Spec assertions. */
        TP_ASSERT(fls[2] == 7);   /* Flow Spec S-Num. */
        TP_ASSERT(fls[3] == 1);   /* Flow Spec S-Type. */
        TP_ASSERT(fls[4] == 7);   /* Envelope. */
        TP_ASSERT(fls[5] == svc); /* Flow Spec service number. */
        TP_ASSERT(fls[6] == 0);   /* Reserved. */
        TP_ASSERT(fls[7] == 0);   /* Reserved. */
                                  /* Ignoring bitrates for now. */
}

void
tp_pcmm_legacy_classifier_basic(void) {
        info("TEST: %s", __func__);

        /* Classifier params. */
        int dscp_tos_field = 0;
        int dscp_tos_mask = 0;
        int src_port = 2000;
        int dst_port = 4000;
        int priority = 64;
        int reserved = 0;
        int protocol = 0;
        char src_ip[11] = "172.20.1.1\0";

        /* Create buffer. */
        int sz = 24;
        uch class[sz];
        memset(class, 0, sz);

        /* Pack legacy classifier. */
        pcmm_legacy_classifier(class, protocol, dscp_tos_field, dscp_tos_mask, src_ip, NULL, src_port, dst_port,
                               priority, reserved);

        /* Legacy classifier length. */
        u16 len = unpack_u16((char*)class);
        TP_ASSERT(len == sz);

        /* Legacy classifier assertions. */
        TP_ASSERT(class[2] == 6);
        TP_ASSERT(class[3] == 1);

        u16 _protocol = unpack_u16((char*)class + 4);
        TP_ASSERT(_protocol == protocol);

        /* Legacy classifier DSCP/TOS fields. */
        TP_ASSERT(class[6] == dscp_tos_field);
        TP_ASSERT(class[7] == dscp_tos_mask);

        /* Legacy classifier IPs. */
        u32 src_ip_int = unpack_u32((char*)class + 8);
        u32 dst_ip_int = unpack_u32((char*)class + 12);
        TP_ASSERT(src_ip_int == (u32)ip4_toi(src_ip));
        TP_ASSERT(dst_ip_int == 0);

        /* Legacy classifier ports. */
        u16 _src_port = unpack_u16((char*)class + 16);
        u16 _dst_port = unpack_u16((char*)class + 18);
        TP_ASSERT(_src_port == src_port);
        TP_ASSERT(_dst_port == dst_port);

        TP_ASSERT(class[20] == priority);
        TP_ASSERT(class[21] == reserved);
        TP_ASSERT(class[22] == reserved);
        TP_ASSERT(class[23] == reserved);
}

void
tp_pcmm_extended_classifier_basic(void) {
        info("TEST: %s", __func__);

        int sz = 40;
        uch ext[sz];
        memset(ext, 0, sz);

        /* Extended classifier params. */
        char src_ip[11] = "172.20.1.1\0";
        char dst_ip[11] = "17.20.1.11\0";
        char mask[16] = "255.255.255.255\0";
        int activation_state = 0;
        int src_port_start = 100;
        int dst_port_start = 300;
        int src_port_end = 200;
        int dst_port_end = 400;
        int dscp_tos_field = 0;
        int dscp_tos_mask = 0;
        int classifier_id = 0;
        int priority = 64;
        int protocol = 0;
        int action = 0;

        pcmm_extended_classifier(ext, protocol, src_ip, mask, src_port_start, src_port_end, dst_ip, mask,
                                 dst_port_start, dst_port_end, priority, dscp_tos_field, dscp_tos_mask, classifier_id,
                                 activation_state, action);

        /* Extended classifier length. */
        u16 len = unpack_u16((char*)ext);
        TP_ASSERT(len == sz);

        /* Extended classifier assertions. */
        TP_ASSERT(ext[2] == 6);
        TP_ASSERT(ext[3] == 2);

        u16 _protocol = unpack_u16((char*)ext + 4);
        TP_ASSERT(_protocol == protocol);

        /* Extended classifier DSCP/TOS fields. */
        TP_ASSERT(ext[6] == dscp_tos_field);
        TP_ASSERT(ext[7] == dscp_tos_mask);

        /* Extended classifier IPs. */
        u32 src_ip_int = unpack_u32((char*)ext + 8);
        u32 dst_ip_int = unpack_u32((char*)ext + 16);

        TP_ASSERT(src_ip_int == (u32)ip4_toi(src_ip));
        TP_ASSERT(dst_ip_int == (u32)ip4_toi(dst_ip));

        /* Extended classifier IP masks. */
        u32 src_ip_mask = unpack_u32((char*)ext + 12);
        u32 dst_ip_mask = unpack_u32((char*)ext + 20);
        u32 mask_int = ip4_toi(mask);

        TP_ASSERT(src_ip_mask == mask_int);
        TP_ASSERT(dst_ip_mask == mask_int);

        /* Extended classifier ports. */
        u16 _src_port_start = unpack_u16((char*)ext + 24);
        u16 _src_port_end = unpack_u16((char*)ext + 26);
        u16 _dst_port_start = unpack_u16((char*)ext + 28);
        u16 _dst_port_end = unpack_u16((char*)ext + 30);

        TP_ASSERT(_src_port_start == src_port_start);
        TP_ASSERT(_dst_port_start == dst_port_start);
        TP_ASSERT(_src_port_end == src_port_end);
        TP_ASSERT(_dst_port_end == dst_port_end);

        u16 _classifier_id = unpack_u16((char*)ext + 32);

        TP_ASSERT(_classifier_id == classifier_id);
        TP_ASSERT(ext[34] == priority);
        TP_ASSERT(ext[36] == 0);
        TP_ASSERT(ext[38] == 0);
}

void
tp_pcmm_ipv6_classifier_basic(void) {
        info("TEST: %s", __func__);

        char src_ip[35] = "2600:6ce1:0:51:7e8f:deff:fefb:3224";
        char dst_ip[35] = "2600:6ce1:0:51:7e8f:deff:fefb:3224";

        int sz = 64;
        uch v6[sz];
        memset(v6, 0, sz);

        int tc_low = 0;
        int tc_high = 0;
        int tc_mask = 0;
        u32 flow_label = 0;
        u32 nh_type = 256;
        int src_prefix_len = 0;
        int dst_prefix_len = 0;
        int src_port_start = 100;
        int dst_port_start = 300;
        int src_port_end = 200;
        int dst_port_end = 400;
        int classifier_id = 0;
        int priority = 0;
        int activation_state = 0;
        int action = 1;

        pcmm_ipv6_classifier(v6, tc_low, tc_high, tc_mask, flow_label, nh_type, src_ip, dst_ip, src_port_start,
                             src_port_end, dst_port_start, dst_port_end, classifier_id, priority, activation_state,
                             action);

        /* IPv6 classifier length. */
        u16 len = unpack_u16((char*)v6);
        TP_ASSERT(len == sz);

        /* IPv6 classifier S-Num/S-Type */
        TP_ASSERT(v6[2] == 6);
        TP_ASSERT(v6[3] == 3);

        TP_ASSERT(v6[4] == 0);

        /* IPv6 classifier traffic-class. */
        TP_ASSERT(v6[5] == tc_low);
        TP_ASSERT(v6[6] == tc_high);
        TP_ASSERT(v6[7] == tc_mask);

        /* IPv6 classifier flow label and next-header. */
        u32 _flow_label = unpack_u32((char*)v6 + 8);
        u16 _nh_type = unpack_u16((char*)v6 + 12);

        TP_ASSERT(_flow_label == flow_label);
        TP_ASSERT(_nh_type == nh_type);

        /* IPv6 clssifier prefix lengths. */
        TP_ASSERT(v6[14] == src_prefix_len);
        TP_ASSERT(v6[15] == dst_prefix_len);

        /* IPv6 classifier ports. */
        u16 _src_port_start = unpack_u16((char*)v6 + 48);
        u16 _src_port_end = unpack_u16((char*)v6 + 50);
        u16 _dst_port_start = unpack_u16((char*)v6 + 52);
        u16 _dst_port_end = unpack_u16((char*)v6 + 54);

        TP_ASSERT(_src_port_start == src_port_start);
        TP_ASSERT(_dst_port_start == dst_port_start);
        TP_ASSERT(_src_port_end == src_port_end);
        TP_ASSERT(_dst_port_end == dst_port_end);

        u16 _classifier_id = unpack_u16((char*)v6 + 56);

        TP_ASSERT(_classifier_id == classifier_id);
        TP_ASSERT(v6[58] == priority);
        TP_ASSERT(v6[59] == activation_state);
        TP_ASSERT(v6[60] == action);
        TP_ASSERT(v6[62] == 0);
}

void
tp_pcmm_scn_gate_legacy_classifier(void) {
        info("TEST: %s", __func__);
        char clf_src_ip[11] = "172.20.1.1\0";
        char downstream[10] = "downstream";

        uch scn_gate[16];
        uch scn_clsf[24];
        uch scn_envl[20];

        memset(scn_gate, 0, 16);
        memset(scn_clsf, 0, 24);
        memset(scn_envl, 0, 20);

        pcmm_gate(scn_gate, downstream, 0, 0, 0, 0, 20, 20, 20, 20);
        pcmm_legacy_classifier(scn_clsf, 0, 0, 0, clf_src_ip, NULL, 0, 0, 64, 0);
        pcmm_scn_envelope(scn_envl, (const unsigned char*)"dsSMI001");
}
