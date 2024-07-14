#include "tp_api.h"
#include "cops.h"

/* Max. JSON payload file size. */
const int MAX_SIZE = 2000;

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
clear(void) {
        const char* resp_path = "data/IGNORE_tp_resp.txt";
        const char* flow_path = "data/IGNORE_tp_flow.txt";
        remove(resp_path);
        remove(flow_path);
}

void
cert_gatespec(u8* data, size_t* i, EXP* exp) {
        u16 len = unpack_u16_it(data, i);

        /* Gate Spec Length = 16, S-Num = 5, S-Type = 1. */
        TP_ASSERT(len == 16);
        TP_ASSERT_EQ_ITER(data, i, 5);
        TP_ASSERT_EQ_ITER(data, i, 1);

        /*
     * Flags is a 1-byte bit-field value defined as follows:
     * Bit 0:  MUST be zero for a downstream, or one for an upstream.
     * Bit 1:  MUST be either zero to disable DSCP overwrite, or one to enable.
     * Persistence enable bit, MUST be either zero (default) to disable
     * Gate persistence, or one to enable persistence.
     * Bits 3-7: reserved, MUST be zero.
     */
        u8 flags = data[*i];

        u8 _dir_bit = (flags & (1 << 0)) >> 0;
        u8 _tos_enb = (flags & (1 << 1)) >> 1;

        if (MATCHES(exp->gate_spec_direction, "upstream")) {
                TP_ASSERT(_dir_bit == 1);
        } else {
                TP_ASSERT(_dir_bit == 0);
        }

        TP_ASSERT(_tos_enb == exp->gate_spec_dtos_ow);

        for (int j = 3; j < 8; j++) {
                /* By right-shifting the desired bit into the least significant
         * bit position, masking can be done with 1. */
                TP_ASSERT(((flags >> j) & 1) == 0);
        }
        *i += 1;

        /*
     * Session class ID is a 1-byte bit-field
     * Bit 0-2: Priority, a number 0 to 7
     * Bit 3:   Preemption
     * Bit 4-7: Configurable, default to 0
     */
        u8 session = data[*i];
        u8 _priority = (session & 0x07) >> 0;
        u8 _preempts = (session & (1 << 3)) >> 3;

        TP_ASSERT(_priority == 0);
        TP_ASSERT(_preempts == 0);

        for (int j = 4; j < 8; j++) {
                /* By right-shifting the desired bit into the least significant
         * bit position, masking can be done with 1. */
                TP_ASSERT(((session >> j) & 1) == 0);
        }
        TP_ASSERT_EQ_ITER(data, i, exp->gate_spec_dtos_ow);
        TP_ASSERT_EQ_ITER(data, i, exp->gate_spec_dtos_mk);
        *i += 1;
        TP_ASSERT(unpack_u16_it(data, i) == exp->gate_spec_timer1);
        TP_ASSERT(unpack_u16_it(data, i) == exp->gate_spec_timer2);
        TP_ASSERT(unpack_u16_it(data, i) == exp->gate_spec_timer3);
        TP_ASSERT(unpack_u16_it(data, i) == exp->gate_spec_timer4);
}

void
cert_lclass(u8* data, size_t* i, EXP* exp) {
        /* Legacy classifier. */
        u16 len = unpack_u16_it(data, i);
        TP_ASSERT(len == 24);
        TP_ASSERT_EQ_ITER(data, i, 6);
        TP_ASSERT_EQ_ITER(data, i, 1);
        u16 proto = unpack_u16_it(data, i);
        TP_ASSERT(proto == exp->class_protocol);
        TP_ASSERT_EQ_ITER(data, i, exp->class_dtos_ow);
        TP_ASSERT_EQ_ITER(data, i, exp->class_dtos_mk);
        TP_ASSERT(unpack_u32_it(data, i) == exp->class_src_int);
        TP_ASSERT(unpack_u32_it(data, i) == exp->class_dst_int);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_src_port_start);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_dst_port_start);
        TP_ASSERT_EQ_ITER(data, i, exp->class_priority);
        TP_ASSERT_EQ_ITER(data, i, 0);
        TP_ASSERT_EQ_ITER(data, i, 0);
        TP_ASSERT_EQ_ITER(data, i, 0);
}

void
cert_eclass(u8* data, size_t* i, EXP* exp) {
        u16 len = unpack_u16_it(data, i);
        TP_ASSERT(len == 40);
        TP_ASSERT_EQ_ITER(data, i, 6);
        TP_ASSERT_EQ_ITER(data, i, 2);
        u16 proto = unpack_u16_it(data, i);
        TP_ASSERT(proto == exp->class_protocol);
        TP_ASSERT_EQ_ITER(data, i, exp->class_dtos_ow);
        TP_ASSERT_EQ_ITER(data, i, exp->class_dtos_mk);
        TP_ASSERT(unpack_u32_it(data, i) == exp->class_src_int);
        TP_ASSERT(unpack_u32_it(data, i) == exp->class_src_mask_int);
        TP_ASSERT(unpack_u32_it(data, i) == exp->class_dst_int);
        TP_ASSERT(unpack_u32_it(data, i) == exp->class_dst_mask_int);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_src_port_start);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_src_port_end);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_dst_port_start);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_dst_port_end);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_id);
        TP_ASSERT_EQ_ITER(data, i, exp->class_priority);
        TP_ASSERT_EQ_ITER(data, i, exp->class_activation_state);
        TP_ASSERT_EQ_ITER(data, i, exp->class_action);
        TP_ASSERT_EQ_ITER(data, i, 0);
        TP_ASSERT_EQ_ITER(data, i, 0);
        TP_ASSERT_EQ_ITER(data, i, 0);
}

void
cert_6class(u8* data, size_t* i, EXP* exp) {
        u16 len = unpack_u16_it(data, i);
        TP_ASSERT(len == 64);
        TP_ASSERT_EQ_ITER(data, i, 6);
        TP_ASSERT_EQ_ITER(data, i, 3);
        TP_ASSERT_EQ_ITER(data, i, 0); /* Reserved. */
        TP_ASSERT_EQ_ITER(data, i, exp->tc_low);
        TP_ASSERT_EQ_ITER(data, i, exp->tc_high);
        TP_ASSERT_EQ_ITER(data, i, exp->tc_mask);

        u32 flow_label = unpack_u32_it(data, i);
        TP_ASSERT(flow_label == exp->flow_label);

        u16 nh_type = unpack_u16_it(data, i);
        TP_ASSERT(nh_type == exp->nh_type);
        TP_ASSERT_EQ_ITER(data, i, exp->src_prefix_len);
        TP_ASSERT_EQ_ITER(data, i, exp->dst_prefix_len);
        u8 stop = (*i) + 16;

        u8 temp_src_pack[16];
        u8 temp_dst_pack[16];
        memset(temp_src_pack, 0, sizeof(temp_src_pack));
        memset(temp_dst_pack, 0, sizeof(temp_dst_pack));

        pack_ip6(temp_src_pack, exp->src_ip6);
        pack_ip6(temp_dst_pack, exp->dst_ip6);
        int j = 0;
        for (; (*i) < stop; (*i)++) {
                TP_ASSERT(temp_src_pack[j++] == data[*i]);
        }

        stop = (*i) + 16, j = 0;
        for (; (*i) < stop; (*i)++) {
                TP_ASSERT(temp_dst_pack[j++] == data[*i]);
        }

        TP_ASSERT(unpack_u16_it(data, i) == exp->class_src_port_start);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_src_port_end);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_dst_port_start);
        TP_ASSERT(unpack_u16_it(data, i) == exp->class_dst_port_end);

        TP_ASSERT(unpack_u16_it(data, i) == exp->class_id);

        TP_ASSERT_EQ_ITER(data, i, exp->class_priority);
        TP_ASSERT_EQ_ITER(data, i, exp->class_activation_state);
        TP_ASSERT_EQ_ITER(data, i, exp->class_action);
}

void
cert_envelope(u8* data, size_t* i, EXP* exp) {
        u16 envelope_len = unpack_u16_it(data, i);
        TP_ASSERT(envelope_len == exp->envelope_size);
        TP_ASSERT_EQ_ITER(data, i, 7);
        TP_ASSERT_EQ_ITER(data, i, exp->envelope_stype);
        TP_ASSERT_EQ_ITER(data, i, 7);
        if (exp->envelope_svcn) {
                TP_ASSERT_EQ_ITER(data, i, exp->envelope_svcn);
        }
        TP_ASSERT_EQ_ITER(data, i, 0);
        TP_ASSERT_EQ_ITER(data, i, 0);

        if (exp->envelope_stype == 1) {
                for (size_t k = 0; k < 3; k++) {
                        TP_ASSERT(unpack_u32_it(data, i) != 0);
                        TP_ASSERT(unpack_u32_it(data, i) != 0);
                        TP_ASSERT(unpack_u32_it(data, i) != 0);
                        TP_ASSERT(unpack_u32_it(data, i) == 200);
                        TP_ASSERT(unpack_u32_it(data, i) == 200);
                        TP_ASSERT(unpack_u32_it(data, i) != 0)
                        TP_ASSERT(unpack_u32_it(data, i) == 2000);
                }
        } else {
                /* Alignment. */
                TP_ASSERT_EQ_ITER(data, i, 0);

                for (unsigned long j = 0; j < strlen(exp->traffic_profile_name); j++) {
                        TP_ASSERT_EQ_ITER(data, i, exp->traffic_profile_name[j]);
                }
                *i += 4;
        }
}

void
tp_qos_data(int op) {
        info("TEST: %s %i", __func__, op);

        /* pack_ip6 will destroy the real subscriber ID so we'll
     * store a copy to pack to assert/validate later on. */
        char sid_real[35] = "2600:6ce1:0:51:7e8f:deff:fefb:3224";
        char sid_test[35] = "2600:6ce1:0:51:7e8f:deff:fefb:3224";

        u8 temp[16];
        memset(temp, 0, sizeof(temp));
        pack_ip6(temp, sid_test);

        /* Build fields object. */
        gctl_t f = {
        .cmts_ip = "18.3.92.6",
        .subscriber_id = sid_real,
        .application_id = 3747,
        .classifier_size = 0,
        .gate_id = 1234,
        .dry_run = 2,
        .failed = 0,
        };

        /* Sendoff. */
        ps_session_t* client = ps_new(MOCK_CMTS);

        const char handle[8] = "54657374";
        for (int k = 0; k < 8; k++) {
                client->handle[k] = handle[k];
        }
        u16 tid = ps_proxy(client, op, f, NULL, 0);

        /* Read result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));
        size_t fsize = util_read_result(result, "data/IGNORE_tp_flow.txt"), i = 0;

        TP_ASSERT(tid != 0)
        TP_ASSERT(fsize > 0);
        TP_ASSERT_EQ_ITER(result, &i, 16);             /* Version. */
        TP_ASSERT_EQ_ITER(result, &i, 2);              /* Opcode is decision. */
        TP_ASSERT(unpack_u16_it(result, &i) == 32778); /* Client-Type. */
        TP_ASSERT(unpack_u32_it(result, &i) == 80);    /* Message length. */
        TP_ASSERT(unpack_u16_it(result, &i) == 8);     /* Handle length. */
        TP_ASSERT_EQ_ITER(result, &i, 1);              /* Handle C-Num. */
        TP_ASSERT_EQ_ITER(result, &i, 1);              /* Handle C-Type. */
        TP_ASSERT_EQ_ITER(result, &i, handle[0]);      /* Handle. */
        TP_ASSERT_EQ_ITER(result, &i, handle[1]);      /* Handle. */
        TP_ASSERT_EQ_ITER(result, &i, handle[2]);      /* Handle. */
        TP_ASSERT_EQ_ITER(result, &i, handle[3]);      /* Handle */
        TP_ASSERT(unpack_u16_it(result, &i) == 8);     /* Context length. */
        TP_ASSERT_EQ_ITER(result, &i, 2);              /* Context C-Num. */
        TP_ASSERT_EQ_ITER(result, &i, 1);              /* Context C-Type. */
        TP_ASSERT(unpack_u16_it(result, &i) == 8);     /* Context Request Type. */
        TP_ASSERT(unpack_u16_it(result, &i) == 0);     /* Context Message Type. */
        TP_ASSERT(unpack_u16_it(result, &i) == 8);     /* Decision length. */
        TP_ASSERT_EQ_ITER(result, &i, 6);              /* Decision C-Num. */
        TP_ASSERT_EQ_ITER(result, &i, 1);              /* Decision C-Type. */
        TP_ASSERT(unpack_u16_it(result, &i) == 1);     /* Decision val #1. */
        TP_ASSERT(unpack_u16_it(result, &i) == 1);     /* Decision val #2. */
        TP_ASSERT_EQ_ITER(result, &i, 0)               /* Decision headers. */
        TP_ASSERT_EQ_ITER(result, &i, 48)              /* Decision headers. */
        TP_ASSERT_EQ_ITER(result, &i, 6)               /* Decision headers. */
        TP_ASSERT_EQ_ITER(result, &i, 4)               /* Decision headers. */
        TP_ASSERT(unpack_u16_it(result, &i) == 8);     /* Transaction Object. */
        TP_ASSERT_EQ_ITER(result, &i, 1);              /* Transaction S-Num. */
        TP_ASSERT_EQ_ITER(result, &i, 1);              /* Transaction S-Type. */
        TP_ASSERT(unpack_u16_it(result, &i) == tid);   /* Transaction ID. */
        TP_ASSERT(unpack_u16_it(result, &i) == op);    /* Request ID. */
        TP_ASSERT(unpack_u16_it(result, &i) == 8);     /* AppMgr Object. */
        TP_ASSERT_EQ_ITER(result, &i, 2);              /* AppMgr S-Num. */
        TP_ASSERT_EQ_ITER(result, &i, 1);              /* AppMgr S-Type. */
        TP_ASSERT(unpack_u16_it(result, &i) == 0);     /* AppMgr app-tag. */
        TP_ASSERT(unpack_u16_it(result, &i) == 3474);  /* AppMgr app-id. */
        TP_ASSERT(unpack_u16_it(result, &i) == 20);    /* SubscriberID Object. */
        TP_ASSERT_EQ_ITER(result, &i, 3);              /* SubscriberID S-Num. */
        TP_ASSERT_EQ_ITER(result, &i, 2);              /* SubscriberID S-Type. */

        size_t j = (i + 16), k = 0;
        while (i < j) {
                TP_ASSERT(temp[k++] == result[i++]);
        }

        if (op != GATE_SET) {
                TP_ASSERT(unpack_u16_it(result, &i) == 8);    /* GateID Object. */
                TP_ASSERT_EQ_ITER(result, &i, 4);             /* GateID S-Num. */
                TP_ASSERT_EQ_ITER(result, &i, 1);             /* GateID S-Type. */
                TP_ASSERT(unpack_u32_it(result, &i) == 1234); /* GateID^2. */
        }

        ps_free(client);
}

void
tp_api(const char* filepath) {
        info("TEST: %s %s", __func__, filepath);

        yyjson_read_err err;
        yy_doc* doc = yyjson_read_file(filepath, YYJSON_READ_NOFLAG, NULL, &err);

        /* Read input JSON. */
        char* buffer[MAX_SIZE];
        memset(buffer, 0, sizeof(buffer));
        size_t sz = util_read_body(filepath, buffer);

        /* Create expected object. */
        EXP* exp = util_get_expected(doc);

        ps_session_t* client = ps_new(MOCK_CMTS);

        lcm_t* lcm = lcm_init(1);
        lcm_set(lcm, client);

        // /* Create fake Ulfius request. */
        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_SET, U_OPT_HTTP_VERB, POST, U_OPT_BINARY_BODY, buffer,
                                      sz, U_OPT_NONE);

        // /* Execute request. */
        int ok = gctl_04(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        // /* Read request result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        sz = util_read_result(result, "data/IGNORE_tp_api.txt");
        TP_ASSERT(sz > 0);

        size_t i = 0;
        cert_gatespec(&result, &i, exp);
        cert_envelope(&result, &i, exp);

        for (int j = 0; j < exp->class_len; j++) {
                if (strstr(filepath, "legacy")) {
                        cert_lclass(&result, &i, exp);

                } else if (strstr(filepath, "extended")) {
                        cert_eclass(&result, &i, exp);

                } else {
                        cert_6class(&result, &i, exp);
                }
        }

        ulfius_clean_request(&req);
        yyjson_doc_free(doc);
        ps_free(client);
        kfree(lcm);
        kfree(exp);
}

void
tp_api_set_werr(const char* filepath, const char* error_message, const char* error_code) {
        info("TEST: %s %s", __func__, filepath);

        /* Read input JSON. */
        char* buffer[MAX_SIZE];
        memset(buffer, 0, sizeof(buffer));
        size_t sz = util_read_body((const char*)filepath, buffer);

        /* Create LCM object. */
        lcm_t* lcm = lcm_init(1);

        /* Create client object. */
        ps_session_t* client = ps_new(MOCK_CMTS);
        lcm_set(lcm, client);

        /* Create fake Ulfius request. */
        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_SET, U_OPT_HTTP_VERB, POST, U_OPT_BINARY_BODY, buffer,
                                      sz, U_OPT_NONE);

        /* Execute request. */
        int ok = gctl_04(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        /* Read request result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        sz = util_read_result(result, "data/IGNORE_tp_resp.txt");
        info("\tError message received: %s", result);
        TP_ASSERT(sz > 0);
        TP_ASSERT(strstr((char*)result, error_message));
        TP_ASSERT(strstr((char*)result, error_code));

        ulfius_clean_request(&req);
        ps_free(client);
        kfree(lcm);
}

void
tp_qos_ccap_lcm_conflict(void) {
        info("TEST: %s", __func__);

        const char* buffer = "{\"input\": {\"cmts_ip\": \"88.7.88.9\", \"dry_run\": 0}}";
        lcm_t* lcm = lcm_init(1);

        ps_session_t* client = ps_new(MOCK_CMTS);
        lcm_set(lcm, client);

        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_CCAP, U_OPT_HTTP_VERB, POST, U_OPT_BINARY_BODY,
                                      buffer, strlen(buffer), U_OPT_NONE);

        int ok = gctl_connect(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        const char* error_path_resp = "data/IGNORE_tp_resp.txt";
        size_t sz = util_read_result(result, error_path_resp);
        debug("\tError message received: %s", result);
        TP_ASSERT(sz > 0);
        TP_ASSERT(strstr((char*)result, "connection already established on"));
        TP_ASSERT(strstr((char*)result, "100"));
        remove(error_path_resp);

        ulfius_clean_request(&req);
        ps_free(client);
        kfree(lcm);
}

void
tp_qos_ccap_lcm_limit(void) {
        info("TEST: %s", __func__);

        const char* buffer = "{\"input\": {\"cmts_ip\": \"192.57.1.1\", \"dry_run\": 0}}";

        lcm_t* lcm = lcm_init(1);

        /* Create client object. */
        ps_session_t* client = ps_new(MOCK_CMTS);
        lcm_set(lcm, client);

        /* Create fake Ulfius request. */
        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_CCAP, U_OPT_HTTP_VERB, POST, U_OPT_BINARY_BODY,
                                      buffer, strlen(buffer), U_OPT_NONE);

        /* Execute request. */
        int ok = gctl_connect(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        /* Read request result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        const char* error_path_resp = "data/IGNORE_tp_resp.txt";
        size_t sz = util_read_result(result, error_path_resp);
        debug("\tError message received: %s %i", result, sz);
        TP_ASSERT(sz > 0);
        TP_ASSERT(strstr((char*)result, "maximum number of connections has been reached"));
        TP_ASSERT(strstr((char*)result, "103"));
        remove(error_path_resp);

        ulfius_clean_request(&req);
        ps_free(client);
        kfree(lcm);
}

void
tp_qos_gate_info_undefined_connection(void) {
        info("TEST: %s", __func__);

        const char* json_data = "{"
                                "  \"input\": {"
                                "    \"dry_run\": 1,"
                                "    \"cmts_ip\": \"97.35.193.57\","
                                "    \"appId\": 21002,"
                                "    \"subscriberId\": \"2600:6ce1:0:51:7e8f:deff:fefb:3224\","
                                "    \"gateId\": 1234"
                                "  }"
                                "}";

        lcm_t* lcm = lcm_init(1);

        /* Create client object. */
        ps_session_t* client = ps_new(MOCK_CMTS);
        lcm_set(lcm, client);

        /* Create fake Ulfius request. */
        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_GET, U_OPT_HTTP_VERB, GET, U_OPT_BINARY_BODY,
                                      json_data, strlen(json_data), U_OPT_NONE);

        /* Execute request. */
        int ok = gctl_07(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        /* Read request result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        const char* error_resp_path = "data/IGNORE_tp_resp.txt";
        size_t sz = util_read_result(result, error_resp_path);
        debug("\tError message received: %s", result);
        TP_ASSERT(sz > 0);
        TP_ASSERT(strstr((char*)result, "no connection has been found"));
        TP_ASSERT(strstr((char*)result, "104"));
        remove(error_resp_path);
        ulfius_clean_request(&req);
        ps_free(client);
        kfree(lcm);
}

void
tp_qos_gate_info_dryrun(void) {
        info("TEST: %s", __func__);

        const char* json_data = "{"
                                "  \"input\": {"
                                "    \"dry_run\": 1,"
                                "    \"cmts_ip\": \"88.7.88.9\","
                                "    \"appId\": 21002,"
                                "    \"subscriberId\": \"2600:6ce1:0:51:7e8f:deff:fefb:3224\","
                                "    \"gateId\": 1234"
                                "  }"
                                "}";

        lcm_t* lcm = lcm_init(1);
        /* Create client object. */
        ps_session_t* client = ps_new(MOCK_CMTS);
        lcm_set(lcm, client);

        /* Create fake Ulfius request. */
        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_GET, U_OPT_HTTP_VERB, GET, U_OPT_BINARY_BODY,
                                      json_data, strlen(json_data), U_OPT_NONE);

        /* Execute request. */
        int ok = gctl_07(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        /* Read request result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        const char* resp_path = "data/IGNORE_tp_resp.txt";
        size_t sz = util_read_result(result, resp_path);
        debug("\tMessage received: %s", result);

        TP_ASSERT(sz > 0);
        TP_ASSERT(strstr((char*)result, "GATE-DR-ACK"));
        TP_ASSERT(strstr((char*)result, "output"));

        remove(resp_path);
        ulfius_clean_request(&req);
        ps_free(client);
        kfree(lcm);
}

void
tp_qos_gate_delete_undefined_connection(void) {
        info("TEST: %s", __func__);

        const char* json_data = "{"
                                "  \"input\": {"
                                "    \"dry_run\": 1,"
                                "    \"cmts_ip\": \"97.35.193.57\","
                                "    \"appId\": 21002,"
                                "    \"subscriberId\": \"2600:6ce1:0:51:7e8f:deff:fefb:3224\","
                                "    \"gateId\": 1234"
                                "  }"
                                "}";

        lcm_t* lcm = lcm_init(1);
        /* Create client object. */
        ps_session_t* client = ps_new(MOCK_CMTS);
        lcm_set(lcm, client);

        /* Create fake Ulfius request. */
        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_DEL, U_OPT_HTTP_VERB, DEL, U_OPT_BINARY_BODY,
                                      json_data, strlen(json_data), U_OPT_NONE);

        /* Execute request. */
        int ok = gctl_10(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        /* Read request result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        const char* error_resp_path = "data/IGNORE_tp_resp.txt";
        size_t sz = util_read_result(result, error_resp_path);
        debug("\tError message received: %s", result);
        TP_ASSERT(sz > 0);
        TP_ASSERT(strstr((char*)result, "no connection has been found"));
        TP_ASSERT(strstr((char*)result, "104"));
        remove(error_resp_path);
        ulfius_clean_request(&req);
        ps_free(client);
        kfree(lcm);
}

void
tp_qos_gate_delete_dryrun(void) {
        info("TEST: %s", __func__);

        const char* json_data = "{"
                                "  \"input\": {"
                                "    \"dry_run\": 1,"
                                "    \"cmts_ip\": \"88.7.88.9\","
                                "    \"appId\": 21002,"
                                "    \"subscriberId\": \"2600:6ce1:0:51:7e8f:deff:fefb:3224\","
                                "    \"gateId\": 1234"
                                "  }"
                                "}";

        lcm_t* lcm = lcm_init(1);

        /* Create client object. */
        ps_session_t* client = ps_new(MOCK_CMTS);
        lcm_set(lcm, client);

        /* Create fake Ulfius request. */
        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_DEL, U_OPT_HTTP_VERB, DEL, U_OPT_BINARY_BODY,
                                      json_data, strlen(json_data), U_OPT_NONE);

        /* Execute request. */
        int ok = gctl_10(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        /* Read request result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        const char* resp_path = "data/IGNORE_tp_resp.txt";
        size_t sz = util_read_result(result, resp_path);
        debug("\tMessage received: %s", result);

        TP_ASSERT(sz > 0);
        TP_ASSERT(strstr((char*)result, "GATE-DR-ACK"));
        TP_ASSERT(strstr((char*)result, "output"));

        remove(resp_path);
        ulfius_clean_request(&req);
        ps_free(client);
        kfree(lcm);
}

void
tp_qos_gate_set_undefined_connection(void) {
        info("TEST: %s", __func__);

        const char* json_data = "{"
                                "  \"input\": {"
                                "    \"dry_run\": 2,"
                                "    \"cmts_ip\": \"88.7.88.10\","
                                "    \"appId\": 21002,"
                                "    \"subscriberId\": \"2600:6ce1:0:51:7e8f:deff:fefb:3224\","
                                "    \"gate\": {"
                                "      \"traffic-profile\": {"
                                "        \"flow-spec-profile\": {"
                                "          \"service-number\": 2,"
                                "          \"envelope\": {}"
                                "        }"
                                "      },"
                                "      \"gate-spec\": {"
                                "        \"dscp-tos-overwrite\": 0,"
                                "        \"dscp-tos-mask\": 0,"
                                "        \"direction\": \"downstream\""
                                "      },"
                                "      \"num-classifiers\": 1,"
                                "      \"classifiers\": ["
                                "        {"
                                "          \"classifier-id\": 1,"
                                "          \"ipv6-classifier\": {"
                                "            \"flags\": 0,"
                                "            \"srcIp6\": \"2600:6ce1:0:51:7e8f:deff:fefb:3224/16\","
                                "            \"dstIp6\": \"10:0:0:51:f8e7:ffed:bfef:4223\","
                                "            \"flow-label\": 4,"
                                "            \"tc-low\": 1,"
                                "            \"tc-high\": 2,"
                                "            \"tc-mask\": 3,"
                                "            \"protocol\": 17,"
                                "            \"next-hdr\": 256,"
                                "            \"srcPort-start\": 190,"
                                "            \"srcPort-end\": 200,"
                                "            \"dstPort-start\": 210,"
                                "            \"dstPort-end\": 220,"
                                "            \"activation-state\": 1,"
                                "            \"action\": 3,"
                                "            \"priority\": 64"
                                "          }"
                                "        }"
                                "      ]"
                                "    }"
                                "  }"
                                "}";

        lcm_t* lcm = lcm_init(1);
        /* Create client object. */
        ps_session_t* client = ps_new(MOCK_CMTS);
        lcm_set(lcm, client);

        /* Create fake Ulfius request. */
        struct _u_request req;
        ulfius_init_request(&req);
        ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_SET, U_OPT_HTTP_VERB, POST, U_OPT_BINARY_BODY,
                                      json_data, strlen(json_data), U_OPT_NONE);

        /* Execute request. */
        int ok = gctl_04(&req, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);

        /* Read request result. */
        u8 result[MAX_SIZE];
        memset(result, 0, sizeof(result));

        const char* error_resp_path = "data/IGNORE_tp_resp.txt";
        size_t sz = util_read_result(result, error_resp_path);
        debug("\tError message received: %s", result);
        TP_ASSERT(sz > 0);
        TP_ASSERT(strstr((char*)result, "no connection has been found"));
        TP_ASSERT(strstr((char*)result, "104"));
        remove(error_resp_path);
        ulfius_clean_request(&req);
        ps_free(client);
        kfree(lcm);
}

void
tp_lcm_reset(void) {
        lcm_t* lcm = lcm_init(10);

        for (int i = 0; i < 10; i++) {
                uint32_t ul_dst;
                uint32_t random_num = rand();

                ul_dst = (random_num >> 24 & 0xFF) << 24 | (random_num >> 16 & 0xFF) << 16 |
                         (random_num >> 8 & 0xFF) << 8 | (random_num & 0xFF);

                struct sockaddr_in addr;
                addr.sin_addr.s_addr = ul_dst;

                char* ip = inet_ntoa(addr.sin_addr);
                info("IP = %s", ip);

                char* format = "{\"input\": {\"cmts_ip\": \"%s\", \"dry_run\": 1}}";
                char* buffer = (char*)malloc(sizeof(char*) * strlen(format));

                sprintf(buffer, format, ip);
                info("request = %s", buffer);

                /* Create fake Ulfius request. */
                struct _u_request req;
                ulfius_init_request(&req);
                ulfius_set_request_properties(&req, U_OPT_HTTP_URL, LOCAL_CCAP, U_OPT_HTTP_VERB, POST,
                                              U_OPT_BINARY_BODY, buffer, strlen(buffer), U_OPT_NONE);

                /* Execute request. */
                int ok = gctl_connect(&req, NULL, lcm);
                TP_ASSERT(ok == U_CALLBACK_COMPLETE);

                ulfius_clean_request(&req);
        }
        struct _u_request req2;
        ulfius_init_request(&req2);
        ulfius_set_request_properties(&req2, U_OPT_HTTP_URL, "http://localhost:8000/clear", U_OPT_HTTP_VERB, POST,
                                      U_OPT_BINARY_BODY, NULL, 0, U_OPT_NONE);

        /* Execute request. */
        int ok = gctl_lcm_reset(&req2, NULL, lcm);
        TP_ASSERT(ok == U_CALLBACK_COMPLETE);
        ulfius_clean_request(&req2);
        kfree(lcm);
}

void
log_test_func(void) {
        pthread_logspecific(LogLevel_DEBUG, MOCK_CMTS);

        info("%s thread '%i' running", __func__, pthread_self());
        info("Before size limit is exceeded! <space >");

        sleep(2);
        info("After size limit is exceeded!");
        return;
}

void
tp_log(void) {
        global_logconf(LogLevel_DEBUG, 250, true, true);

        pthread_t tid;
        if (pthread_create(&tid, NULL, log_test_func, NULL) != 0) {
                error("pthread_create() failed");

                exit(1);
        }
        sleep(4);
        pthread_cancel(tid);
        pthread_join(tid, NULL);
}

void
file_test_read_file(void) {
        FILE* fp = fopen("data/yrpt_0.txt", "w");
        if (fp == NULL) {
                error("failed to open fp %s", strerror(errno));
        }

        fprintf(fp, "%s", "kenny");
}

void
print_bits2(uint8_t* ptr) {
        int i;
        for (i = 0; i < 8; i++) {
                printf("%d", !!((*ptr << i) & 0x80));
        }
        printf("\n");
}

void
print_nibble2(uint8_t* ptr) {
        int i;
        for (i = 0; i < 4; i++) {
                printf("%d", !!((*ptr << i) & 0x80));
        }
        printf("\n");
}

void
tp_test(void) {
        char buf[BUFFER_SIZE];
        memset(buf, 0, sizeof buf);
        buf[0] = (((1 << 4) & 0xF0) | 0x01);

        uint8_t* ptr = (uint8_t*)buf;
        print_bits2(ptr);

        uint8_t version = (*ptr) >> 4;
        uint8_t flags = (*ptr & 0xF0) >> 4;

        print_bits2(&version);
        print_bits2(&flags);
        printf("\n %i \n", version);
}

int
api_unittest_executor(void) {
        info("Starting test session!");

        clear();

        tp_qos_data(GATE_INFO);
        tp_qos_data(GATE_DEL);
        tp_qos_data(GATE_SET);

#if !defined(EXCLUDE_JSON_TEST)
        tp_api("tests/policy_server/unit/payloads/happy/api_mock_scn_legacy.json");
        tp_api("tests/policy_server/unit/payloads/happy/api_mock_scn_extended.json");
        tp_api("tests/policy_server/unit/payloads/happy/api_mock_scn_v6.json");
        tp_api("tests/policy_server/unit/payloads/happy/api_mock_flow_spec_legacy.json");
        tp_api("tests/policy_server/unit/payloads/happy/api_mock_flow_spec_extended.json");
        tp_api("tests/policy_server/unit/payloads/happy/api_mock_flow_spec_v6.json");
        tp_api("tests/policy_server/unit/payloads/happy/api_mock_max_extended_classifiers.json");
#else
        warning("skipping tp_api_* tests");
#endif

        clear();
        tp_qos_ccap_lcm_conflict();
        tp_qos_ccap_lcm_limit();
        tp_qos_gate_info_undefined_connection();
        tp_qos_gate_info_dryrun();
        tp_qos_gate_delete_undefined_connection();
        tp_qos_gate_delete_dryrun();
        tp_qos_gate_set_undefined_connection();

#if !defined(EXCLUDE_JSON_TEST)
        tp_api_set_werr("tests/policy_server/unit/payloads/sad/api_mock_missing_spec.json", "invalid gate-specification given",
                        "106");
        tp_api_set_werr("tests/policy_server/unit/payloads/sad/api_mock_invalid_prof.json", "invalid traffic-profile given",
                        "107");
        tp_api_set_werr("tests/policy_server/unit/payloads/sad/api_mock_invalid_class.json", "invalid classifier type given",
                        "108");
        tp_api_set_werr("tests/policy_server/unit/payloads/sad/api_mock_classifier_count.json",
                        "invalid number of classifiers, expected >1/<5", "109");
#else
        warning("skipping tp_api_set_werr_* tests");
#endif
        clear();

        /* This should come last because it alters the global logger settings. */
        tp_log();

        return EXIT_SUCCESS;
}
