#include "include/helpers.h"
#include <stdint.h>
#include "yyjson.h"

size_t
util_read_result(uint8_t* dst, const char* filepath) {
        int fd;
        fd = open(filepath, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR);
        if (fd < 0) {
                error("failed to open file: %s", strerror(errno));

                return 0;
        }
        remove(filepath);
        return read(fd, dst, 2000);
}

size_t
util_read_body(const char* file_path, char* dst) {
        FILE* fp;
        fp = fopen(file_path, "r");

        if (fp == NULL) {
                error("failed to open file '%s'", file_path);
        }
        int x = fread(dst, sizeof(unsigned char), 4000, fp);
        fclose(fp);

        return x;
}

EXP*
util_build_expected(yy_val* root) {
        EXP* self = ALLOC_T(EXP);

        yy_val* gate = yy_obj(root, "gate");
        yy_val* spec = yy_obj(gate, "gate-spec");
        yy_val* tftp = yy_obj(gate, "traffic-profile");
        const char* scn = gctl_otos(tftp, "service-class-name");

        self->envelope_svcn = 0;
        if (!scn || scn == NULL) {
                /* Flow Spec profile. */
                yy_val* flow_spec = yy_obj(tftp, FLOW_SPEC_PROFILE);
                self->envelope_svcn = gctl_otoi(flow_spec, SERVICE_NUMBER);
                self->envelope_size = 92;
                self->envelope_stype = 1;
                self->gate_spec_dtos_ow = 0;
        } else {
                /* Service-class-name envelope. */
                self->envelope_size = 20;
                self->envelope_stype = 2;
        }

        const char* dir = gctl_otos(spec, "direction");
        int dtos_ow = gctl_otoi(spec, "dscp-tos-overwrite");
        int dtos_mk = gctl_otoi(spec, "dscp-tos-mask");

        self->gate_spec_dtos_ow = dtos_ow;
        self->gate_spec_dtos_mk = dtos_mk;
        self->gate_spec_direction = dir;
        self->traffic_profile_name = scn;

        /* T1 indicates that the CMTS provisioned value for the timer MUST be used */
        self->gate_spec_timer1 = gctl_otoi(spec, T1);
        if (!self->gate_spec_timer1)
                self->gate_spec_timer1 = 0;

        /* T2 corresponds to the DOCSIS Admitted timer */
        self->gate_spec_timer2 = gctl_otoi(spec, T2);
        if (!self->gate_spec_timer2)
                self->gate_spec_timer2 = 0;

        /* T3 corresponds to the DOCSIS Active timer */
        self->gate_spec_timer3 = gctl_otoi(spec, T3);
        if (!self->gate_spec_timer3)
                self->gate_spec_timer3 = 0;

        self->gate_spec_timer4 = 0;

        yy_val* classifiers = yy_obj(gate, CLASSIFIERS);

        self->class_len = 0;
        for (size_t i = 0; i < yyjson_get_len(classifiers); i++) {
                yy_val* element = yyjson_arr_get(classifiers, i);
                yy_val* obj = yy_obj(element, EXT_CLASS);
                /* Find classifier type. */
                int classifier_type = EXTENDED_CLASSIFIER;
                self->class_len += 1;

                if (!obj || obj == NULL) {
                        obj = yy_obj(element, LEG_CLASS);
                        classifier_type = DEFAULT_CLASSIFIER;
                }

                if (!obj || obj == NULL) {
                        obj = yy_obj(element, IP6_CLASS);
                        classifier_type = IPV6_CLASSIFIER;
                }
                self->class_id = gctl_otoi(element, CLASS_ID);

                /* All classifiers use these fields. */
                char* src_ip = (char*)gctl_otos(obj, SRC_IP4);
                char* dst_ip = (char*)gctl_otos(obj, DST_IP4);

                if (src_ip && dst_ip) {
                        self->class_src_int = (u32)ip4_toi(src_ip);
                        self->class_dst_int = (u32)ip4_toi(dst_ip);
                } else {
                        self->src_ip6 = (char*)gctl_otos(obj, SRC_IP6);
                        self->dst_ip6 = (char*)gctl_otos(obj, DST_IP6);
                        self->src_prefix_len = prefixlen(self->src_ip6);
                        self->dst_prefix_len = prefixlen(self->dst_ip6);
                }
                self->class_src_port_start = gctl_otoi(obj, SRC_PORT_START);
                self->class_dst_port_start = gctl_otoi(obj, DST_PORT_START);
                self->class_src_port_end = gctl_otoi(obj, SRC_PORT_END);
                self->class_dst_port_end = gctl_otoi(obj, DST_PORT_END);
                self->class_dtos_ow = gctl_otoi(obj, TOS_BYTE);
                self->class_dtos_mk = gctl_otoi(obj, TOS_MASK);
                self->class_protocol = gctl_otoi(obj, PROTOCOL);
                self->class_priority = gctl_otoi(obj, PRIORITY);
                char* src_ip_mask = (char*)gctl_otos(obj, SRC_MASK);
                char* dst_ip_mask = (char*)gctl_otos(obj, DST_MASK);
                if (src_ip_mask != NULL) {
                        self->class_src_mask_int = (u32)ip4_toi(src_ip_mask);
                }
                if (dst_ip_mask != NULL) {
                        self->class_dst_mask_int = (u32)ip4_toi(dst_ip_mask);
                }
                if (!self->class_priority) {
                        self->class_priority = 64;
                }
                self->class_action = gctl_otoi(obj, ACTION);
                self->class_activation_state = gctl_otoi(obj, ASTATE);
                self->tc_low = gctl_otoi(obj, TC_LOW);
                self->tc_high = gctl_otoi(obj, TC_HIGH);
                self->tc_mask = gctl_otoi(obj, TC_MASK);
                self->flow_label = gctl_otoi(obj, FLOW_LABEL);
                self->nh_type = gctl_otoi(obj, NEXT_HDR);
                (void)classifier_type;
        }
        return self;
}

EXP*
util_get_expected(yyjson_doc* doc) {
        yy_val* root = gctl_ytoi(doc);
        EXP* exp = util_build_expected(root);
        return exp;
}
