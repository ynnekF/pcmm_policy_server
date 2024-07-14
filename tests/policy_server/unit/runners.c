#include "runners.h"

int
unittest_executor(void) {
        /*
         * COPS API tests
         */
        tp_cops_common_handle_object();
        tp_cops_common_context_object();
        tp_cops_common_decision_object();
        tp_cops_client_accept_message();
        tp_cops_keepalive_message();
        tp_cops_report_state_opcode_ok();
        tp_cops_report_state_opcode_to_acronym();
        tp_cops_report_state_opcode_to_string();

        /*
         * PCMM API tests
         */
        tp_pcmm_report_state_gate_state_lookup();
        tp_pcmm_report_state_gate_state_reason();
        tp_pcmm_common_transaction_id();
        tp_pcmm_common_application_id();
        tp_pcmm_common_subscriber_v4();
        tp_pcmm_common_subscriber_v6();
        tp_pcmm_common_gate_id();
        tp_pcmm_report_state_opcode_to_action();
        tp_pcmm_report_state_opcode_to_error();
        tp_pcmm_report_state_major_minor();
        tp_pcmm_gate_spec_flags_ds_dscp_disabled();
        tp_pcmm_gate_spec_flags_us_dscp_disabled();
        tp_pcmm_gate_spec_flags_ds_dscp_enabled();
        tp_pcmm_gate_spec_flags_us_dscp_enabled();
        tp_pcmm_gate_spec_flags();
        tp_pcmm_gate_spec_session();
        tp_pcmm_envelope_all_scn_types();
        tp_pcmm_scn_gate_envelope_ds();
        tp_pcmm_scn_gate_envelope_us();
        tp_pcmm_flow_spec_envelope_basic();
        tp_pcmm_legacy_classifier_basic();
        tp_pcmm_extended_classifier_basic();
        tp_pcmm_ipv6_classifier_basic();
        tp_pcmm_scn_gate_legacy_classifier();

        /*
         * IP util. lib tests
         */
        tp_iputil_ip6_check();
        tp_iputil_prefixlen();
        tp_iputil_ito_ip4();

        /* Ulfius API tests */
        return api_unittest_executor();
}
