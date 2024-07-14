#ifndef TP_PCMM_H
#define TP_PCMM_H

#include "helpers.h"

void tp_pcmm_report_state_opcode_to_action(void);
void tp_pcmm_report_state_opcode_to_error(void);
void tp_pcmm_report_state_opcode_to_error(void);
void tp_pcmm_report_state_major_minor(void);

void tp_pcmm_common_transaction_id(void);
void tp_pcmm_common_application_id(void);
void tp_pcmm_common_subscriber_v4(void);
void tp_pcmm_common_subscriber_v6(void);
void tp_pcmm_common_gate_id(void);

void tp_pcmm_report_state_gate_state_lookup(void);
void tp_pcmm_report_state_gate_state_reason(void);

void tp_pcmm_gate_spec_flags_ds_dscp_disabled(void);
void tp_pcmm_gate_spec_flags_us_dscp_disabled(void);
void tp_pcmm_gate_spec_flags_ds_dscp_enabled(void);
void tp_pcmm_gate_spec_flags_us_dscp_enabled(void);
void tp_pcmm_gate_spec_flags(void);
void tp_pcmm_gate_spec_session(void);
void tp_pcmm_envelope_all_scn_types(void);
void tp_pcmm_scn_gate_envelope_ds(void);
void tp_pcmm_scn_gate_envelope_us(void);
void tp_pcmm_flow_spec_envelope_basic(void);
void tp_pcmm_legacy_classifier_basic(void);
void tp_pcmm_extended_classifier_basic(void);
void tp_pcmm_ipv6_classifier_basic(void);
void tp_pcmm_scn_gate_legacy_classifier(void);
#endif /* ifndef TP_PCMM_H */
