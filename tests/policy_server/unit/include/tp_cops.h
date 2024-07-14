#ifndef TP_COPS_H
#define TP_COPS_H

#include "helpers.h"

void tp_cops_report_state_opcode_ok(void);
void tp_cops_report_state_opcode_to_acronym(void);
void tp_cops_report_state_opcode_to_string(void);
void tp_cops_common_handle_object(void);
void tp_cops_common_context_object(void);
void tp_cops_common_decision_object(void);
void tp_cops_client_accept_message(void);
void tp_cops_keepalive_message(void);

#endif /* ifndef TP_COPS_H */
