#ifndef FIELDS_H
#define FIELDS_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* clang-format off */
typedef struct {
    int     dscp_tos_field;
    int     dscp_tos_ovwr;
    int     dscp_tos_mask;
    int     preemption;
    int     priority;
    int     timer1;
    int     timer2;
    int     timer3;
    int     timer4;

    const char* direction;
} pcmm_gate_t;

typedef struct {
    const char* subscriber_id;
    const char* cmts_ip;
    
    pcmm_gate_t gate;

    int         application_id;
    long        gate_id;
    int         dry_run;
    
    size_t      envelope_size;   /* total envelope portion size */
    size_t      classifier_size; /* total classifier portion size*/
    
    bool failed;
    int failop;
} gctl_t;

#endif /* ifndef FIELDS_H*/
