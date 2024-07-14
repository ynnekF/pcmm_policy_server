#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
#endif

#ifndef ROUTES_H
#define ROUTES_H

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ulfius.h>

#include "fields.h"
#include "lcm.h"
#include "ps.h"
#include "yyjson.h"

#define TP_STORAGE             "data/IGNORE_tp_api.txt"
#define TP_API_RESP            "data/IGNORE_tp_resp.txt"

#define CONNECT_REQUEST_FORMAT "{\"input\": {\"cmts_ip\": \"%s\", \"dry_run\": 0}}";
#define R_STRCONN              "{\"output\": {\"message\": \"connected to %s\"}}"
#define METRIC_ATTACH          ", \"build-time\": %f, \"wait-time\": %f, \"read-time\": %f}"
#define API_ERROR              "{\"output\": {\"error-code\": %d, \"error-message\": \"%s\"}}"

#define WAIT_FOR(seconds)                      \
        time_t timeout = time(NULL) + seconds; \
        while (time(NULL) < timeout)

#define DRYRUN_GID   (unsigned long)67496710
#define DRYRUN_CMD   "GATE-DR-ACK"
#define DRYRUN_APP   21003
#define ECONFLICT    100
#define ENOESTAB     101
#define ESOCKFAIL    102
#define ENOROOM      103
#define ENOCON       104
#define EINVREQ      105
#define EINVGATE     106
#define EBADPROF     107
#define EBADTYPE     108
#define EUNEXPC      109
#define ETIMEOUT     110
#define EINVIP       111
#define JSON_OK      200
#define JSON_DRYRUN  201
#define JSON_CONNECT 202

/* Cast function to Ulfius callback. */
#define a_cast (int (*)(request_t, response_t, void*))&

#define INFO     "INFO"
#define GET      "GET"
#define DEL      "DELETE"
#define POST     "POST"

/* Paths. */
#define QOS_DEL  "/gate-delete"
#define QOS_SET  "/gate-set"
#define QOS_GET  "/gate-info"
#define QOS_CON  "/connect"
#define LCM_CLR  "/clear"
#define LCM_STAT "/status"

#define INPUT   "input"
#define APP_ID  "appId"
#define GATE_ID "gateId"
#define SUB_ID  "subscriberId"
#define CMTS_IP "cmts_ip"
#define DRY_RUN "dry_run"

/* Gate */
#define GATE            "gate"
#define CLASSIFIERS     "classifiers"
#define GATE_SPEC       "gate-spec"
#define TRAFFIC_PROFILE "traffic-profile"
#define DIRECTION       "direction"

/* Speedboost */
#define SERVICE_CLASS_NAME "service-class-name"
#define DSCP_TOS_OVERWRITE "dscp-tos-overwrite"
#define DSCP_TOS_MASK      "dscp-tos-mask"
#define NUM_CLASSIFIERS    "num-classifiers"

/* Flow Spec */
#define FLOW_SPEC_PROFILE "flow-spec-profile"
#define SERVICE_NUMBER    "service-number"
#define T1                "t1"
#define T2                "t2"
#define T3                "t3"

/* Classifiers */
#define SRC_IP4             "srcIp"
#define DST_IP4             "dstIp"
#define SRC_IP6             "srcIp6"
#define DST_IP6             "dstIp6"
#define TOS_BYTE            "tos-byte"
#define TOS_MASK            "tos-mask"
#define PROTOCOL            "protocol"
#define PRIORITY            "priority"
#define TC_LOW              "tc-low"
#define TC_HIGH             "tc-high"
#define TC_MASK             "tc-mask"
#define FLOW_LABEL          "flow-label"
#define NEXT_HDR            "next-hdr"
#define ASTATE              "activation-state"
#define SRC_PORT_END        "srcPort-end"
#define DST_PORT_END        "dstPort-end"
#define DST_PORT_START      "dstPort-start"
#define SRC_PORT_START      "srcPort-start"
#define SRC_MASK            "srcIpMask"
#define DST_MASK            "dstIpMask"
#define IP6_CLASS           "ipv6-classifier"
#define EXT_CLASS           "ext-classifier"
#define LEG_CLASS           "classifier"
#define CLASS_ID            "classifier-id"
#define EXTENDED_CLASSIFIER 0
#define DEFAULT_CLASSIFIER  1
#define IPV6_CLASSIFIER     2

/* 0x00 Add classifier  */
/* 0x01 Replace classifier */
/* 0x02 Delete classifier */
/* 0x03 No change */
#define ACTION "action"

static pthread_t threads[MAXROOM];
static pthread_mutex_t lcm_lock;

typedef struct _u_response* response_t;     /* Ulfius Response type */
typedef const struct _u_request* request_t; /* Ulfius Request type */

/* Parse the object for the field name's corresponding value.
 * If found, return a yyjson_get_str value from the object.
 * Otherwise I believe this should return a null value. */
const char* gctl_otos(yy_val* object, char* field);

/* Parse the object for the field name's corresponding value.
 * If found, return a yyjson_get_int value from the object.
 * Otherwise I believe this should return a null value. */
int gctl_otoi(yy_val* object, char* field);

/* Return the `input` field from a PCMM request payload.
 * E.g., {"input": {"example": "fields"}}*/
yy_val* gctl_ytoi(yy_doc* doc);

int gctl_webapi_init(int max_cmts_connections, char** preflight, int pf_len);
int gctl_connect(request_t request, response_t response, lcm_t* lcm);
int gctl_04(request_t request, response_t response, lcm_t* lcm);
int gctl_07(request_t request, response_t response, lcm_t* lcm);
int gctl_10(request_t request, response_t response, lcm_t* lcm);
int gctl_lcm_reset(request_t req, response_t res, lcm_t* lcm);
int gctl_lcm_stat(request_t req, response_t res, lcm_t* lcm);

#endif
