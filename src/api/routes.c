#include "routes.h"
#include <stdarg.h>
#include <string.h>
#include "cops.h"
#include "iputil.h"
#include "ulfius.h"

#define WARN_LOCKLCM "failed to acquire threads lock (%s)"
#define WARN_LOCKERR "failed to initialize threads lock (%s)"
#define WARN_TIMEOUT "timed-out waiting for %i"

/*
 * Return the elapsed time in seconds between start and end.
 *
 * @start time_t value representing the start time
 * @end   tiem_t value representing the end time
 */
static double gctl_elapsed(time_t start, time_t end);

/*
 * Helper function which returns true if the object is NULL otherwise returns false
 *
 * @object Existing yyjson_val object or just a pointer to NULL
 */
static bool gctl_isnil(yyjson_val* object);

/*
 * Output the key's and types of the given yyjson object.
 * Note: Can be used within any non-root yyjson objects.
 *
 * @root Any yyjson document value which contains subfields
 */
static void gctl_it_json(yyjson_val* root);

/*
 * Gate control API util. - Called at the beginning of every endpoint callback to log the method
 * and request path on each and every request (i.e., POST /gate-set OR GET /gate-info).
 *
 * @request Initialized ulfius `struct _u_request` object
 */
static void gctl_log(request_t request);

/*
 * Gate control API util. - During request body validations (after processing into yyjson_doc) this
 * function accpets a reason-code integer which gets set in the gctl_t object's field `failop`.
 * This is just a helper to reduce dup. code that also allows the API response function to correctly
 * populate the error message in the Ulfius response.
 *
 * @gc          Gate control API object
 * @reason      Reason code which MUST correspond to a description in `gctl_resp`
 */
static gctl_t gctl_set_schemaerr(gctl_t gc, int reason);

/*
 * Gate control API util. - After processing the request body of POST /gate-set request, this
 * function is invoked to compute and return the total request size (excluding COPS specific objs).
 *
 * @gsz Gate specification size (should be exactly 16)
 * @csz Classifier size (The classifier objects have a maximum size of 320 (x5 IPv6 classifiers))
 * @esz Envelope size (The envelope object has a maximum size of 92 (FlowSpec envelope))
 */
static size_t gctl_policy_decision_size(size_t gsz, size_t csz, size_t esz);

/*
 * Gate control API util. - On a POST /connect request which successfully connects to a CMTS and
 * spins off a new thread, this function is invoked to store the `pthread_t` thread ID in the global
 * `threads` array. Since this is a shared resource, it must be locked.
 *
 * @tid pthread_t opaque object which corresponds to a thread ID
 * @pos The position value where the thread ID will be stored. This value must match what the
 *      current LCM count value so any subsequent /clear calls are executed correctly.
 */
static int gctl_lock_tid(pthread_t tid, size_t pos);

/*
 * Gate control API util. - This is the primary API response builder and cleanup function. This
 * function MUST free the yyjson_doc given, call ulfius_set_string_body_response with a valid
 * response buffer that corresponds to the given code, then return U_CALLBACK_COMPLETE.
 *
 * @buffer
 * @code
 * @doc
 * @response
 * @...
 */
static int json_frommsg(char* buffer, uint8_t code, yyjson_doc* doc, response_t response, ...);
static int json_err(uint8_t code, yyjson_doc* doc, response_t response, ...);
static int json_ok(uint8_t code, yyjson_doc* doc, response_t response, ...);

static void
gctl_it_json(yyjson_val* root) {
        /* Init iter.*/
        yy_iter iter;
        yy_init(root, &iter);
        yyjson_val *key, *val;

        /* Debug a yyjson object. */
        while ((key = yy_next(&iter))) {
                val = yy_nval(key);
                printf("%s: %s\n", yy_str(key), yy_type(val));
        }
}

static bool
gctl_isnil(yyjson_val* object) {
        return !object || object == NULL;
}

static double
gctl_elapsed(time_t start, time_t end) {
        return (double)(end - start) / CLOCKS_PER_SEC;
}

static void
gctl_log(request_t request) {
        info("%s %s request received!", request->http_verb, request->http_url);
}

const char*
gctl_otos(yyjson_val* object, char* field) {
        /* Gate control API util. - object to string. */
        yyjson_val* temp = yyjson_obj_get(object, field);
        return yy_str(temp);
}

int
gctl_otoi(yyjson_val* object, char* field) {
        /* Gate control API util. - object to int. */
        yyjson_val* temp = yyjson_obj_get(object, field);
        return yy_int(temp);
}

yyjson_val*
gctl_ytoi(yyjson_doc* doc) {
        /* yyjson document to input. */
        yyjson_val* root = yy_root(doc);
        return yyjson_obj_get(root, INPUT);
}

static gctl_t
gctl_set_schemaerr(gctl_t gc, int reason) {
        error("API validations failed with reason code '%i'", reason);

        /*
         * Helper function which sets the `failed` field to true, and sets `failop`
         * to the given reason-code (which indicates where it failed validations).
         */
        gc.failed = true;
        gc.failop = reason;

        return gc;
}

static int
gctl_lock_tid(pthread_t tid, size_t pos) {
        errno = 0;

        if (pthread_mutex_lock(&lcm_lock) != 0) {
                error(WARN_LOCKLCM, strerror(errno));

                if (pthread_mutex_init(&lcm_lock, NULL) != 0) {
                        fatal(WARN_LOCKERR, strerror(errno));

                        return -1;
                }

                if (pthread_mutex_lock(&lcm_lock) != 0) {
                        error(WARN_LOCKLCM, strerror(errno));

                        return -1;
                }
        }
        /*
         * Store the pthread_t thread ID in the static global threads array so that it can be
         * used to send a signal to the thread itself indicating it must return.
         */
        threads[pos] = tid;
        pthread_mutex_unlock(&lcm_lock);

        return 0;
}

static size_t
gctl_policy_decision_size(size_t gsz, size_t csz, size_t esz) {
        size_t total = gsz + csz + esz;

        if (total > (16 + 320 + 92) + 1)
                warning("maximum size exceeded");

        return total;
}

static int
json_err(uint8_t code, yyjson_doc* doc, response_t response, ...) {
        char e[90];

        memset(e, 0, sizeof(e));

        va_list args;
        va_start(args, response);

        switch (code) {
                case EINVREQ:   sprintf(e, "invalid payload"); break;
                case EINVGATE:  sprintf(e, "invalid gate-specification given"); break;
                case EBADPROF:  sprintf(e, "invalid traffic-profile given"); break;
                case EBADTYPE:  sprintf(e, "invalid classifier type given"); break;
                case EUNEXPC:   sprintf(e, "invalid number of classifiers, expected >1/<5"); break;
                case ENOROOM:   sprintf(e, "maximum number of connections has been reached"); break;
                case ESOCKFAIL: vsprintf(e, "failed to establish socket connection", args); break;
                case ECONFLICT: vsprintf(e, "connection already established on %s", args); break;
                case ENOESTAB:  vsprintf(e, "no cops connection has been established", args); break;
                case ETIMEOUT:  vsprintf(e, "timed out waiting for id '%u'", args); break;
                case ENOCON:    vsprintf(e, "no connection has been found for '%s'", args); break;
                case EINVIP:    vsprintf(e, "invalid ip address '%s'", args); break;
                default:        sprintf(e, "undefined error");
        }
        va_end(args);
        yy_free(doc);

        char buffer[200];
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, API_ERROR, code, e);

        const char* ptr = (const char*)buffer;
        ulfius_set_string_body_response(response, 400, ptr);

#if defined(UNIT_TEST)
        stash_data(buffer, TP_API_RESP, 0);
#endif
        return U_CALLBACK_COMPLETE;
}

static int
json_ok(uint8_t code, yyjson_doc* doc, response_t response, ...) {
        char buffer[200];
        memset(buffer, 0, sizeof(buffer));

        if (code == JSON_DRYRUN) {
                sprintf(buffer, RESPONSE_DRYRUN, 0UL, "GATE-DR-ACK", 21003, 0.0, 0.0);

        } else if (code == JSON_CONNECT) {
                va_list args;
                va_start(args, response);
                vsprintf(buffer, R_STRCONN, args);
                va_end(args);
        } else {
                error("unknown code given to %s", __func__);
        }
        yy_free(doc);

        code = 200;
        ulfius_set_string_body_response(response, code, buffer);

#if defined(UNIT_TEST)
        stash_data(buffer, TP_API_RESP, 0);
#endif
        return U_CALLBACK_COMPLETE;
}

static int
json_frommsg(char* buffer, uint8_t code, yyjson_doc* doc, response_t response, ...) {
        va_list args;
        va_start(args, response);

        int i = strlen(buffer), j = 100;

        char metrics[i];
        char message[i + j];
        vsprintf(metrics, METRIC_ATTACH, args);

        memcpy(message, buffer, i);
        memcpy(message + i, metrics, j);

        ulfius_set_string_body_response(response, code, message);

#if defined(UNIT_TEST)
        stash_data(buffer, TP_API_RESP, 0);
#endif
        va_end(args);
        yy_free(doc);

        code = 200;
        return U_CALLBACK_COMPLETE;
}

int
gctl_webapi_init(int max_pep, char** preflight, int pf_len) {
        if (pthread_mutex_init(&lcm_lock, NULL) != 0) {
                fatal(WARN_LOCKERR, strerror(errno));

                return 1;
        }

        uint16_t port = conf_get_ulfius_server_port();
        uint8_t addrF = conf_get_ulfius_af_type();

        struct _u_instance instance;

        if (addrF == AF_INET) {
                struct sockaddr_in sin;
                memset(&sin, 0, sizeof(sin));

                sin.sin_family = AF_INET;
                sin.sin_port = htons(port);
                sin.sin_addr.s_addr = htonl(INADDR_ANY);

                /* Initialize instance for IPv4 ONLY. Return 1 on failure. */
                if (ulfius_init_instance(&instance, port, &sin, NULL) != U_OK)
                        return 1;

        } else {
                struct sockaddr_in6 sin6;
                memset(&sin6, 0, sizeof(sin6));

                sin6.sin6_family = AF_INET6;  /* Address family IPv6. */
                sin6.sin6_addr = in6addr_any; /* Bind to any available network interface. */
                sin6.sin6_port = htons(port); /* Network byte order long. */

                unsigned short net_type = (addrF & U_USE_ALL) ? U_USE_ALL : U_USE_IPV6;

                /* Initialize instance for IPv6/IPv4. Return 1 on failure. */
                if (ulfius_init_instance_ipv6(&instance, port, &sin6, net_type, NULL) != U_OK)
                        return 1;
        }

        lcm_t* lcm = lcm_init(max_pep);
        if (!lcm) {
                fatal("failed to initialize lcm");

                return 1;
        }

        ulfius_add_endpoint_by_val(&instance, POST, LCM_CLR, NULL, 0, a_cast(gctl_lcm_reset), lcm);
        ulfius_add_endpoint_by_val(&instance, GET, LCM_STAT, NULL, 0, a_cast(gctl_lcm_stat), lcm);
        ulfius_add_endpoint_by_val(&instance, POST, QOS_CON, NULL, 0, a_cast(gctl_connect), lcm);
        ulfius_add_endpoint_by_val(&instance, POST, QOS_SET, NULL, 0, a_cast(gctl_04), lcm);
        ulfius_add_endpoint_by_val(&instance, GET, QOS_GET, NULL, 0, a_cast(gctl_07), lcm);
        ulfius_add_endpoint_by_val(&instance, DEL, QOS_DEL, NULL, 0, a_cast(gctl_10), lcm);

        if (ulfius_start_framework(&instance) != U_OK)
                return 1;

        info("initialized ulfius framework");

        /* Handle pre-configurable CMTS connections. */
        char** ptr = preflight;

        for (int i = 0; i < pf_len; i++) {
                ptr = &preflight[i];
                /*
                 * Populate template with IP ({"input": "cmts_ip": <ptr>, ..}), then initialize a
                 * pseudo Ulfius API request object under the path /preflight/connect with
                 * the payload. After executing the request, free the payload and pointer.
                 */
                char* format = CONNECT_REQUEST_FORMAT;
                char* buffer = (char*)malloc(sizeof(char*) * strlen(format));

                sprintf(buffer, format, *ptr);
                debug("request [%i] = %s", strlen(buffer), buffer);

                struct _u_request req;
                ulfius_init_request(&req);
                ulfius_set_request_properties(&req, U_OPT_HTTP_URL, "/preflight/connect", U_OPT_HTTP_VERB, POST,
                                              U_OPT_BINARY_BODY, buffer, strlen(buffer), U_OPT_NONE);

                gctl_connect(&req, NULL, lcm);
                kfree(buffer);
                kfree(*ptr);
                ++ptr;
        }

        int c;
        while ((c = getchar()) != '\n');

        kfree(lcm);

        ulfius_stop_framework(&instance);
        ulfius_clean_instance(&instance);

        gctl_it_json(NULL);
        return EXIT_SUCCESS;
}

gctl_t
gctl_new_request(yyjson_val* input) {
        gctl_t gc;
        gc.gate_id = gctl_otoi(input, GATE_ID);
        gc.cmts_ip = gctl_otos(input, CMTS_IP);
        gc.dry_run = gctl_otoi(input, DRY_RUN);

        if (!gc.gate_id)
                gc.gate_id = 0;

        if (!gc.dry_run)
                gc.dry_run = 0;

        gc.application_id = gctl_otoi(input, APP_ID);
        gc.subscriber_id = gctl_otos(input, SUB_ID);
        gc.failed = false;

        return gc;
}

gctl_t
gctl_read_policy(yyjson_val* input, uch classifier[], uch envelope[]) {
        gctl_t gc = gctl_new_request(input);

        yyjson_val* gate = yyjson_obj_get(input, GATE);
        yyjson_val* spec = yyjson_obj_get(gate, GATE_SPEC);

        if (gctl_isnil(gate) || gctl_isnil(spec))
                return gctl_set_schemaerr(gc, EINVGATE);

        /* Read the required traffic-profile and profile type. */
        yyjson_val* traffic = yyjson_obj_get(gate, TRAFFIC_PROFILE);
        yyjson_val* profile = yyjson_obj_get(traffic, SERVICE_CLASS_NAME);

        if (!profile || profile == NULL) {
                /* Flow Spec envelope. */
                gc.gate.dscp_tos_field = 0;

                if (gctl_isnil(profile = yyjson_obj_get(traffic, FLOW_SPEC_PROFILE)))
                        return gctl_set_schemaerr(gc, EBADPROF);

                /*
                 * If Service Number is set to two, this signals Guaranteed service and the CMTS
                 * must utilize both the TSpec + RSpec values to perform the necessary authorization
                 * reservation and commit operations. TODO is this number always 2 from PCMM.
                 */
                pcmm_flowspec_envelope(envelope, gctl_otoi(profile, SERVICE_NUMBER));
                gc.envelope_size = 92;
        } else {
                /*
                 * DOCSIS Service Class Name object defines the preconfigured Service
                 * Class Name associated with a Gate (i.e., usSMI001, dsSMI001).
                 */
                pcmm_scn_envelope(envelope, (const unsigned char*)yy_str(profile));
                gc.envelope_size = 20;
        }

        /* Gate timers. */
        int t1 = gctl_otoi(spec, T1);
        int t2 = gctl_otoi(spec, T2);
        int t3 = gctl_otoi(spec, T3);

        gc.gate.timer1 = (t1) ? t1 : 0;
        gc.gate.timer2 = (t2) ? t2 : 0;
        gc.gate.timer3 = (t3) ? t3 : 0;
        gc.gate.timer4 = 0;

        /* DSCP/ToS values. */
        int tos_ovwr = gctl_otoi(spec, DSCP_TOS_OVERWRITE);
        int tos_mask = gctl_otoi(spec, DSCP_TOS_MASK);

        gc.gate.dscp_tos_ovwr = (tos_ovwr) ? tos_ovwr : 0;
        gc.gate.dscp_tos_mask = (tos_mask) ? tos_mask : 0;

        /* Gate spec. direction used to build flags field. */
        gc.gate.direction = gctl_otos(spec, DIRECTION);

        /*
         * Parse the request body's gate.classifiers object for Legacy classifiers, Extended
         * classifiers and IPv6 classifiers. This API requires that a single classifier be
         * given and no more than 5 classifiers be processed at a time, otherwise returns err.
         */
        yyjson_val* classifiers = yyjson_obj_get(gate, CLASSIFIERS);

        size_t clen = yyjson_get_len(classifiers);

        /* Accept a maximum of 5 classifiers, otherwise err. */
        if (clen <= 0 || clen > 5)
                return gctl_set_schemaerr(gc, EUNEXPC);

        gc.classifier_size = 0;

        for (size_t i = 0; i < clen; i++) {
                yyjson_val* element = yyjson_arr_get(classifiers, i);

                /* Find classifier type. */
                yyjson_val* obj = yyjson_obj_get(element, EXT_CLASS);
                int classifier_type = EXTENDED_CLASSIFIER;

                if (gctl_isnil(obj)) {
                        obj = yyjson_obj_get(element, LEG_CLASS);
                        classifier_type = DEFAULT_CLASSIFIER;

                        if (gctl_isnil(obj)) {
                                obj = yyjson_obj_get(element, IP6_CLASS);
                                classifier_type = IPV6_CLASSIFIER;

                                if (gctl_isnil(obj))
                                        return gctl_set_schemaerr(gc, EBADTYPE);
                        }
                }

                /* All classifiers use these fields. */
                char* src_ipv4 = (char*)gctl_otos(obj, SRC_IP4);
                char* dst_ipv4 = (char*)gctl_otos(obj, DST_IP4);

                int src_port_start = gctl_otoi(obj, SRC_PORT_START);
                int dst_port_start = gctl_otoi(obj, DST_PORT_START);

                int c_tos_field = gctl_otoi(obj, TOS_BYTE);
                int c_tos_mask = gctl_otoi(obj, TOS_MASK);
                int protocol = gctl_otoi(obj, PROTOCOL);
                int priority = gctl_otoi(obj, PRIORITY);
                int reserved = 0;

                if (!priority)
                        priority = 64;

                /* Pointer to final request object. */
                unsigned char* ptr = (unsigned char*)(classifier + gc.classifier_size);

                if (classifier_type == DEFAULT_CLASSIFIER) {
                        pcmm_legacy_classifier(ptr, protocol, c_tos_field, c_tos_mask, src_ipv4, dst_ipv4,
                                               src_port_start, dst_port_start, priority, reserved);

                        /* Legacy classifiers ALWAYS have a size of 24. */
                        gc.classifier_size += 24;
                        continue;
                }

                /* Extended/IPv6 classifier fields. */
                int src_port_end = gctl_otoi(obj, SRC_PORT_END);
                int dst_port_end = gctl_otoi(obj, DST_PORT_END);

                /* Extended/IPv6 action fields. */
                int class_action = gctl_otoi(obj, ACTION);
                int class_state = gctl_otoi(obj, ASTATE);
                int class_uuid = gctl_otoi(element, CLASS_ID);

                if (classifier_type == EXTENDED_CLASSIFIER) {
                        char* src_mask = (char*)gctl_otos(obj, SRC_MASK);
                        char* dst_mask = (char*)gctl_otos(obj, DST_MASK);

                        pcmm_extended_classifier(ptr, protocol, src_ipv4, src_mask, src_port_start, src_port_end,
                                                 dst_ipv4, dst_mask, dst_port_start, dst_port_end, priority,
                                                 c_tos_field, c_tos_mask, class_uuid, class_state, class_action);

                        /* Extended classifiers ALWAYS have a size of 40. */
                        gc.classifier_size += 40;
                        continue;
                }

                /* IPv6 fields only. */
                char* src_ipv6 = (char*)gctl_otos(obj, SRC_IP6);
                char* dst_ipv6 = (char*)gctl_otos(obj, DST_IP6);
                int flow_label = gctl_otoi(obj, FLOW_LABEL);
                int next_header = gctl_otoi(obj, NEXT_HDR);

                /* IPv6 traffic class fields. */
                int tc_high = gctl_otoi(obj, TC_HIGH);
                int tc_mask = gctl_otoi(obj, TC_MASK);
                int tc_low = gctl_otoi(obj, TC_LOW);

                pcmm_ipv6_classifier(ptr, tc_low, tc_high, tc_mask, flow_label, next_header, src_ipv6, dst_ipv6,
                                     src_port_start, src_port_end, dst_port_start, dst_port_end, class_uuid, priority,
                                     class_state, class_action);

                /* IPv6 classifiers ALWAYS have a size of 64. */
                gc.classifier_size += 64;
        }
        return gc;
}

double
gctl_async_get_decision(char* dst, uint16_t id) {
        time_t start = clock();

        char filename[100];
        memset(filename, 0, 100);
        snprintf(filename, sizeof(filename), "data/yrpt_%u.txt", id);

        /* Indicates whether data was read. */
        bool ok = false;

        WAIT_FOR(15) {
                FILE* fp = fopen(filename, "r");

                if (!fp) {
                        if (fp != NULL)
                                fclose(fp);
                        fp = NULL;
                        continue;
                }

                if (fgets(dst, 400, fp) != NULL) {
                        fflush(fp);
                        if (fclose(fp) != 0)
                                error("failed to close file: %s", strerror(errno));

                        fp = NULL;
                        ok = true;

                        remove(filename);
                        break;
                }
                /*
                 * Likely file exists but data wasn't consumed (in-progress)
                 * Reset the file pointer and retry. Nothing else to do.
                 */
                fclose(fp);
                fp = NULL;
        }
        time_t end = clock();

        if (!ok)
                memset(dst, 0, sizeof(&dst));

        return gctl_elapsed(start, end);
}

int
gctl_connect(request_t req, response_t res, lcm_t* lcm) {
        gctl_log(req);

        if (req->binary_body_length == 0)
                return U_CALLBACK_COMPLETE;

        yyjson_doc* doc = yyjson_read(req->binary_body,        /* Raw body. */
                                      req->binary_body_length, /* Raw body length. */
                                      YYJSON_READ_NOFLAG);     /* yyjson options. */

        yyjson_val* input = gctl_ytoi(doc);

        /*
         * Read in the request fields input.cmts_ip and validate that the local connection
         * manager has no conflicting clients and hasn't yet reached the hard PEP limit.
         */
        char* ip = (char*)gctl_otos(input, CMTS_IP);

        if (!is_ip4(ip))
                return json_err(EINVIP, doc, res, ip);

        if (lcm_getps(lcm, ip) != NULL)
                return json_err(ECONFLICT, doc, res, ip);

        if (lcm_alloc_ok(lcm) == LCM_ERR)
                return json_err(ENOROOM, doc, res, ip);

        /*
         * Attempt to create a new Policy Server event object and connect it to the given
         * CMTS IP address. On any failure return `json_err` with corresponding code.
         */
        ps_session_t* ps = ps_new(ip);

        if (ps == NULL) {
                error("policy server is null");
                return U_CALLBACK_COMPLETE;
        }

        if (!gctl_otoi(input, DRY_RUN)) {
                if (ps_admctl(ps) == 0) {
                        /*
                         * Failed to connect to the given IP address. Free the client object's
                         * IP address, close the socket (should be closed) and free the client.
                         */
                        ps_free(ps);

                        return json_err(ESOCKFAIL, doc, res, ip);
                } else {
                        info("sucessfully connected to %s", ip);
                }
        }

        pthread_t thread = ps_boot(ps);
        if (thread == 0) {
                /*
                 * Failed to spin off a new policy server thread loop. Free the client object's
                 * IP address, close the connected socket and free the client entirely.
                 */
                ps_free(ps);

                return json_err(ESOCKFAIL, doc, res, ip);
        }

        int pos = lcm_set(lcm, ps);
        if (pos < 0)
                error("failed to add client to lcm (%i)", pos);

        if (gctl_lock_tid(thread, pos) < 0) {
                error("failed to add thread to global list '%s'", strerror(errno));

                return U_CALLBACK_COMPLETE;
        }

        return json_ok(JSON_CONNECT, doc, res, ps->cmts_addr);
}

int
gctl_request(request_t req, response_t res, lcm_t* lcm, int op) {
        gctl_log(req);
        time_t start = clock();

        yyjson_doc* doc = yyjson_read(req->binary_body,        /* Raw body. */
                                      req->binary_body_length, /* Raw body length. */
                                      YYJSON_READ_NOFLAG);     /* yyjson options. */

        gctl_t gc = gctl_new_request(gctl_ytoi(doc));
        ps_session_t* ps = lcm_getps(lcm, gc.cmts_ip);

        if (ps == NULL)
                return json_err(ENOCON, doc, res, gc.cmts_ip);

        /*
         * Sendoff the Gate-Info or Gate-Delete request and receive the random transaction ID
         * associated with the request used to lookup the ephemeral response file generated.
         */
        const u16 id = ps_proxy(ps, op, gc, NULL, 0);
        const time_t sent = clock();

        if (gc.dry_run)
                return json_ok(JSON_DRYRUN, doc, res);

        char response[400];
        memset(response, 0, 400);
        gctl_async_get_decision(response, id);

        if (sizeof(response) == 0 || strlen(response) == 0) {
                warning(WARN_TIMEOUT, id);

                return json_err(ETIMEOUT, doc, res, id);
        }

        double tb = gctl_elapsed(start, sent);   /* Time taken to build and send the request. */
        double tw = gctl_elapsed(sent, clock()); /* Time taken to receive a response. */

        return json_frommsg(response, JSON_OK, doc, res, tb, tw, 0.0);
}

int
gctl_07(request_t req, response_t res, lcm_t* lcm) {
        return gctl_request(req, res, lcm, GATE_INFO);
}

int
gctl_10(request_t req, response_t res, lcm_t* lcm) {
        return gctl_request(req, res, lcm, GATE_DEL);
}

int
gctl_04(request_t req, response_t res, lcm_t* lcm) {
        gctl_log(req);
        time_t start = clock();

        yyjson_doc* doc = yyjson_read(req->binary_body,        /* Raw body. */
                                      req->binary_body_length, /* Raw body length. */
                                      YYJSON_READ_NOFLAG);     /* yyjson options. */

        yyjson_val* input = gctl_ytoi(doc);

        unsigned char pktmm_gate[16];
        unsigned char pktmm_clsf[320];
        unsigned char pktmm_envl[92];

        memset(pktmm_gate, 0, sizeof(pktmm_gate));
        memset(pktmm_envl, 0, sizeof(pktmm_envl));
        memset(pktmm_clsf, 0, sizeof(pktmm_clsf));

        gctl_t gc = gctl_read_policy(input, pktmm_clsf, pktmm_envl);

        if (gc.failed) {
                /*
                 * Input request validation failed, `failed` has been marked true. If the failop
                 * field has been populated (gctl_schemaerr() call), pass that as primary code.
                 */
                int reason = (gc.failop) ? gc.failop : EINVREQ;
                return json_err(reason, doc, res);
        }

        size_t len = gctl_policy_decision_size(16, gc.envelope_size, gc.classifier_size);

        pcmm_gate_t gate = gc.gate;
        pcmm_gate(pktmm_gate, (char*)gate.direction, gate.priority, gate.preemption, gate.dscp_tos_ovwr,
                  gate.dscp_tos_mask, gate.timer1, gate.timer2, gate.timer3, gate.timer4);

        size_t i = 0;
        uint8_t data[len];
        memset(data, 0, sizeof(data));

        concat_c8(data, &i, pktmm_gate, 16);
        concat_c8(data, &i, pktmm_envl, gc.envelope_size);
        concat_c8(data, &i, pktmm_clsf, gc.classifier_size);

        ps_session_t* client = lcm_getps(lcm, gc.cmts_ip);
        if (!client)
                return json_err(ENOCON, doc, res, gc.cmts_ip);

        /*
         * Sendoff the Gate-Set request and receive the random transaction ID associated with
         * the request used to lookup the ephemeral response file generated.
         */
        const uint16_t id = ps_proxy(client, GATE_SET, gc, data, len);
        const time_t sent = clock();

        if (gc.dry_run > 0) {
#if defined(UNIT_TEST)
                /*
                 * Unit tests under the `tests` directory, validating the result of
                 * `gctl_read_policy` requires that the QoS service data be stored.
                 * See all tests under tp_api for reference. Then return dryrun.
                 */
                stash_u8_data(data, TP_STORAGE, len);
#endif
                return json_ok(JSON_DRYRUN, doc, res);
        }

        const time_t read_start = clock();

        char response[200];
        memset(response, 0, 200);
        gctl_async_get_decision(response, id);

        if (sizeof(response) == 0 || strlen(response) == 0) {
                warning(WARN_TIMEOUT, id);
                return json_err(ETIMEOUT, doc, res, id);
        }

        double tb = gctl_elapsed(start, sent);         /* Time taken to build and send request. */
        double tw = gctl_elapsed(sent, clock());       /* Time taken waiting for a response. */
        double tr = gctl_elapsed(read_start, clock()); /* Time taken to read a response. */

        return json_frommsg(response, JSON_OK, doc, res, tb, tw, tr);
}

int
gctl_lcm_reset(request_t req, response_t res, lcm_t* lcm) {
        errno = 0;

        gctl_log(req);

        if (pthread_mutex_lock(&lcm_lock) != 0) {
                warning(WARN_LOCKLCM, strerror(errno));

                if (pthread_mutex_init(&lcm_lock, NULL) != 0) {
                        warning(WARN_LOCKERR, strerror(errno));

                        return U_CALLBACK_COMPLETE;
                }

                if (pthread_mutex_lock(&lcm_lock) != 0) {
                        error(WARN_LOCKLCM, strerror(errno));

                        return U_CALLBACK_COMPLETE;
                }
        }

        if (lcm->count <= 0) {
                /*
                 * If the current size indicated by the LCM is zero, return immediately
                 * as there are no threads to kill or sockets to close. Jump to the cleanup
                 * function to reset some stats (which should be redundant.)
                 */
                info("no existing threads to kill");

                pthread_mutex_unlock(&lcm_lock);
                return U_CALLBACK_COMPLETE;
        }

        for (size_t i = 0; i < lcm->count; i++) {
                pthread_t id = threads[i];

                ps_session_t* ps = lcm->clients[i];

                info("signaling kill %li/%s", id, ps->cmts_addr);

                /*
                 * Toggle the 'signal' die within the client to force the infinite loop (fsm)
                 * that it needs to exit as soon as possible. Then send a cancellation request
                 * to the thread to call the thread-specific data destructors.
                 */
                pthread_mutex_lock(&ps->evnt_lock);
                ps->die = true;
                pthread_mutex_unlock(&ps->evnt_lock);
#ifndef linux
                pthread_cancel(id);
#endif
                pthread_join(id, NULL);

                if (ps->sock <= 0) {
                        /*
                         * When closing an invalid socket will run into errors / hanging
                         * code when performing socket opertionas on non-sockets, primarily
                         * during testing. If the socket is invalid don't attempt to close.
                         */
                        warning("received invalid fd '%i', skipping", ps->sock);
                } else {
                        info("closing socket %i", ps->sock);
                        sock_close(ps->sock);
                }

                /*
                 * Free any allocated memory surrounding the client which involves the
                 * client specific information RPT data and the struct reference itself.
                 */
                debug("freeing client %li/%s", id, ps->cmts_addr);
                ps_free(ps);

                /* Set the location in `threads` to NULL. */
                threads[i] = NULL;
        }
        lcm->count = 0;
        sleep(1);
        pthread_mutex_unlock(&lcm_lock);

        info("/clear complete");

        (void)res;
        return U_CALLBACK_COMPLETE;
}

int
gctl_lcm_stat(request_t req, response_t res, lcm_t* lcm) {
        gctl_log(req);

        ulfius_set_string_body_response(res, 200, "ok");

        (void)lcm;
        return U_CALLBACK_COMPLETE;
}
