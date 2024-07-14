#include "ps.h"
#include <stdint.h>
#include <string.h>
#include "log.h"

#define WARN_BROKEN_PIPE   "attempting to write to broken pipe"
#define WARN_OVERFLOW      "possible overflow with value %llu"
#define WARN_UNSOL_RPT     "invalid report bits"
#define WARN_EHDR          "invalid header %lu/%lu/%lu"
#define SOL_SELECT_RETRIES 10

/*
 * Use getsockopt() and SO_ERROR to report error status and clear it before attempting to close
 * the socket (reference see `sock_close` which is the only place that should invoke this.)
 *
 * @fd  Active/Inactive socket file descriptor
 */
static int sock_SO_ERROR(int fd);

/*
 * Write a message to the socket file-descriptor
 *
 * @self    Client object
 * @msg     Buffer containing message written to the socket fd
 * @bytes   Length of the message written
 */
static void sock_write(ps_session_t* self, uint8_t* msg, int bytes);

/*
 * Connect a socket to the pre-configured CMTS connection data
 *
 * Handle EINPROGRESS socket code - The socket is nonblocking and the connection cannot be
 * completed immediately. Create a fd_set which ONLY contains the configured socket, then
 * call `select` to monitor the status. https://man7.org/linux/man-pages/man2/connect.2.html
 */
static int sock_connect(ps_session_t* self);

/*
 * Set custom socket options related to keep-alivces and Nagle's algorithm
 *
 * SO_KEEPALIVE Enables sending of keep-alive messages on connection-oriented sockets
 * O_NONBLOCK   Prevents recv() from blocking when no messages are available. recv()
 *              fails and sets errno to EAGAIN or EWOULDBLOCK.
 */
static int sock_setsockopts(int fd);

/*
 * Set the O_NONBLOCK open flag as a property on the given open file descriptor. The primary socket
 * must be non-blocking to prevent the calling process from being blocked waiting for data.
 *
 * @fd Active/Inactive socket file descriptor
 */
static int sock_set_nonblock(int fd);

/*
 * Return a timeval structure which pulls and sets the maximum amount of time to wait when
 * connecting a socket (note: this pulls the timeout value (seconds) from our settings file)
 */
static struct timeval sock_get_timeoutv(void);

/*
 * The keep-alive message MUST be transmitted by the PEP within the period period defined by the
 * minimum of all KA Timer values specified in all received CAT messages for the connection. A KA
 * message MUST be generated randomly between 1/4 and 3/4 of this minimum KA timer interval. When
 * the PDP receives a keep-alive message from a PEP, it MUST echo a keep-alive back to the PEP. This
 * message provides validation for each side that the connection is still functioning on even when
 * there is no other messaging.
 *
 * @self (typedef struct)
 */
static void sock_keepalive(ps_session_t* self);

/*
 * (RPT) Report-State Operation
 *
 * The RPT message is used by the PEP to communicate to the PDP its success or failure in carrying
 * out the PDP's decision, or to report an accounting related change in state. The Report-Type
 * specifies the kind of report and the optional ClientSI can carry additional information per
 * Client-Type. The client sends a RPT messgae to the server indicating changes to the request
 * state in the client. The client sends this to inform the server of the actual resource reserved
 * after the server has granted admission. The client can also use Report-State to periodically
 * inform the server the current state of the client.
 */
static void ps_pcmm_report_decision(pcmm_rpt_t rpt, int classifier_type);
static void ps_pcmm_report(char* buf, size_t* ptr, uint16_t rpt_length);
static int ps_polld(ps_session_t* self, int target);
static int ps_recvd(ps_session_t* self);

__attribute__((unused())) static int ps_find_u16(uint8_t* array, size_t sz, uint16_t target);

/*
 * The Client-Open message can be used by the PEP to specify to the PDP
 * the client-types the PEP can support, the last PDP to which the PEP
 * connected for the given client-type, and/or client specific feature
 * negotiation. A Client-Open message can be sent to the PDP at any time
 * and multiple Client-Open messages for the same client-type are
 * allowed (in case of global state changes).
 *
 * The client sends a REQ message to the server to request admission control
 * decision information or device configuration information. The REQ message
 * may contain client-specific information that the server uses, together with
 * data in the session admission policy database, to make policy-based decisions.
 */
static void* ps_statemachine(void* obj);

#if defined(UNIT_TEST)

/*
 * Unit test mock API call requires the constructed request
 * be stored in the below file for SET gate validations.
 */

void
stash_u8_data(uint8_t* buffer, const char* filename, size_t len) {
        int fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
        if (fd < 0)
                error("failed to open test-write file: %s", strerror(errno));
        if (len == 0)
                len = strlen((const char*)buffer);
        int tp_write_size = write(fd, buffer, len);
        close(fd);
        debug("wrote %d bytes to %s", tp_write_size, filename);
}

void
stash_data(char* buffer, const char* filename, size_t len) {
        int fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
        if (fd < 0)
                error("failed to open test-write file: %s", strerror(errno));
        if (len == 0)
                len = strlen(buffer);
        int tp_write_size = write(fd, buffer, len);
        close(fd);
        debug("wrote %d bytes to %s", tp_write_size, filename);
}
#endif

static int
sock_SO_ERROR(int fd) {
        int err = 1;
        socklen_t len = sizeof(err);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&err, &len) == -1)
                error("socket error: %s", strerror(errno));

        if (err)
                errno = err;

        return err;
}

static void
sock_write(ps_session_t* self, uint8_t* msg, int bytes_expected) {
        if (!self->connection) {
                warning(WARN_BROKEN_PIPE);

                return;
        }

        ssize_t bytes = write(self->sock, msg, bytes_expected);

        if ((bytes < 0) || bytes < bytes_expected)
                error("socket write failed on error '%i' or partial write errno (%s) -"
                      "bytes written=%i, bytes_attempted=%i, size_limit=%i ",
                      errno, strerror(errno), bytes, bytes_expected, -1);
}

static void
sock_keepalive(ps_session_t* self) {
        uint8_t ka[8];
        memset(ka, 0, sizeof(ka));

        info("keep-alive received from %s", self->cmts_addr);
        cops_keepalive(ka);

        sock_write(self, ka, 8);
}

static int
sock_set_nonblock(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);

        if (flags == -1)
                return flags;

        flags |= O_NONBLOCK;

        if (fcntl(fd, F_SETFL, flags) == -1)
                return -1;

        return 0;
}

static int
sock_setsockopts(int fd) {
        int ka = 1;
        int nd = 0;

        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka)) != 0)
                return -1;

        if (setsockopt(fd, SOL_SOCKET, TCP_NODELAY, &nd, sizeof(nd)))
                return -1;

        if (sock_set_nonblock(fd) < 0)
                return -1;

        return 0;
}

static struct timeval
sock_get_timeoutv(void) {
        struct timeval timeout_o;
        memset(&timeout_o, 0, sizeof(timeout_o));

        timeout_o.tv_sec = conf_get_maxconnect_secs();
        timeout_o.tv_usec = 0;

        return timeout_o;
}

static int
sock_connect(ps_session_t* self) {
        debug("%s:%u connect initiated", self->cmts_addr, self->cmts_port);
        errno = 0;

        int fd = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));

        sin.sin_family = AF_INET;
        sin.sin_port = htons(self->cmts_port);

        if (inet_pton(AF_INET, self->cmts_addr, &sin.sin_addr) != 1)
                return sock_close(fd);

        if (sock_setsockopts(fd) < 0)
                return sock_close(fd);

        int stat = connect(fd, (struct sockaddr*)&sin, sizeof(sin));
        self->sock = fd;

        debug("connect in progress %i (%s)", stat, strerror(errno));
        if (stat == 0)
                return (self->connection = 1);

        if (errno != EINPROGRESS)
                warning("unknown connect state: %i (%s)", stat, strerror(errno));
        if (stat == ENOENT)
                warning("ignoring ENOENT");

        /*
         * Define a set of file descriptors which ONLY contains the working socket.
         * Clear the FD set, then using FD_SET, include the working file descriptor.
         */
        struct timeval timeout = sock_get_timeoutv();

        int retry = 0;
        do {
                fd_set set;
                FD_ZERO(&set);
                FD_SET(fd, &set);

                /*
                 * select() allows a program to monitor multiple file descriptors, waiting until
                 * one or more of the file descriptors becomes "ready" for some class of I/O op.
                 */
                stat = select(fd + 1, NULL, &set, NULL, &timeout);
                if (stat > 0)
                        break;

                if (stat == 0) {
                        error("system call interrupted (timeout)");
                        return sock_close(fd);
                }

                if (stat < 0 && errno != EINTR) {
                        error("connection to '%s' failed", self->cmts_addr);
                        return sock_close(fd);
                }

                error("unknown error polling socket %i/%i (%s)", errno, stat, strerror(errno));
                retry++;

                if (retry > SOL_SELECT_RETRIES)
                        return sock_close(fd);

        } while (1);

        return (self->connection = 1);
}

int
sock_close(int fd) {
        debug("%s called on fd=%i", __func__, fd);

        struct stat statbuf;
        fstat(fd, &statbuf);

        if (!S_ISSOCK(statbuf.st_mode)) {
                warning(ENOSOCK);
                return 0;
        }

        if (fd < 0)
                return 0;

        sock_SO_ERROR(fd);

        if (shutdown(fd, SHUT_RDWR) < 0) {
                if (errno != ENOTCONN && errno != EINVAL) {
                        error("shutdown error %s", strerror(errno));

                        if (MATCHES(strerror(errno), ENOSOCK)) {
                                warning(ENOSOCK);

                                return 0;
                        }
                }
        }
        if (close(fd) < 0)
                error("close error %s", strerror(errno));

        return 0;
}

static int
ps_polld(ps_session_t* self, int target) {
        debug("polling for opcode=%i (%s)", target, cops_otoa(target));

        time_t cur = time(NULL);
        time_t end = cur + 10;

        while (cur < end) {
                if (ps_recvd(self) == target)
                        return 1;

                cur = time(NULL);
        }

        warning("failed to receive opcode=%i", target);
        return 0;
}

static int
ps_find_u16(uint8_t* stream, size_t array_length, uint16_t target) {
        if (array_length == 0)
                return -1;

        for (size_t i = 0; i < array_length - 1; i++) {
                uint16_t value = (uint16_t)((unsigned char)stream[i] << 8 | (unsigned char)stream[i + 1]);
                if (value == target) {
                        return i;
                }
        }
        return -1;
}

static void
ps_pcmm_report_decision(pcmm_rpt_t rpt, int classifier_type) {
        char buf[512];

        FILE* fp = NULL;

        if (rpt.transaction_id == 0 && rpt.gate_id != 0) {
                snprintf(buf, sizeof(buf), ORPHAN_ENTRY_FILE);

                if ((fp = fopen(buf, "a")) == NULL) {
                        error("orph: fopen failed");

                        if (fp != NULL) {
                                fflush(fp);
                                fclose(fp);
                        }
                        return;
                }

                if (fprintf(fp, orpfmt, rpt.gate_id, rpt.gate_cmd) < 0)
                        error("orph: fprintf failed");

                fflush(fp);
                fclose(fp);
                fp = NULL;

                warning("wrote to orphan gate_id '%u'", rpt.gate_id);
                return;
        }

        snprintf(buf, sizeof(buf), "data/yrpt_%i.txt", rpt.transaction_id);

        if ((fp = fopen(buf, "w")) == NULL) {
                error("failed to open %s: %s", buf, strerror(errno));

                return;
        }

        if (write_report(fp, rpt, classifier_type) < 0)
                error("issue when writing to report file - %s", strerror(errno));

        if (fclose(fp) != 0)
                error("failed to close file: %s", strerror(errno));

        fp = NULL;
}

static void
ps_pcmm_report(char* buf, size_t* ptr, uint16_t rpt_length) {
        unsigned char* report = (unsigned char*)buf + *ptr;
        size_t rpt_idx = 0;
        size_t end_idx = (size_t)(rpt_length - 4);

        if (end_idx == 0) {
                warning("invalid end index");
                return;
        }

        pcmm_rpt_t rpt = {.packetcable_err_descr = "NIL",
                          .packetcable_err_subcode = 0,
                          .packetcable_err_code = 0,
                          .application_tag = 0,
                          .application_id = 0,
                          .transaction_id = 0,
                          .gate_cmd = "NIL",
                          .gate_id = 0};

        int classifier_type = -1; /* Indicate classifier type. */
        int report_required = 0;  /* Indicate miscellaneous type. */

        while (rpt_idx < end_idx) {
                __attribute__((unused())) uint16_t len = unpack_u16_it(report, &rpt_idx);
                uint8_t major = unpack_u8_it(report, &rpt_idx);
                uint8_t minor = unpack_u8_it(report, &rpt_idx);

                if (major == 0 || major > 19 || minor == 0 || minor > 2)
                        continue;

                char* block = (char*)report + rpt_idx;
                rpt_idx += len - 4;

                if (pcmm_is_gateid(major, minor)) {
                        rpt.gate_id = atog(block);
                        continue;
                }

                if (pcmm_is_gatespec(major, minor)) {
                        pcmm_decode_gate(&rpt, block);
                        continue;
                }

                if (pcmm_is_classifier(major)) {
                        switch (minor) {
                                case 1:  classifier_type = pcmm_decode_classifier(&rpt, block); continue;
                                case 2:  classifier_type = pcmm_decode_extended(&rpt, block); continue;
                                default: warning("unkown gate/classifier type"); continue;
                        }
                }

                const uint16_t code = unpack_u16(block);
                const uint16_t subc = unpack_u16(block + 2);

                switch (major) {
                        case 1:  pcmm_decode_transaction(&rpt, code, subc); continue;
                        case 2:  pcmm_decode_application(&rpt, code, subc); continue;
                        case 14: pcmm_decode_error(&rpt, code, subc); continue;
                        case 15:
                                /*
                                 * On any gate state report message we can set the flag to false
                                 * to indicate an ephemeral file doesn't need to be created.
                                 */
                                report_required = pcmm_gatestate_rpt(code, subc);
                                continue;

                        default: continue;
                }

                if (rpt_idx >= end_idx)
                        break;
        }
        *ptr += (rpt_length - 4);

        if (report_required)
                warning("skipping gate_state report write");
        else
                ps_pcmm_report_decision(rpt, classifier_type);
}

static int
ps_recvd(ps_session_t* self) {
        errno = 0;

        char buf[BUFFER_SIZE];
        memset(buf, 0, sizeof(buf));

        ssize_t bytes = recv(self->sock, buf, BUFFER_SIZE, MSG_PEEK);
        if (bytes <= 0)
                return 0;

        if (bytes >= SSIZE_MAX)
                warning(WARN_OVERFLOW, bytes);

        uint8_t* ptr = (uint8_t*)buf;
        size_t idx = 1;

        uint8_t ver = (*ptr) >> 4;
        uint8_t sol = (*ptr & 0xF0) >> 4;
        uint8_t opc = unpack_u8_it(ptr, &idx);

        uint16_t client = unpack_u16_it(ptr, &idx);
        uint32_t length = unpack_u32_it(ptr, &idx);

        if (sol != 1 && opc == 3)
                warning(WARN_UNSOL_RPT);

        if (!cops_header_ok(opc, client, length)) {
                warning(WARN_EHDR, opc, client, length);
                size_t ub = (size_t)bytes;
                bool commit = true;

                for (size_t i = 0; i < ub; i++) {
                        size_t it = i;

                        if ((i + 2) >= ub || (i + 4) >= ub)
                                break;

                        if ((client = unpack_u16_it(ptr, &it)) != PCMM_CLIENT_TYPE)
                                continue;

                        if ((length = unpack_u32_it(ptr, &it)) > 1000)
                                warning(WARN_OVERFLOW, length);

                        if (i >= 2)
                                recv(self->sock, buf, i - 2, MSG_WAITALL);
                        else
                                opc = 3;

                        commit = false;
                        break;
                }

                if (commit) {
                        debug_raw(buf, bytes, "invalid_buffer");
                        recv(self->sock, buf, bytes, MSG_WAITALL);
                        return 0;
                }
        }

        memset(buf, 0, sizeof(buf));

        if (bytes >= BUFFER_SIZE || length >= BUFFER_SIZE)
                warning(WARN_OVERFLOW, length);

        if (bytes != length)
                bytes = recv(self->sock, buf, length, MSG_WAITALL);
        else
                bytes = recv(self->sock, buf, bytes, MSG_WAITALL);

        if (bytes < 0)
                return 0;

        if (bytes < length) {
                size_t due = length - bytes;
                memset(buf, 0, bytes);

                while (recv(self->sock, buf, due, MSG_WAITALL) != (ssize_t)due);
                bytes += due;
        }

        debug("(%u) %lu/%lu/%lu", opc, bytes, length, client);

        while (idx < (size_t)bytes) {
                uint16_t len = unpack_u16_it(ptr, &idx);
                uint8_t cnv = unpack_u8_it(ptr, &idx);
                uint8_t ctv = unpack_u8_it(ptr, &idx);

                if (cops_class_ok(cnv, ctv) == 0)
                        continue;

                if (cnv == 9 && opc == 3) {
                        /*
                         * Handling client-specific info within a report state message. Iterate
                         * through the remainder of the report, then determine if an ephemeral
                         * response file needs to be generated for a waiting API thread.
                         */
                        ps_pcmm_report(buf, &idx, len);

                } else if (cnv == 1 && !self->uuid_received) {
                        /*
                         * Handle/Handle message received and no previous opaque handle has been
                         * stored. Copy the unique value into the object's handle character array.
                         */
                        char* ptrptr = (char*)(ptr + idx);

                        for (int i = 0; i < 4; i++) self->handle[i] = *(ptrptr + i);
                        idx += 4;

                        self->uuid_received = true; /* Toggle handle received flag. */

                } else if (cnv == 8) {
                        /*
                         * PacketCable error object received, dump the buffer into the error log
                         * and stdout if enabled, log the primary/sub codes and return.
                         */
                        debug_raw(buf, bytes, "PCE Buffer");
                        fatal("PacketCable Error %i %i.%i %u/%u/%u", bytes, cnv, ctv, opc, ver, length);
                }
        }
        return opc;
}

static void*
ps_statemachine(void* obj) {
        ps_session_t* self = obj;

        int thread_log_level = conf_get_log_level();
        if (thread_log_level < 0 || thread_log_level > 5) {
                warning("invalid log level, defaulting to INFO");

                thread_log_level = 0;
        }

        pthread_logspecific(thread_log_level, self->cmts_addr);

        for (;;) {
                if (self->die)
                        return NULL;

                int opcode = ps_recvd(self);

                if (OPCODE_KA(opcode)) {
                        sock_keepalive(self);

                } else if (OPCODE_OPN(opcode)) {
                        info("Client-Open received out of sequence");

                } else if (OPCODE_REQ(opcode)) {
                        info("REQ received out of sequence.");

                } else if (OPCODE_CC(opcode) || opcode == -1) {
                        /*
                         * The Client-Close message can be issued by either the PDP or PEP to
                         * notify the other that a particular type of client is no longer being
                         * supported. The error object is included to describe the reason for the
                         * close.
                         */
                        error("Client-Close/Error received, closing socket and reconnecting.");
                        close(self->sock);

                        self->connection = 0;
                        self->uuid_received = false;

                        while (!ps_admctl(self)) sleep(2);

                        info("successfully reconnected to %s", self->cmts_addr);
                        continue;
                }
        }
}

ps_session_t*
ps_new(char* cmts_ip) {
        errno = 0;

        if (!is_ip4(cmts_ip)) {
                fatal("invalid ip address (%s)", cmts_ip);
                return NULL;
        }

        ps_session_t* self = ALLOC_T(policy_server_session_type);

        unsigned long iplen = strlen(cmts_ip) + 1;

        self->cmts_addr = NULL;
        self->cmts_addr = (char*)malloc(iplen);
        self->cmts_port = conf_get_cmts_tcp_port();

        memset(self->cmts_addr, 0, iplen);
        memcpy(self->cmts_addr, cmts_ip, iplen);
        memset(self->handle, 0, sizeof(self->handle));

        self->ka_timer = conf_get_KAtimer(); /* Keep-Alive timer. */
        self->ac_timer = conf_get_ACtimer(); /* Accounting timer. */
        self->uuid_received = 0;             /* Handle object received. */
        self->connection = 0;                /* Indicate established. */
        self->sock = -1;                     /* Socket file descriptor. */
        self->die = 0;                       /* Indicate whether to exit loop. */

        /* Initialize object specific mutex locks. */
        if (pthread_mutex_init(&self->read_lock, NULL) != 0 || pthread_mutex_init(&self->evnt_lock, NULL) != 0) {
                fatal("failed to init locks (%s)", strerror(errno));

                ps_free(self);
                return NULL;
        }
        return self;
}

void
ps_free(ps_session_t* self) {
        if (self->cmts_addr) {
                /* Free memory allocated in init function for CMTS ip address. */
                kfree(self->cmts_addr);
        }

        /* Close socket - this may already be closed but it'll just spit out a warning log. */
        sock_close(self->sock);

        if (!self)
                return;

        /* Free this object. */
        kfree(self);
}

uint16_t
ps_proxy(ps_session_t* self, int op, gctl_t gc, const uint8_t* request, size_t len) {
        const uint16_t txn_id = rand();

        /* Determine the IP type and size. */
        int ip6 = is_ip6(gc.subscriber_id);
        int addr_len = (ip6) ? 20 : 8;

        uint8_t ctl_ctx[8];
        uint8_t ctl_dec[8];
        uint8_t ctl_hnd[8];
        uint8_t ctl_sub[addr_len];

        memset(ctl_ctx, 0, 8);
        memset(ctl_dec, 0, 8);
        memset(ctl_hnd, 0, 8);
        memset(ctl_sub, 0, addr_len);

        /*
         * Build the decision, context, handle and subscriber objects. When not in dry run mode,
         * include the handle in the request. Then build the subscriber ID object (IPv4 or IPv6).
         */
        cops_decision(ctl_dec);
        cops_context(ctl_ctx);

        if (gc.dry_run != 1)
                cops_handle(ctl_hnd, self->handle);

        if (ip6)
                pcmm_subscriber6_identifier(ctl_sub, gc.subscriber_id, addr_len);
        else
                pcmm_subscriber4_identifier(ctl_sub, ip4_toi(gc.subscriber_id));

        uint8_t ctl_gid[8]; /* gate id */
        uint8_t ctl_cop[8]; /* command op */
        uint8_t ctl_aid[8]; /* application id */

        memset(ctl_gid, 0, 8);
        memset(ctl_cop, 0, 8);
        memset(ctl_aid, 0, 8);

        /*
         * Build the applciation ID, transaction and gate ID objects. If the operation command is a
         * SET, allocate 8 bits for the gate ID if it's not zero, then allocate 16 bits plus the
         * length of the QoS + PCMM gate request data compiled in the API
         */
        pcmm_application_identifier(ctl_aid, 0, 3474);
        pcmm_transaction_identifier(ctl_cop, txn_id, (uint16_t)op);
        pcmm_gate_identifier(ctl_gid, gc.gate_id);

        size_t mod = 0;

        if (op == GATE_SET) {
                if (gc.gate_id != 0) {
                        mod += 8;
                }
                mod += (16 + len);
        } else {
                mod += 24;
        }

        size_t ctl_size = addr_len + mod; /* Gate control messages. */
        size_t dec_size = ctl_size + 4;   /* Decision size. */
        size_t msg_size = dec_size + 32;  /* Decision + header size. */

        /*
         * Pack the gate control messages by combining the command, application ID and subscriber ID
         * objects. Then if the operation is a gate-set op. and the gate ID exists, pack the control
         * data with the gate ID, and the request data from the API. Otherwise pack the null gate ID.
         */
        uint8_t decision[msg_size];
        uint8_t message[msg_size];

        memset(decision, 0, msg_size);
        memset(message, 0, msg_size);

        size_t ptr = pack_ctl_objs(decision, ctl_hnd, ctl_ctx, ctl_dec, ctl_cop, ctl_aid, ctl_sub, dec_size, addr_len);

        if (op == GATE_SET) {
                if (gc.gate_id != 0) {
                        concat_c8(decision, &ptr, ctl_gid, 8);
                }
                concat(decision, &ptr, request, len);
        } else {
                concat(decision, &ptr, ctl_gid, 8);
        }

        new_cops_message(message, 2, decision, msg_size);

        if (!gc.dry_run)
                sock_write(self, message, msg_size);

#if defined(UNIT_TEST)
        stash_u8_data(message, "data/IGNORE_tp_flow.txt", msg_size);
        debug_message(message, self->handle);
#endif
        return txn_id;
}

int
ps_admctl(ps_session_t* self) {
        errno = 0;

        if (sock_connect(self) == 0) {
                warning("socket connection failed: %s", strerror(errno));

                return 0;
        }
        ps_polld(self, 6);

        size_t len = (self->ac_timer) ? 24 : 16;
        uint8_t msg[len];

        cops_client_accept(msg, self->ka_timer, self->ac_timer);

        debug("sending client-accept (ka=%i)", self->ka_timer);
        sock_write(self, msg, len);

        return ps_polld(self, 1);
}

pthread_t
ps_boot(ps_session_t* self) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, ps_statemachine, self) != 0) {
                error("pthread_create() failed");

                error("%s", strerror(errno));
                return 0;
        }
        return tid;
}
