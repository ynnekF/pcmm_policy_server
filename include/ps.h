#ifndef CCLIENT_H
#define CCLIENT_H

#include <arpa/inet.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "cops.h"
#include "fields.h"
#include "iputil.h"
#include "log.h"
#include "pcmm.h"

#if defined(__APPLE__)
#define orpfmt "cops-gate-id: %u, GateCmd: %s\n"
#elif defined(__linux__)
#define orpfmt "cops-gate-id: %u, GateCmd: %s\n"
#else
#define orpfmt
#endif

#define kfree(v) \
        free(v); \
        v = NULL;

#define ENOSOCK            "Socket operation on non-socket"
#define MATCHES(x, v)      strcmp(x, v) == 0
#define ALLOC_T(type)      (type*)malloc(sizeof(type))
#define ALLOC_M(type, mod) (type*)malloc(sizeof(type) * mod)

#define BUFFER_SIZE        65535 /* Read-in buffer size used by recv(), need to review. */
#define OPCODE_REQ(v)      (v == 1)
#define OPCODE_DEC(v)      (v == 2)
#define OPCODE_RPT(v)      (v == 3)
#define OPCODE_DRQ(v)      (v == 4)
#define OPCODE_SSQ(v)      (v == 5)
#define OPCODE_OPN(v)      (v == 6)
#define OPCODE_CAT(v)      (v == 7)
#define OPCODE_CC(v)       (v == 8)
#define OPCODE_KA(v)       (v == 9)
#define OPCODE_SSC(v)      (v == 10)

typedef float f32;
typedef double f64;
typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef size_t usize;
typedef unsigned char uch;

/*
 * ClientSI, the client specific information object, holds the client-type specific data for which
 * a policy decision needs to be made. In the case of configuration, the Named ClientSI may include
 * named information about the module, interface, or functionality to configured. The ordering of
 * multiple ClientSIs is not important.
 */
typedef struct {
        char* data;   /* ClientSI data store */
        uint16_t len; /* ClientSI data length */
} client_si;

typedef struct {
        char* cmts_addr; /* Stores the string version of the CMTS IP */
        int connection;  /* Specifies whether a connection is established */
        int cmts_port;   /* Stores the CMTS port value */
        int ka_timer;    /* Keep-Alive interval timer value */
        int ac_timer;    /* Accounting timer */
        int sock;        /* Socket file-descriptor */

        pthread_mutex_t evnt_lock; /* Lock `die`. */
        pthread_mutex_t read_lock; /* Lock `report`. */

        client_si report;
        char handle[8];

        bool uuid_received; /* Signal handle received. */
        bool die;           /* Signal exit. */
} policy_server_session_type;

typedef policy_server_session_type ps_session_t;

/*
 * Attempt to close an open socket. This verifies the given file descriptor via S_ISSOCK (returns 0
 * if the file is a socket and MT/AS/AC safe operation), then clears the socket errno and attempts
 * to close the socket.
 *
 * @fd  Active or inactive socket file descriptor
 */
int sock_close(int fd);

/*
 * Initialize a new client shell which stores the given CMTS IP, sets the default IANA TCP port the
 * CMTS listens on and initializes the rest of the fields. Note: The CMTS IP must be stored by the
 * client in memory so we can free the yyjson_doc the request orignally read and alloc'd.
 *
 * @cmts_ip Valid IPv4 address (Does not support IPv6)
 */
ps_session_t* ps_new(char* cmts_ip);

/*
 * Create a new thread running the fsm, then return the thread ID for the API to store. A log is
 * created on any failure and zero is returned.
 *
 * @self An initialized, non-connected shell object.
 */
pthread_t ps_boot(ps_session_t* self);

/*
 * Free all memory associated with the object. This includes the CMTS IP memory, and itself, which
 * is allocated during the init function.
 *
 * @self An active object connected to a CMTS
 */
void ps_free(ps_session_t* self);

/*
 * (OPN) Client-Open Operation PEP --> PDP + (CAT) Client-Accept Operation PDP --> PEP
 *
 * The Client-Open Message can be sent by the PEP to the PDP at any time, indicating that is is
 * ready to accept a COPS connection. A ClientSI object may be included to provide PEP-specific info
 * to the PDP. (RFC 2748, section 3.6)
 *
 * The Client-Accept message is used to positively respond to the Client-Open message, returning to
 * the PEP, an object with a timer indicating the maximum time interval between keep-alive messages.
 * (RFC 2748, section 3.7). The COPS client (PEP) sends an OPN message to initiate a connection with
 * the COPS server (PDP), and the server responds with a Client-Accept (CAT) msg to accept the
 * connection.
 *
 * The opn() function will wait for the OPN message from the PEP (CMTS). After receiving an OPN,
 * we'll response with a client-accept message. Finally it will wait for the REQ.
 *
 */
int ps_admctl(ps_session_t*);

/*
 * Request (REQ) Operation
 *
 * +---------+-------------+------------+------------------+
 * | Version | Opcode      | ClientType | Length           |
 * +---------+-------------+------------+------------------+
 * | Handle  | Context     | Decision   | Decision Headers |
 * +---------+-------------+------------+------------------+
 * | Command | Application | Subscriber | Gate ID          |
 * +---------+-------------+------------+------------------+
 *
 * The client sends a REQ message to the server to request admission control decision information or
 * device configuration information. The REQ message may contain client- specific information that
 * the server uses, together with the data in the session admission policy database, to make
 * policy-based decisions.
 *
 */
uint16_t ps_proxy(ps_session_t* self, int op, gctl_t fields, const uint8_t* request, size_t len);

/*
 * Stash data under a IGNORE_tp_* file for C unit test validations
 *
 * @buffer      The data to be written to the given file
 * @filename    Name of the file where the data should be stored (should follow IGNORE_tp_*)
 * @len         The number of bytes to be written to the file
 */
void stash_data(char* buffer, const char* filename, size_t len);

/*
 * Stash data under a IGNORE_tp_* file for C unit test validations
 *
 * @buffer      The data to be written to the given file
 * @filename    Name of the file where the data should be stored (should follow IGNORE_tp_*)
 * @len         The number of bytes to be written to the file
 */
void stash_u8_data(uint8_t* buffer, const char* filename, size_t len);

#endif
