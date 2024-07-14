#ifndef LCM_H
#define LCM_H

#include "ps.h"

#define MAXROOM 20

/* Hard limit to `max_cmts_connections` */
static const int LCM_ERR = -1;
static const int LCM_OK = 1;

typedef struct {
        size_t count;  /* Count of the current number of connections/threads available. */
        size_t maxpep; /* Maximum number of connections/threads the LCM will store before
                      rejecting net new connect requests. This is a soft cap while the
                      MAXROOM value is considered the hard cap.*/

        ps_session_t* clients[MAXROOM]; /* Array of pointers to different PDP loop objects. */
        pthread_t threads[];            /* NOT IMPLEMENTED. */
} lcm_t;

lcm_t* lcm_init(int maxpep);

/*
 * Add a pthread_t "id" opaque object to the Local Connection Manager's list.
 * So it can be killed later on in the event of an API request to /clear.
 *
 * @self Local connection manager object
 * @conn Policy server 'session' client that will be added to the list
 */
int lcm_set(lcm_t* self, ps_session_t* conn);

/*
 * Lookup and return the correct Policy server client from the LCM's `clients` list
 * by searching each for the given CMTS IP, since the IP should be specific
 * to the Policy server client.
 *
 * @self        Local connection manager object
 * @cmts_ip     CMTS IP address search target
 */
ps_session_t* lcm_getps(lcm_t* self, const char* cmts_ip);

/*
 * Determine whether the Local Connection Manager can store another Policy server client
 *
 * @self        Local connection manager object
 *
 * Returns 1 if no space is available, 0 if the LCM has not exceeded the
 * maximum number of stored clients (see `MAX_YLMIT`)
 */
int lcm_alloc_ok(lcm_t* self);

#endif /* ifndef LCM_H */
