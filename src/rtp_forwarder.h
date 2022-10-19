#pragma once

#include <glib.h>

#include <arpa/inet.h>

extern "C" {
#include "janus/refcount.h"
#include "janus/rtpsrtp.h"
}

namespace ptt_audioroom
{

struct ptt_room;

/* RTP forwarder instance: address to send to, and current RTP header info */
struct rtp_forwarder {
	struct sockaddr_in serv_addr;
	struct sockaddr_in6 serv_addr6;
	uint32_t ssrc;
	int payload_type;
	uint16_t seq_number;
	uint32_t timestamp;
	gboolean always_on;
	/* Only needed for SRTP forwarders */
	gboolean is_srtp;
	srtp_t srtp_ctx;
	srtp_policy_t srtp_policy;
	/* Reference */
	gint destroyed;
	janus_refcount ref;
};

void rtp_forwarder_destroy(rtp_forwarder *rf);
void rtp_forwarder_free(const janus_refcount *f_ref);

}
