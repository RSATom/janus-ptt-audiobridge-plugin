/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "rtp_forwarder.h"

#include <glib.h>
#include <inttypes.h>

extern "C" {
#include "janus/utils.h"
}

#include "ptt_room.h"


namespace ptt_audiobridge
{

guint32 rtp_forwarder_add_helper(ptt_room *room,
		const gchar *host, uint16_t port, uint32_t ssrc, int pt,
		int srtp_suite, const char *srtp_crypto,
		gboolean always_on, guint32 stream_id) {
	if(room == NULL || host == NULL)
		return 0;
	rtp_forwarder *rf = (rtp_forwarder *)g_malloc0(sizeof(rtp_forwarder));
	/* First of all, let's check if we need to setup an SRTP forwarder */
	if(srtp_suite > 0 && srtp_crypto != NULL) {
		/* Base64 decode the crypto string and set it as the SRTP context */
		gsize len = 0;
		guchar *decoded = g_base64_decode(srtp_crypto, &len);
		if(len < SRTP_MASTER_LENGTH) {
			JANUS_LOG(LOG_ERR, "Invalid SRTP crypto (%s)\n", srtp_crypto);
			g_free(decoded);
			g_free(rf);
			return 0;
		}
		/* Set SRTP policy */
		srtp_policy_t *policy = &rf->srtp_policy;
		srtp_crypto_policy_set_rtp_default(&(policy->rtp));
		if(srtp_suite == 32) {
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy->rtp));
		} else if(srtp_suite == 80) {
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtp));
		}
		policy->ssrc.type = ssrc_any_outbound;
		policy->key = decoded;
		policy->next = NULL;
		/* Create SRTP context */
		srtp_err_status_t res = srtp_create(&rf->srtp_ctx, policy);
		if(res != srtp_err_status_ok) {
			/* Something went wrong... */
			JANUS_LOG(LOG_ERR, "Error creating forwarder SRTP session: %d (%s)\n", res, janus_srtp_error_str(res));
			g_free(decoded);
			policy->key = NULL;
			g_free(rf);
			return 0;
		}
		rf->is_srtp = TRUE;
	}
	/* Check if the host address is IPv4 or IPv6 */
	if(strstr(host, ":") != NULL) {
		rf->serv_addr6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, host, &(rf->serv_addr6.sin6_addr));
		rf->serv_addr6.sin6_port = htons(port);
	} else {
		rf->serv_addr.sin_family = AF_INET;
		inet_pton(AF_INET, host, &(rf->serv_addr.sin_addr));
		rf->serv_addr.sin_port = htons(port);
	}
	/* Setup RTP info (we'll use the stream ID as SSRC) */
	rf->ssrc = ssrc;
	rf->payload_type = pt;
	rf->seq_number = 0;
	rf->timestamp = 0;
	rf->always_on = always_on;

	janus_mutex_lock(&room->rtp_mutex);

	guint32 actual_stream_id;
	if(stream_id > 0) {
		actual_stream_id = stream_id;
	} else {
		actual_stream_id = janus_random_uint32();
	}

	while(g_hash_table_lookup(room->rtp_forwarders, GUINT_TO_POINTER(actual_stream_id)) != NULL) {
		actual_stream_id = janus_random_uint32();
	}
	janus_refcount_init(&rf->ref, rtp_forwarder_free);
	g_hash_table_insert(room->rtp_forwarders, GUINT_TO_POINTER(actual_stream_id), rf);

	janus_mutex_unlock(&room->rtp_mutex);

	JANUS_LOG(LOG_VERB, "Added RTP forwarder to room %s: %s:%d (ID: %" SCNu32 ")\n",
		room->room_id_str, host, port, actual_stream_id);

	return actual_stream_id;
}


void rtp_forwarder_destroy(rtp_forwarder *rf) {
	if(rf && g_atomic_int_compare_and_exchange(&rf->destroyed, 0, 1)) {
		janus_refcount_decrease(&rf->ref);
	}
}

void rtp_forwarder_free(const janus_refcount *f_ref) {
	rtp_forwarder *rf = janus_refcount_containerof(f_ref, rtp_forwarder, ref);
	if(rf->is_srtp) {
		srtp_dealloc(rf->srtp_ctx);
		g_free(rf->srtp_policy.key);
	}
	g_free(rf);
}

}
