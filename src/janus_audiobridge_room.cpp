#include "janus_audiobridge_room.h"


namespace ptt_audioroom
{

void janus_audiobridge_room_destroy(janus_audiobridge_room *audiobridge) {
	if(!audiobridge)
		return;
	if(!g_atomic_int_compare_and_exchange(&audiobridge->destroyed, 0, 1))
		return;
	/* Decrease the counter */
	janus_refcount_decrease(&audiobridge->ref);
}

void janus_audiobridge_room_free(const janus_refcount *audiobridge_ref) {
	janus_audiobridge_room *audiobridge = janus_refcount_containerof(audiobridge_ref, janus_audiobridge_room, ref);
	/* This room can be destroyed, free all the resources */
	g_free(audiobridge->room_id_str);
	g_free(audiobridge->room_name);
	g_free(audiobridge->room_secret);
	g_free(audiobridge->room_pin);
	g_hash_table_destroy(audiobridge->participants);
	g_hash_table_destroy(audiobridge->allowed);
	if(audiobridge->rtp_udp_sock > 0)
		close(audiobridge->rtp_udp_sock);
	if(audiobridge->rtp_encoder)
		opus_encoder_destroy(audiobridge->rtp_encoder);
	g_hash_table_destroy(audiobridge->rtp_forwarders);
	delete audiobridge;
}

}
