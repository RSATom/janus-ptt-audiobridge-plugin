#include "janus_audiobridge_participant.h"

extern "C" {
#include "janus/utils.h"
}

#include "janus_audiobridge_room.h"
#include "janus_audiobridge_rtp_relay_packet.h"


namespace ptt_audioroom
{

void janus_audiobridge_recorder_create(janus_audiobridge_participant *participant) {
	if(participant == NULL || participant->room == NULL)
		return;
	janus_audiobridge_room *audiobridge = participant->room;
	char filename[255];
	audio_recorder *rc = NULL;
	gint64 now = janus_get_real_time();
	if(participant->arc == NULL) {
		memset(filename, 0, 255);
		/* Build a filename */
		g_snprintf(filename, 255, "audiobridge-%s-user-%s-%" SCNi64 "-audio",
			audiobridge->room_id_str, participant->user_id_str, now);
		rc = audio_recorder_create(audiobridge->mjrs_dir,
			janus_audiocodec_name(JANUS_AUDIOCODEC_OPUS), filename);
		if(rc == NULL) {
			JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this participant!\n");
		}
		if(participant->extmap_id > 0)
			audio_recorder_add_extmap(rc, participant->extmap_id, JANUS_RTP_EXTMAP_AUDIO_LEVEL);
		participant->arc = rc;
	}
}

void janus_audiobridge_recorder_close(janus_audiobridge_participant *participant) {
	if(participant->arc) {
		audio_recorder *rc = participant->arc;
		participant->arc = NULL;
		audio_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed user's audio recording %s\n", rc->filename ? rc->filename : "??");
		audio_recorder_destroy(rc);
	}
}

void janus_audiobridge_participant_destroy(janus_audiobridge_participant *participant) {
	if(!participant)
		return;
	if(!g_atomic_int_compare_and_exchange(&participant->destroyed, 0, 1))
		return;
	/* Decrease the counter */
	janus_refcount_decrease(&participant->ref);
}

void janus_audiobridge_participant_unref(janus_audiobridge_participant *participant) {
	if(!participant)
		return;
	/* Just decrease the counter */
	janus_refcount_decrease(&participant->ref);
}

void janus_audiobridge_participant_free(const janus_refcount *participant_ref) {
	static_assert(std::is_standard_layout<janus_audiobridge_participant>::value);
	janus_audiobridge_participant *participant = (janus_audiobridge_participant*)participant_ref;
	/* This participant can be destroyed, free all the resources */
	g_free(participant->user_id_str);
	g_free(participant->display);
	if(participant->encoder)
		opus_encoder_destroy(participant->encoder);
	if(participant->decoder)
		opus_decoder_destroy(participant->decoder);
	while(participant->inbuf) {
		GList *first = g_list_first(participant->inbuf);
		janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)first->data;
		participant->inbuf = g_list_delete_link(participant->inbuf, first);
		if(pkt)
			g_free(pkt->data);
		g_free(pkt);
	}
	if(participant->outbuf != NULL) {
		while(g_async_queue_length(participant->outbuf) > 0) {
			janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)g_async_queue_pop(participant->outbuf);
			g_free(pkt->data);
			g_free(pkt);
		}
		g_async_queue_unref(participant->outbuf);
	}
	delete participant;
}

}
