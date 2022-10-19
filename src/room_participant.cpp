#include "room_participant.h"

extern "C" {
#include "janus/utils.h"
}

#include "ptt_room.h"
#include "rtp_relay_packet.h"


namespace ptt_audioroom
{

void recorder_create(room_participant *participant) {
	if(participant == NULL || participant->room == NULL)
		return;
	ptt_room *audiobridge = participant->room;
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

void recorder_close(room_participant *participant) {
	if(participant->arc) {
		audio_recorder *rc = participant->arc;
		participant->arc = NULL;
		audio_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed user's audio recording %s\n", rc->filename ? rc->filename : "??");
		audio_recorder_destroy(rc);
	}
}

void participant_destroy(room_participant *participant) {
	if(!participant)
		return;
	if(!g_atomic_int_compare_and_exchange(&participant->destroyed, 0, 1))
		return;
	/* Decrease the counter */
	janus_refcount_decrease(&participant->ref);
}

void participant_unref(room_participant *participant) {
	if(!participant)
		return;
	/* Just decrease the counter */
	janus_refcount_decrease(&participant->ref);
}

void participant_free(const janus_refcount *participant_ref) {
	static_assert(std::is_standard_layout<room_participant>::value);
	room_participant *participant = (room_participant*)participant_ref;
	/* This participant can be destroyed, free all the resources */
	g_free(participant->user_id_str);
	g_free(participant->display);
	while(participant->inbuf) {
		GList *first = g_list_first(participant->inbuf);
		rtp_relay_packet *pkt = (rtp_relay_packet *)first->data;
		participant->inbuf = g_list_delete_link(participant->inbuf, first);
		if(pkt)
			g_free(pkt->data);
		g_free(pkt);
	}
	delete participant;
}

}
