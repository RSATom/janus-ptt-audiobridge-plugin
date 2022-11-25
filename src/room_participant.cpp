/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "room_participant.h"

#include <type_traits>

extern "C" {
#include "janus/apierror.h"
#include "janus/utils.h"
}

#include "ptt_audiobridge_plugin.h"
#include "ptt_room.h"
#include "rtp_relay_packet.h"
#include "glib_ptr.h"


namespace ptt_audiobridge
{

static void participant_free(const janus_refcount *participant_ref);

room_participant* room_participant::create()
{
	room_participant* participant = new room_participant {};
	janus_refcount_init(participant, participant_free);
	return participant;
}

// ptt_room::mutex should be locked
std::string generate_recording_id(room_participant* participant) {
	const ptt_room* room = participant->room;
	const gint64 now = janus_get_real_time();

	gchar_ptr escaped_room_id_ptr(g_uri_escape_string(room->room_id_str, nullptr, false));
	gchar_ptr escaped_participant_id_ptr(g_uri_escape_string(participant->user_id_str, nullptr, false));
	gchar_ptr uuid_ptr(janus_random_uuid());

	std::string recording_id;
	recording_id += std::string(room->room_id_str) + G_DIR_SEPARATOR_S;
	recording_id += std::string(participant->user_id_str) + G_DIR_SEPARATOR_S;
	recording_id += std::to_string(now) + "-" +uuid_ptr.get() + "-audio";

	return recording_id;
}

// ptt_room::mutex should be locked
void mute_participant(
	plugin_session *session,
	room_participant *participant,
	gboolean mute,
	gboolean self_notify,
	gboolean lock_qmutex)
{
	if(participant->muted == mute)
		return;

	ptt_room *audiobridge = participant->room;

	JANUS_LOG(LOG_INFO, "Setting muted property: %s (room %s, user %s)\n",
		mute ? "true" : "false", participant->room->room_id_str, participant->user_id_str);
	participant->muted = mute;
	if(participant->muted) {
		audiobridge->unmuted_participant = nullptr;

		participant->recording_id.clear();

		/* Clear the queued packets waiting to be handled */
		clear_inbuf(participant, lock_qmutex);
	} else {
		participant->recording_id = generate_recording_id(participant);

		gint64 now = janus_get_monotonic_time();
		audiobridge->unmuted_participant = participant;
		participant->unmuted_timestamp = now;
	}

	/* Notify all other participants about the mute/unmute */
	json_t *participantInfo = json_object();
	json_object_set_new(participantInfo, "id", json_string(participant->user_id_str));
	if(participant->display)
		json_object_set_new(participantInfo, "display", json_string(participant->display));

	json_t *pub = json_object();
	json_object_set_new(pub, "audiobridge", participant->muted ? json_string("muted") : json_string("unmuted"));
	json_object_set_new(pub, "room", json_string(participant->room->room_id_str));
	if(!participant->muted && audiobridge->mjrs)
		json_object_set_new(pub, "recording_id", json_string(participant->recording_id.c_str()));
	json_object_set(pub, "participant", participantInfo);

	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, audiobridge->participants);
	while(g_hash_table_iter_next(&iter, NULL, &value)) {
		room_participant *p = (room_participant *)value;
		if(!self_notify && p == participant) {
			continue;	/* Skip participant itself */
		}
		JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n",
			p->user_id_str, p->display ? p->display : "??");
		int ret = gateway->push_event(p->session->handle, &ptt_audiobridge_plugin, NULL, pub, NULL);
		JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	}
	json_decref(pub);

	/* Also notify event handlers */
	if(notify_events && gateway->events_is_enabled()) {
		ptt_room *audiobridge = participant->room;
		json_t *info = json_object();
		json_object_set_new(info, "event", participant->muted ? json_string("muted") : json_string("unmuted"));
		json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
		if(!participant->muted && audiobridge->mjrs)
			json_object_set_new(pub, "recording_id", json_string(participant->recording_id.c_str()));
		json_object_set(info, "participant", participantInfo);

		gateway->notify_event(&ptt_audiobridge_plugin, session ? session->handle : NULL, info);
	}
	json_decref(participantInfo);
}

void clear_inbuf(room_participant* participant, bool lock_qmutex)
{
	if(lock_qmutex) janus_mutex_lock(&participant->qmutex);
	for(GList* first = participant->inbuf; first; first = g_list_delete_link(first, first)) {
		if(rtp_relay_packet* pkt = (rtp_relay_packet *)first->data) {
			g_free(pkt->data);
			g_free(pkt);
		}
	}
	participant->inbuf = nullptr;
	if(lock_qmutex) janus_mutex_unlock(&participant->qmutex);
}

void participant_destroy(room_participant *participant) {
	if(!participant)
		return;
	if(!g_atomic_int_compare_and_exchange(&participant->destroyed, 0, 1))
		return;
	/* Decrease the counter */
	janus_refcount_decrease(participant);
}

void participant_unref(room_participant *participant) {
	if(!participant)
		return;
	/* Just decrease the counter */
	janus_refcount_decrease(participant);
}

static void participant_free(const janus_refcount *participant_ref) {
	room_participant *participant =
		const_cast<room_participant*>( // yes, I know, it's ugly, but I can do nothing atm
			static_cast<const room_participant*>(participant_ref));

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
