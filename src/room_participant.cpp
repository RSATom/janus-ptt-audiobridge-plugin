#include "room_participant.h"

#include <type_traits>

extern "C" {
#include "janus/utils.h"
}

#include "ptt_room.h"
#include "rtp_relay_packet.h"


namespace ptt_audioroom
{

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
