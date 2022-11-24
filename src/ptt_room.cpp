/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "ptt_room.h"

#include <cassert>
#include <type_traits>

#include <glib/gstdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

extern "C" {
#include "janus/apierror.h"
}

#include "constants.h"
#include "ptt_audiobridge_plugin.h"
#include "room_participant.h"
#include "rtp_forwarder.h"
#include "rtp_relay_packet.h"
#include "janus_mutex_lock_guard.h"
#include "opus_file.h"


namespace ptt_audiobridge
{

enum {
	max_rtp_size = 1500,
	rtp_header_size = 12,
};

struct now_playing {
	const file_info source_file;

	now_playing(const file_info& source_file) :
		source_file(source_file) {}
	~now_playing() {
		if(source_file.unlink_on_finish)
			g_unlink(source_file.path.c_str());
	}

	bool open() {
		return _file_reader.open(source_file.path);
	}

	bool is_readable() const {
		return _file_reader.last_read_result() == opus_file::ReadResult::Success;
	}

	std::optional<const ogg_packet> read_next_packet() {
		if(_file_reader.read_next_packet() == opus_file::ReadResult::Success) {
			return _file_reader.last_read_packet();
		}
		return {};
	}

private:
	opus_file _file_reader;
};

static void ptt_room_free(const janus_refcount *audiobridge_ref);

ptt_room* ptt_room::create()
{
	ptt_room* room= new ptt_room {};
	janus_refcount_init(room, ptt_room_free);
	return room;
}

static void relay_rtp_packet(
	room_participant* target_participant,
	void* rtp_packet,
	unsigned rtp_packet_size)
{
	assert(rtp_packet_size >= rtp_header_size);

	janus_rtp_header* rtp_header = (janus_rtp_header*)rtp_packet;

	const auto timestamp_save = rtp_header->timestamp;
	const auto seq_number_save = rtp_header->seq_number;

	/* Fix sequence number and timestamp (room switching may be involved) */
	janus_rtp_header_update(rtp_header, &target_participant->context, FALSE, 0);

	if(gateway != NULL) {
		janus_plugin_rtp rtp = {
			.mindex = -1,
			.video = FALSE,
			.buffer = (char *)rtp_packet,
			.length = (uint16_t)rtp_packet_size
		};
		janus_plugin_rtp_extensions_reset(&rtp.extensions);
		/* FIXME Should we add our own audio level extension? */
		gateway->relay_rtp(target_participant->session->handle, &rtp);
	}

	// janus_rtp_header_update alters timestamp and seq_number,
	// so let's restore it to original value for safety
	rtp_header->timestamp = timestamp_save;
	rtp_header->seq_number = seq_number_save;
}

// ptt_room::mutex should be locked
void notify_participants(ptt_room* room, json_t* msg) {
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, room->participants);
	while(!room->destroyed && g_hash_table_iter_next(&iter, NULL, &value)) {
		room_participant *p = (room_participant *)value;
		if(p && p->session) {
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &ptt_audiobridge_plugin, NULL, msg, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
	}
}

// ptt_room::mutex should be locked
static void notify_playback_started(ptt_room* room, const std::string& file_id) {
	JANUS_LOG(LOG_INFO, "[%s] Playback started (%s)\n", room->room_id_str, file_id.c_str());
	json_t *event = json_object();
	json_object_set_new(event, "audiobridge", json_string("playback-started"));
	json_object_set_new(event, "room", json_string(room->room_id_str));
	json_object_set_new(event, "file_id", json_string(file_id.c_str()));
	notify_participants(room, event);
	json_decref(event);

	/* Also notify event handlers */
	if(notify_events && gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("playback-started"));
		json_object_set_new(info, "room", json_string(room->room_id_str));
		json_object_set_new(info, "file_id", json_string(file_id.c_str()));
		gateway->notify_event(&ptt_audiobridge_plugin, NULL, info);
	}
}

// ptt_room::mutex should be locked
static void notify_playback_stopped(ptt_room* room, const std::string& file_id) {
	JANUS_LOG(LOG_INFO, "[%s] Playback stopped (%s)\n", room->room_id_str, file_id.c_str());
	json_t *event = json_object();
	json_object_set_new(event, "audiobridge", json_string("playback-stopped"));
	json_object_set_new(event, "room", json_string(room->room_id_str));
	json_object_set_new(event, "file_id", json_string(file_id.c_str()));
	notify_participants(room, event);
	json_decref(event);

	/* Also notify event handlers */
	if(notify_events && gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("playback-stopped"));
		json_object_set_new(info, "room", json_string(room->room_id_str));
		json_object_set_new(info, "file_id", json_string(file_id.c_str()));
		gateway->notify_event(&ptt_audiobridge_plugin, NULL, info);
	}
}

static void update_rtp_header(
	janus_rtp_header* rtp_header,
	uint32_t ssrc,
	uint32_t timestamp,
	uint16_t seq_number)
{
	rtp_header->version = 2;
	rtp_header->markerbit = 0; /* FIXME Should be 1 for the first packet */
	rtp_header->seq_number = htons(seq_number);
	rtp_header->timestamp = htonl(timestamp);
	rtp_header->ssrc = htonl(ssrc);
}

static void update_rtp_header(
	janus_rtp_header* rtp_header,
	uint8_t payload_type,
	uint32_t ssrc,
	uint32_t timestamp,
	uint16_t seq_number)
{
	rtp_header->type = payload_type;
	update_rtp_header(rtp_header, ssrc, timestamp, seq_number);
}

void* room_sender_thread(void* data) {
	JANUS_LOG(LOG_VERB, "Audio bridge thread starting...\n");
	ptt_room *audiobridge = (ptt_room *)data;
	if(!audiobridge) {
		JANUS_LOG(LOG_ERR, "Invalid room!\n");
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Thread is for room %s (%s)...\n",
		audiobridge->room_id_str, audiobridge->room_name);

	/* Timer */
	struct timeval now, before;
	gettimeofday(&before, NULL);
	now.tv_sec = before.tv_sec;
	now.tv_usec = before.tv_usec;
	time_t passed, d_s, d_us;

	/* RTP */
	guint16 seq = 0;
	guint32 ts = 0;

	char rtp_buffer[max_rtp_size];

	/* SRTP buffer, if needed */
	char sbuf[1500];

	room_participant* unmuted_participant = nullptr;
	std::string unmuted_participant_id;
	std::unique_ptr<audio_recorder> recorder_ptr;

	std::unique_ptr<now_playing> now_playing_ptr;

	/* Loop */
	int i=0;
	int count = 0, rf_count = 0, prev_count = 0;
	while(!g_atomic_int_get(&stopping) && !g_atomic_int_get(&audiobridge->destroyed)) {
		/* See if it's time to prepare a frame */
		gettimeofday(&now, NULL);
		d_s = now.tv_sec - before.tv_sec;
		d_us = now.tv_usec - before.tv_usec;
		if(d_us < 0) {
			d_us += 1000000;
			--d_s;
		}
		passed = d_s*1000000 + d_us;
		if(passed < 15000) {	/* Let's wait about 15ms at max */
			g_usleep(5000);
			continue;
		}
		/* Update the reference time */
		before.tv_usec += 20000;
		if(before.tv_usec > 1000000) {
			before.tv_sec++;
			before.tv_usec -= 1000000;
		}
		/* Do we need to mix at all? */
		janus_mutex_lock_nodebug(&audiobridge->mutex);
		count = g_hash_table_size(audiobridge->participants);
		rf_count = g_hash_table_size(audiobridge->rtp_forwarders);
		unsigned pf_count = audiobridge->files_to_play.size();
		if((count + rf_count + pf_count) == 0) {
			janus_mutex_unlock_nodebug(&audiobridge->mutex);
			/* No participant and RTP forwarders, do nothing */
			if(prev_count > 0) {
				JANUS_LOG(LOG_INFO, "Last user/forwarder/file just left room %s, going idle...\n", audiobridge->room_id_str);
				prev_count = 0;
			}
			continue;
		}
		if(prev_count == 0) {
			JANUS_LOG(LOG_INFO, "First user/forwarder/file just joined room %s, waking it up...\n", audiobridge->room_id_str);
		}
		prev_count = count + rf_count + pf_count;

		/* Update RTP header information */
		seq++;
		ts += OPUS_SAMPLES;
		/* Mix all contributions */
		GList *participants_list = g_hash_table_get_values(audiobridge->participants);
		/* Add a reference to all these participants, in case some leave while we're mixing */
		GList *ps = participants_list;
		while(ps) {
			room_participant *p = (room_participant *)ps->data;
			if(p != audiobridge->unmuted_participant) {
				assert(!p->inbuf);
				if(p->inbuf)
					JANUS_LOG(LOG_ERR, "Muted participant has queued packets.\n");
			}

			janus_refcount_increase(p);
			ps = ps->next;
		}

		room_participant* current_unmuted_participant = audiobridge->unmuted_participant;

		// There is a very small chance new participant will be allocated on the same address
		// as already destroyed unmuted participant.
		// So let's protect from it by comparing ids also.
		if(unmuted_participant != current_unmuted_participant ||
			(current_unmuted_participant &&
				unmuted_participant_id != current_unmuted_participant->user_id_str))
		{
			recorder_ptr.reset();

			unmuted_participant = current_unmuted_participant;
			if(current_unmuted_participant)
				unmuted_participant_id = current_unmuted_participant->user_id_str;
			else
				unmuted_participant_id.clear();

			if(audiobridge->mjrs && audiobridge->mjrs_dir &&
				unmuted_participant && !unmuted_participant->recording_id.empty())
			{
				std::string recording_path = audiobridge->mjrs_dir;
				if(recording_path.back() != G_DIR_SEPARATOR) {
					recording_path += G_DIR_SEPARATOR_S;
				}
				recording_path += unmuted_participant->recording_id;
				recording_path += ".mjr";

				recorder_ptr = std::make_unique<audio_recorder>(recording_path, janus_audiocodec_name(JANUS_AUDIOCODEC_OPUS));

				if(unmuted_participant->extmap_id > 0) {
					recorder_ptr->add_extmap(unmuted_participant->extmap_id, JANUS_RTP_EXTMAP_AUDIO_LEVEL);
				}

				if(!recorder_ptr->open()) {
					recorder_ptr.reset();
				}
			}
		}

		if(!unmuted_participant &&
			!audiobridge->playing_file &&
			!audiobridge->files_to_play.empty())
		{
			assert(!now_playing_ptr);

			// it's time to start next file playback

			memset(rtp_buffer, 0 , rtp_header_size); // to avoid side effects from previous use

			now_playing_ptr = std::make_unique<now_playing>(audiobridge->files_to_play.front());
			audiobridge->files_to_play.pop_front();

			audiobridge->playing_file = true;
			notify_playback_started(audiobridge, now_playing_ptr->source_file.id);

			now_playing_ptr->open();
		}

		if(now_playing_ptr && !now_playing_ptr->is_readable()) {
			assert(audiobridge->playing_file);

			// it's time to stop file playback

			audiobridge->playing_file = false;
			notify_playback_stopped(audiobridge, now_playing_ptr->source_file.id);

			now_playing_ptr.reset();
		}

		janus_mutex_unlock_nodebug(&audiobridge->mutex);

		assert(!unmuted_participant || !now_playing_ptr);

		if(unmuted_participant) {
			janus_mutex_lock_guard inbuf_lock_guard(&unmuted_participant->qmutex);
			if(g_atomic_int_get(&unmuted_participant->destroyed) ||
				!unmuted_participant->session ||
				!g_atomic_int_get(&unmuted_participant->session->started) ||
				!g_atomic_int_get(&unmuted_participant->active) ||
				unmuted_participant->prebuffering ||
				!unmuted_participant->inbuf)
			{
				continue;
			}

			GList* peek = g_list_first(unmuted_participant->inbuf);
			rtp_relay_packet* pkt = (rtp_relay_packet *)(peek ? peek->data : NULL);
			unmuted_participant->inbuf = g_list_delete_link(unmuted_participant->inbuf, peek);

			inbuf_lock_guard.unlock();

			if(recorder_ptr) recorder_ptr->save_frame(pkt->data, pkt->length);

			if(pkt && !pkt->silence) {
				update_rtp_header(pkt->data, audiobridge->room_ssrc, ts, seq);

				/* Send packet to each participant (except self) */
				ps = participants_list;
				while(ps) {
					room_participant* p = (room_participant*)ps->data;
					if(g_atomic_int_get(&p->destroyed) ||
						!p->session ||
						!g_atomic_int_get(&p->session->started) ||
						p == unmuted_participant)
					{
						ps = ps->next;
						continue;
					}

					pkt->data->type = p->opus_pt;
					relay_rtp_packet(p, pkt->data, pkt->length);

					ps = ps->next;
				}
			}

			/* Forward the packet as RTP to any RTP forwarder that may be listening */
			janus_mutex_lock_guard forwarders_lock_guard(&audiobridge->rtp_mutex);
			if(g_hash_table_size(audiobridge->rtp_forwarders) > 0) {
				/* If the room is empty, check if there's any RTP forwarder with an "always on" option */
				gboolean go_on = FALSE;
				if(count == 0) {
					GHashTableIter iter;
					gpointer value;
					g_hash_table_iter_init(&iter, audiobridge->rtp_forwarders);
					while(g_hash_table_iter_next(&iter, NULL, &value)) {
						rtp_forwarder *forwarder = (rtp_forwarder *)value;
						if(forwarder->always_on) {
							go_on = TRUE;
							break;
						}
					}
				} else {
					go_on = TRUE;
				}
				if(go_on) {
					GHashTableIter iter;
					gpointer key, value;
					g_hash_table_iter_init(&iter, audiobridge->rtp_forwarders);
					while(audiobridge->rtp_udp_sock > 0 && g_hash_table_iter_next(&iter, &key, &value)) {
						guint32 stream_id = GPOINTER_TO_UINT(key);
						rtp_forwarder *forwarder = (rtp_forwarder *)value;
						if(count == 0 && !forwarder->always_on)
							continue;

						forwarder->seq_number++;
						forwarder->timestamp += OPUS_SAMPLES;

						update_rtp_header(
							pkt->data,
							forwarder->payload_type,
							forwarder->ssrc ? forwarder->ssrc : stream_id,
							forwarder->timestamp,
							forwarder->seq_number);

						/* Check if this packet needs to be encrypted */
						char* payload = (char *)pkt->data;
						int plen = pkt->length;
						if(forwarder->is_srtp) {
							memcpy(sbuf, payload, plen);
							int protected_ = plen;
							int res = srtp_protect(forwarder->srtp_ctx, sbuf, &protected_);
							if(res != srtp_err_status_ok) {
								janus_rtp_header *header = (janus_rtp_header *)sbuf;
								guint32 timestamp = ntohl(header->timestamp);
								guint16 seq = ntohs(header->seq_number);
								JANUS_LOG(LOG_ERR, "Error encrypting RTP packet for room %s... %s (len=%d-->%d, ts=%" SCNu32 ", seq=%" SCNu16 ")...\n",
									audiobridge->room_id_str, janus_srtp_error_str(res), plen, protected_, timestamp, seq);
							} else {
								payload = (char *)&sbuf;
								plen = protected_;
							}
						}

						/* No encryption, send the RTP packet as it is */
						struct sockaddr *address = (forwarder->serv_addr.sin_family == AF_INET ?
							(struct sockaddr *)&forwarder->serv_addr : (struct sockaddr *)&forwarder->serv_addr6);
						size_t addrlen = (forwarder->serv_addr.sin_family == AF_INET ? sizeof(forwarder->serv_addr) : sizeof(forwarder->serv_addr6));
						if(sendto(audiobridge->rtp_udp_sock, payload, plen, 0, address, addrlen) < 0) {
							JANUS_LOG(LOG_HUGE, "Error forwarding mixed RTP packet for room %s... %s (len=%d)...\n",
								audiobridge->room_id_str, g_strerror(errno), plen);
						}
					}
				}
			}

			if(pkt) {
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
			}
		} else if(now_playing_ptr) {
			if(std::optional<const ogg_packet> ogg_packet = now_playing_ptr->read_next_packet()) {
				const gsize rtp_size = std::min<gsize>(ogg_packet->bytes + rtp_header_size, max_rtp_size);
				memcpy(rtp_buffer + rtp_header_size, ogg_packet->packet, rtp_size - rtp_header_size);

				janus_rtp_header* rtp_header = (janus_rtp_header*)(rtp_buffer);
				update_rtp_header(rtp_header, audiobridge->room_ssrc, ts, seq);

				ps = participants_list;
				while(ps) {
					room_participant *p = (room_participant *)ps->data;
					if(g_atomic_int_get(&p->destroyed) || !p->session || !g_atomic_int_get(&p->session->started)) {
						ps = ps->next;
						continue;
					}

					rtp_header->type = p->opus_pt;
					relay_rtp_packet(p, rtp_buffer, rtp_size);

					ps = ps->next;
				}
			}
		}

		ps = participants_list;
		while(ps) {
			room_participant *p = (room_participant *)ps->data;
			janus_refcount_decrease(p);
			ps = ps->next;
		}
		g_list_free(participants_list);

	}

	JANUS_LOG(LOG_VERB, "Leaving sender thread for room %s (%s)...\n", audiobridge->room_id_str, audiobridge->room_name);

	janus_refcount_decrease(audiobridge);

	return NULL;
}

int create_udp_socket_if_needed(ptt_room *audiobridge) {
	if(audiobridge->rtp_udp_sock > 0) {
		return 0;
	}

	audiobridge->rtp_udp_sock = socket(!ipv6_disabled ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(audiobridge->rtp_udp_sock <= 0) {
		JANUS_LOG(LOG_ERR, "Could not open UDP socket for RTP forwarder (room %s), %d (%s)\n",
			audiobridge->room_id_str, errno, g_strerror(errno));
		return -1;
	}
	if(!ipv6_disabled) {
		int v6only = 0;
		if(setsockopt(audiobridge->rtp_udp_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
			JANUS_LOG(LOG_ERR, "Could not configure UDP socket for RTP forwarder (room %s), %d (%s))\n",
				audiobridge->room_id_str, errno, g_strerror(errno));
			return -1;
		}
	}

	return 0;
}

void ptt_room_destroy(ptt_room *audiobridge) {
	if(!audiobridge)
		return;
	if(!g_atomic_int_compare_and_exchange(&audiobridge->destroyed, 0, 1))
		return;
	/* Decrease the counter */
	janus_refcount_decrease(audiobridge);
}

static void ptt_room_free(const janus_refcount *audiobridge_ref) {
	ptt_room *audiobridge =
		const_cast<ptt_room*>( // yes, I know, it's ugly, but I can do nothing atm
			static_cast<const ptt_room*>(audiobridge_ref));

	/* This room can be destroyed, free all the resources */
	g_free(audiobridge->room_id_str);
	g_free(audiobridge->room_name);
	g_free(audiobridge->room_secret);
	g_free(audiobridge->room_pin);
	g_hash_table_destroy(audiobridge->participants);
	g_hash_table_destroy(audiobridge->allowed);
	if(audiobridge->rtp_udp_sock > 0)
		close(audiobridge->rtp_udp_sock);
	g_hash_table_destroy(audiobridge->rtp_forwarders);

	delete audiobridge;
}

}
