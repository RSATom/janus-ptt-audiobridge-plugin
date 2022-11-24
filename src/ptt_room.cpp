/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "ptt_room.h"

#include <cassert>
#include <type_traits>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "constants.h"
#include "ptt_audiobridge_plugin.h"
#include "room_participant.h"
#include "rtp_forwarder.h"
#include "rtp_relay_packet.h"
#include "janus_mutex_lock_guard.h"


namespace ptt_audiobridge
{

static void ptt_room_free(const janus_refcount *audiobridge_ref);

ptt_room* ptt_room::create()
{
	ptt_room* room= new ptt_room {};
	janus_refcount_init(room, ptt_room_free);
	return room;
}

static void relay_rtp_packet(
	room_participant *participant,
	plugin_session* session,
	rtp_relay_packet *packet)
{
	/* Set the payload type */
	packet->data->type = participant->opus_pt;
	const auto timestamp_save = packet->data->timestamp;
	const auto seq_number_save = packet->data->seq_number;
	/* Fix sequence number and timestamp (room switching may be involved) */
	janus_rtp_header_update(packet->data, &participant->context, FALSE, 0);
	if(gateway != NULL) {
		janus_plugin_rtp rtp = { .mindex = -1, .video = FALSE, .buffer = (char *)packet->data, .length = (uint16_t)packet->length };
		janus_plugin_rtp_extensions_reset(&rtp.extensions);
		/* FIXME Should we add our own audio level extension? */
		gateway->relay_rtp(session->handle, &rtp);
	}
	/* Restore the timestamp and sequence number to what the sender set them to */
	packet->data->timestamp = timestamp_save;
	packet->data->seq_number = seq_number_save;
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
	/* SRTP buffer, if needed */
	char sbuf[1500];

	room_participant* unmuted_participant = nullptr;
	std::string unmuted_participant_id;
	std::unique_ptr<audio_recorder> recorder_ptr;

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
		if((count+rf_count) == 0) {
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
		prev_count = count+rf_count;
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

		janus_mutex_unlock_nodebug(&audiobridge->mutex);

		if(unmuted_participant) {
			room_participant *p = unmuted_participant;
			janus_mutex_lock_guard inbuf_lock_guard(&p->qmutex);
			if(g_atomic_int_get(&p->destroyed) || !p->session || !g_atomic_int_get(&p->session->started) || !g_atomic_int_get(&p->active) || p->prebuffering || !p->inbuf) {
				continue;
			}

			GList *peek = g_list_first(p->inbuf);
			rtp_relay_packet *pkt = (rtp_relay_packet *)(peek ? peek->data : NULL);
			p->inbuf = g_list_delete_link(p->inbuf, peek);

			inbuf_lock_guard.unlock();

			if(recorder_ptr) recorder_ptr->save_frame(pkt->data, pkt->length);

			if(pkt && !pkt->silence) {
				update_rtp_header(pkt->data, audiobridge->room_ssrc, ts, seq);

				/* Send packet to each participant (except self) */
				ps = participants_list;
				while(ps) {
					room_participant *p = (room_participant *)ps->data;
					if(g_atomic_int_get(&p->destroyed) || !p->session || !g_atomic_int_get(&p->session->started) || p == unmuted_participant) {
						ps = ps->next;
						continue;
					}

					relay_rtp_packet(p, p->session, pkt);

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
