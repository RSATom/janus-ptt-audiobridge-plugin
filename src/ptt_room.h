/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#pragma once

#include <cstdint>
#include <string>
#include <deque>
#include <optional>

#include <glib.h>

#include <jansson.h>
#include <opus/opus.h>

extern "C" {
#include "janus/refcount.h"
}


namespace ptt_audiobridge
{

struct file_info {
	file_info(const char* id, const char* opaque, const char* path, bool unlink_on_finish) :
		id(id ? id : "id"),
		opaque(opaque ? std::string(opaque) : std::string()),
		path(path ? std::string(path) : std::string()),
		unlink_on_finish(unlink_on_finish) {}
	file_info(std::string&& id, std::string&& opaque, std::string&& path, bool unlink_on_finish) :
		id(id), opaque(opaque), path(path), unlink_on_finish(unlink_on_finish) {}

	const std::string id;
	const std::string opaque;
	const std::string path;
	const bool unlink_on_finish;
};

struct ptt_room: public janus_refcount {
	static ptt_room* create();

	gchar *room_id_str;			/* Unique room ID (when using strings) */
	gchar *room_name;			/* Room description */
	gchar *room_secret;			/* Secret needed to manipulate (e.g., destroy) this room */
	gchar *room_pin;			/* Password needed to join this room, if any */
	uint32_t room_ssrc;			/* SSRC we'll use for packets generated by the mixer */
	gboolean is_private;		/* Whether this room is 'private' (as in hidden) or not */
	gboolean audiolevel_ext;	/* Whether the ssrc-audio-level extension must be negotiated or not for new joins */
	gboolean audiolevel_event;	/* Whether to emit event to other users about audiolevel */
	uint default_prebuffering;	/* Number of packets to buffer before decoding each participant */
	int audio_active_packets;	/* Amount of packets with audio level for checkup */
	int audio_level_average;	/* Average audio level */
	gboolean mjrs;				/* Whether all participants in the room should be individually recorded to mjr files or not */
	gchar *mjrs_dir;			/* Folder to save the mjrs file to */
	gboolean destroy;			/* Value to flag the room for destruction */

	GHashTable *participants;	/* Map of participants */
	struct room_participant* unmuted_participant;

	bool playing_file;
	std::deque<file_info> files_to_play;

	gboolean check_tokens;		/* Whether to check tokens when participants join (see below) */
	GHashTable *allowed;		/* Map of participants (as tokens) allowed to join */
	GThread *thread;			/* Mixer thread for this room */
	gint destroyed;	/* Whether this room has been destroyed */
	janus_mutex mutex;			/* Mutex to lock this room instance */

	/* RTP forwarders for this room's mix */
	GHashTable *rtp_forwarders;	/* RTP forwarders list (as a hashmap) */
	janus_mutex rtp_mutex;		/* Mutex to lock the RTP forwarders list */
	int rtp_udp_sock;			/* UDP socket to use to forward RTP packets */
};

// ptt_room::mutex should be locked
void notify_participants(ptt_room* room, json_t* msg);

void* room_sender_thread(void* data);

int create_udp_socket_if_needed(ptt_room *audiobridge);

void ptt_room_destroy(ptt_room *audiobridge);

}
