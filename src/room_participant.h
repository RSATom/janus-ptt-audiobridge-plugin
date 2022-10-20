#pragma once

#include <thread>

#include <glib.h>

#include <opus/opus.h>

extern "C" {
#include "janus/mutex.h"
#include "janus/refcount.h"
#include "janus/rtp.h"
}

#include "audio_recorder.h"


namespace ptt_audioroom
{

struct plugin_session;
struct ptt_room;

struct room_participant {
	janus_refcount ref;			/* Reference counter for this participant */
	plugin_session *session;
	ptt_room *room;	/* Room */
	gchar *user_id_str;		/* Unique ID in the room (when using strings) */
	gchar *display;			/* Display name (opaque value, only meaningful to application) */
	gboolean admin;			/* If the participant is an admin (can't be globally muted) */
	gboolean prebuffering;	/* Whether this participant needs pre-buffering of a few packets (just joined) */
	uint prebuffer_count;	/* Number of packets to buffer before decoding this participant */
	volatile gint active;	/* Whether this participant can receive media at all */
	gboolean muted;			/* Whether this participant is muted */
	gint64 unmuted_timestamp;
	/* RTP stuff */
	GList *inbuf;			/* Incoming audio from this participant, as an ordered list of packets */
	gint64 last_drop;		/* When we last dropped a packet because the imcoming queue was full */
	gint64 inbuf_timestamp;	/* Last inbuf update timestamp */
	janus_mutex qmutex;		/* Incoming queue mutex */
	int opus_pt;			/* Opus payload type */
	int extmap_id;			/* Audio level RTP extension id, if any */
	int dBov_level;			/* Value in dBov of the audio level (last value from extension) */
	int audio_active_packets;	/* Participant's number of audio packets to accumulate */
	int audio_dBov_sum;	    /* Participant's accumulated dBov value for audio level */
	int user_audio_active_packets; /* Participant's number of audio packets to evaluate */
	int user_audio_level_average;	 /* Participant's average level of dBov value */
	gboolean talking;		/* Whether this participant is currently talking (uses audio levels extension) */
	janus_rtp_switching_context context;	/* Needed in case the participant changes room */
	/* Opus stuff */
	gboolean fec;				/* Opus FEC status */
	uint16_t expected_seq;		/* Expected sequence number */
	uint16_t probation; 		/* Used to determine new ssrc validity */
	uint32_t last_timestamp;	/* Last in seq timestamp */
	gboolean reset;				/* Whether or not the Opus context must be reset, without re-joining the room */
	audio_recorder *arc;		/* The Janus recorder instance for this user's audio, if enabled */
	janus_mutex rec_mutex;		/* Mutex to protect the recorder from race conditions */
	gint destroyed;	/* Whether this room has been destroyed */

	std::thread::id incoming_rtp_thread_id;
};

void clear_inbuf(room_participant *participant, bool lock_qmutex);

void recorder_create(room_participant *participant);
void recorder_close(room_participant *participant);

void participant_destroy(room_participant *participant);
void participant_unref(room_participant *participant);
void participant_free(const janus_refcount *participant_ref);

}