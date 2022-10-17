#pragma once

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

struct janus_audiobridge_session;
struct janus_audiobridge_room;

struct janus_audiobridge_participant {
	janus_refcount ref;			/* Reference counter for this participant */
	janus_audiobridge_session *session;
	janus_audiobridge_room *room;	/* Room */
	gchar *user_id_str;		/* Unique ID in the room (when using strings) */
	gchar *display;			/* Display name (opaque value, only meaningful to application) */
	gboolean admin;			/* If the participant is an admin (can't be globally muted) */
	gboolean prebuffering;	/* Whether this participant needs pre-buffering of a few packets (just joined) */
	uint prebuffer_count;	/* Number of packets to buffer before decoding this participant */
	volatile gint active;	/* Whether this participant can receive media at all */
	gint encoding;	/* Whether this participant is currently encoding */
	gint decoding;	/* Whether this participant is currently decoding */
	gboolean muted;			/* Whether this participant is muted */
	gint64 unmuted_timestamp;
	int volume_gain;		/* Gain to apply to the input audio (in percentage) */
	int32_t opus_bitrate;	/* Bitrate to use for the Opus stream */
	int opus_complexity;	/* Complexity to use in the encoder (by default, DEFAULT_COMPLEXITY) */
	gboolean stereo;		/* Whether stereo will be used for spatial audio */
	int spatial_position;	/* Panning of this participant in the mix */
	/* RTP stuff */
	GList *inbuf;			/* Incoming audio from this participant, as an ordered list of packets */
	GAsyncQueue *outbuf;	/* Mixed audio for this participant */
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
	OpusEncoder *encoder;		/* Opus encoder instance */
	OpusDecoder *decoder;		/* Opus decoder instance */
	gboolean fec;				/* Opus FEC status */
	int expected_loss;			/* Percentage of expected loss, to configure libopus FEC behaviour (default=0, no FEC even if negotiated) */
	uint16_t expected_seq;		/* Expected sequence number */
	uint16_t probation; 		/* Used to determine new ssrc validity */
	uint32_t last_timestamp;	/* Last in seq timestamp */
	gboolean reset;				/* Whether or not the Opus context must be reset, without re-joining the room */
	GThread *thread;			/* Encoding thread for this participant */
	audio_recorder *arc;		/* The Janus recorder instance for this user's audio, if enabled */
	janus_mutex rec_mutex;		/* Mutex to protect the recorder from race conditions */
	gint destroyed;	/* Whether this room has been destroyed */
};

void janus_audiobridge_recorder_create(janus_audiobridge_participant *participant);
void janus_audiobridge_recorder_close(janus_audiobridge_participant *participant);

void janus_audiobridge_participant_destroy(janus_audiobridge_participant *participant);
void janus_audiobridge_participant_unref(janus_audiobridge_participant *participant);
void janus_audiobridge_participant_free(const janus_refcount *participant_ref);

}
