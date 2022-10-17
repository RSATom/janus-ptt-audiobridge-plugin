/*! \file
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>

#include <glib.h>
#include <jansson.h>

#include "audio_recorder.h"

extern "C" {
#include "janus/debug.h"
#include "janus/utils.h"
}

namespace ptt_audioroom
{

/* Info header in the structured recording */
static const char *header = "MJR00002";
/* Frame header in the structured recording */
static const char *frame_header = "MEET";

static void audio_recorder_free(const janus_refcount *recorder_ref) {
	audio_recorder *recorder = janus_refcount_containerof(recorder_ref, audio_recorder, ref);
	/* This recorder can be destroyed, free all the resources */
	audio_recorder_close(recorder);
	g_free(recorder->dir);
	recorder->dir = NULL;
	g_free(recorder->filename);
	recorder->filename = NULL;
	if(recorder->file != NULL)
		fclose(recorder->file);
	recorder->file = NULL;
	g_free(recorder->codec);
	recorder->codec = NULL;
	if(recorder->extensions != NULL)
		g_hash_table_destroy(recorder->extensions);
	g_free(recorder);
}

audio_recorder *audio_recorder_create(const char *dir, const char *codec, const char *filename) {
	if(codec == NULL) {
		JANUS_LOG(LOG_ERR, "Missing codec information\n");
		return NULL;
	}
	if(0 != strcasecmp(codec, "opus") && 0 != strcasecmp(codec, "multiopus")) {
		/* We don't recognize the codec: while we might go on anyway, we'd rather fail instead */
		JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
		return NULL;
	}
	/* Create the recorder */
	audio_recorder *rc = (audio_recorder *)g_malloc0(sizeof(audio_recorder));
	janus_refcount_init(&rc->ref, audio_recorder_free);
	janus_rtp_switching_context_reset(&rc->context);
	rc->dir = NULL;
	rc->filename = NULL;
	rc->file = NULL;
	rc->codec = g_strdup(codec);
	rc->created = janus_get_real_time();
	const char *rec_dir = NULL;
	const char *rec_file = NULL;
	char *copy_for_parent = NULL;
	char *copy_for_base = NULL;
	/* Check dir and filename values */
	if(filename != NULL) {
		/* Helper copies to avoid overwriting */
		copy_for_parent = g_strdup(filename);
		copy_for_base = g_strdup(filename);
		/* Get filename parent folder */
		const char *filename_parent = dirname(copy_for_parent);
		/* Get filename base file */
		const char *filename_base = basename(copy_for_base);
		if(!dir) {
			/* If dir is NULL we have to create filename_parent and filename_base */
			rec_dir = filename_parent;
			rec_file = filename_base;
		} else {
			/* If dir is valid we have to create dir and filename*/
			rec_dir = dir;
			rec_file = filename;
			if(strcasecmp(filename_parent, ".") || strcasecmp(filename_base, filename)) {
				JANUS_LOG(LOG_WARN, "Unsupported combination of dir and filename %s %s\n", dir, filename);
			}
		}
	}
	if(rec_dir != NULL) {
		/* Check if this directory exists, and create it if needed */
		struct stat s;
		int err = stat(rec_dir, &s);
		if(err == -1) {
			if(ENOENT == errno) {
				/* Directory does not exist, try creating it */
				if(janus_mkdir(rec_dir, 0755) < 0) {
					JANUS_LOG(LOG_ERR, "mkdir (%s) error: %d (%s)\n", rec_dir, errno, g_strerror(errno));
					audio_recorder_destroy(rc);
					g_free(copy_for_parent);
					g_free(copy_for_base);
					return NULL;
				}
			} else {
				JANUS_LOG(LOG_ERR, "stat (%s) error: %d (%s)\n", rec_dir, errno, g_strerror(errno));
				audio_recorder_destroy(rc);
				g_free(copy_for_parent);
				g_free(copy_for_base);
				return NULL;
			}
		} else {
			if(S_ISDIR(s.st_mode)) {
				/* Directory exists */
				JANUS_LOG(LOG_VERB, "Directory exists: %s\n", rec_dir);
			} else {
				/* File exists but it's not a directory? */
				JANUS_LOG(LOG_ERR, "Not a directory? %s\n", rec_dir);
				audio_recorder_destroy(rc);
				g_free(copy_for_parent);
				g_free(copy_for_base);
				return NULL;
			}
		}
	}
	char newname[1024];
	memset(newname, 0, 1024);
	if(rec_file == NULL) {
		/* Choose a random username */
		g_snprintf(newname, 1024, "janus-recording-%" SCNu32 ".mjr", janus_random_uint32());
	} else {
		/* Just append the extension */
		g_snprintf(newname, 1024, "%s.mjr", rec_file);
	}
	/* Try opening the file now */
	if(rec_dir == NULL) {
		/* Make sure folder to save to is not protected */
		if(janus_is_folder_protected(newname)) {
			JANUS_LOG(LOG_ERR, "Target recording path '%s' is in protected folder...\n", newname);
			audio_recorder_destroy(rc);
			g_free(copy_for_parent);
			g_free(copy_for_base);
			return NULL;
		}
		rc->file = fopen(newname, "ab");
	} else {
		char path[1024];
		memset(path, 0, 1024);
		g_snprintf(path, 1024, "%s/%s", rec_dir, newname);
		/* Make sure folder to save to is not protected */
		if(janus_is_folder_protected(path)) {
			JANUS_LOG(LOG_ERR, "Target recording path '%s' is in protected folder...\n", path);
			audio_recorder_destroy(rc);
			g_free(copy_for_parent);
			g_free(copy_for_base);
			return NULL;
		}
		rc->file = fopen(path, "ab");
	}
	if(rc->file == NULL) {
		JANUS_LOG(LOG_ERR, "fopen error: %d\n", errno);
		audio_recorder_destroy(rc);
		g_free(copy_for_parent);
		g_free(copy_for_base);
		return NULL;
	}
	if(rec_dir)
		rc->dir = g_strdup(rec_dir);
	rc->filename = g_strdup(newname);
	/* Write the first part of the header */
	size_t res = fwrite(header, sizeof(char), strlen(header), rc->file);
	if(res != strlen(header)) {
		JANUS_LOG(LOG_ERR, "Couldn't write .mjr header (%zu != %zu, %s)\n",
			res, strlen(header), g_strerror(errno));
		audio_recorder_destroy(rc);
		g_free(copy_for_parent);
		g_free(copy_for_base);
		return NULL;
	}
	rc->writable = 1;
	/* We still need to also write the info header first */
	rc->header = 0;
	/* Done */
	rc->destroyed = 0;
	g_free(copy_for_parent);
	g_free(copy_for_base);
	return rc;
}

int audio_recorder_add_extmap(audio_recorder *recorder, int id, const char *extmap) {
	if(!recorder || recorder->header || id < 1 || id > 15 || extmap == NULL )
		return -1;
	if(recorder->extensions == NULL)
		recorder->extensions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)g_free);
	g_hash_table_insert(recorder->extensions, GINT_TO_POINTER(id), g_strdup(extmap));
	return 0;
}

int audio_recorder_opusred(audio_recorder *recorder, int red_pt) {
	if(!recorder)
		return -1;
	if(!recorder->header) {
		recorder->opusred_pt = red_pt;
		return 0;
	}
	return -1;
}

int audio_recorder_save_frame(audio_recorder *recorder, char *buffer, uint length) {
	if(!recorder)
		return -1;
	if(!buffer || length < 1) {
		return -2;
	}
	if(!recorder->file) {
		return -3;
	}
	if(!recorder->writable) {
		return -4;
	}
	gint64 now = janus_get_monotonic_time();
	if(!recorder->header) {
		/* Write info header as a JSON formatted info */
		json_t *info = json_object();
		/* FIXME Codecs should be configurable in the future */
		const char *type = "a";
		json_object_set_new(info, "t", json_string(type));								/* Audio/Video/Data */
		json_object_set_new(info, "c", json_string(recorder->codec));					/* Media codec */
		if(recorder->extensions) {
			/* Add the extmaps to the JSON object */
			json_t *extmaps = NULL;
			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init(&iter, recorder->extensions);
			while(g_hash_table_iter_next(&iter, &key, &value)) {
				int id = GPOINTER_TO_INT(key);
				char *extmap = (char *)value;
				if(id > 0 && id < 16 && extmap != NULL) {
					if(extmaps == NULL)
						extmaps = json_object();
					char id_str[3];
					g_snprintf(id_str, sizeof(id_str), "%d", id);
					json_object_set_new(extmaps, id_str, json_string(extmap));
				}
			}
			if(extmaps != NULL)
				json_object_set_new(info, "x", extmaps);
		}
		json_object_set_new(info, "s", json_integer(recorder->created));				/* Created time */
		json_object_set_new(info, "u", json_integer(janus_get_real_time()));			/* First frame written time */
		/* If this is audio and using RED, take note of the payload type */
		if(recorder->opusred_pt > 0)
			json_object_set_new(info, "or", json_integer(recorder->opusred_pt));
		gchar *info_text = json_dumps(info, JSON_PRESERVE_ORDER);
		json_decref(info);
		if(info_text == NULL) {
			JANUS_LOG(LOG_ERR, "Error converting header to text...\n");
			return -5;
		}
		uint16_t info_bytes = htons(strlen(info_text));
		size_t res = fwrite(&info_bytes, sizeof(uint16_t), 1, recorder->file);
		if(res != 1) {
			JANUS_LOG(LOG_WARN, "Couldn't write size of JSON header in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
				res, sizeof(uint16_t), g_strerror(errno));
		}
		res = fwrite(info_text, sizeof(char), strlen(info_text), recorder->file);
		if(res != strlen(info_text)) {
			JANUS_LOG(LOG_WARN, "Couldn't write JSON header in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
				res, strlen(info_text), g_strerror(errno));
		}
		free(info_text);
		/* Done */
		recorder->started = now;
		recorder->header = 1;
	}
	/* Write frame header (fixed part[4], timestamp[4], length[2]) */
	size_t res = fwrite(frame_header, sizeof(char), strlen(frame_header), recorder->file);
	if(res != strlen(frame_header)) {
		JANUS_LOG(LOG_WARN, "Couldn't write frame header in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
			res, strlen(frame_header), g_strerror(errno));
	}
	uint32_t timestamp = (uint32_t)(now > recorder->started ? ((now - recorder->started)/1000) : 0);
	timestamp = htonl(timestamp);
	res = fwrite(&timestamp, sizeof(uint32_t), 1, recorder->file);
	if(res != 1) {
		JANUS_LOG(LOG_WARN, "Couldn't write frame timestamp in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
			res, sizeof(uint32_t), g_strerror(errno));
	}
	uint16_t header_bytes = htons(length);
	res = fwrite(&header_bytes, sizeof(uint16_t), 1, recorder->file);
	if(res != 1) {
		JANUS_LOG(LOG_WARN, "Couldn't write size of frame in .mjr file (%zu != %zu, %s), expect issues post-processing\n",
			res, sizeof(uint16_t), g_strerror(errno));
	}
	/* Edit packet header if needed */
	janus_rtp_header *header = (janus_rtp_header *)buffer;
	uint32_t ssrc = 0;
	uint16_t seq = 0;
	ssrc = ntohl(header->ssrc);
	seq = ntohs(header->seq_number);
	timestamp = ntohl(header->timestamp);
	janus_rtp_header_update(header, &recorder->context, false, 0);
	/* Save packet on file */
	int temp = 0, tot = length;
	while(tot > 0) {
		temp = fwrite(buffer+length-tot, sizeof(char), tot, recorder->file);
		if(temp <= 0) {
			JANUS_LOG(LOG_ERR, "Error saving frame...\n");
			/* Restore packet header data */
			header->ssrc = htonl(ssrc);
			header->seq_number = htons(seq);
			header->timestamp = htonl(timestamp);
			return -6;
		}
		tot -= temp;
	}
	/* Restore packet header data */
	header->ssrc = htonl(ssrc);
	header->seq_number = htons(seq);
	header->timestamp = htonl(timestamp);
	fflush(recorder->file);
	/* Done */
	return 0;
}

int audio_recorder_close(audio_recorder *recorder) {
	if(!recorder || !recorder->writable)
		return -1;
	recorder ->writable = FALSE;
	if(recorder->file) {
		fseek(recorder->file, 0L, SEEK_END);
		size_t fsize = ftell(recorder->file);
		JANUS_LOG(LOG_INFO, "File is %zu bytes: %s\n", fsize, recorder->filename);
	}
	return 0;
}

void audio_recorder_destroy(audio_recorder *recorder) {
	if(!recorder || recorder->destroyed)
		return;
	recorder->destroyed = TRUE;
	janus_refcount_decrease(&recorder->ref);
}

}
