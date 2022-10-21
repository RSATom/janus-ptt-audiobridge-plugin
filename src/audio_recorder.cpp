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
#include <glib/gstdio.h>
#include <jansson.h>

#include "audio_recorder.h"

extern "C" {
#include "janus/debug.h"
#include "janus/utils.h"
}

#include "c_ptr.h"
#include "glib_ptr.h"
#include "json_ptr.h"


namespace {

const char header[] = "MJR00002";
const char frame_header[] = "MEET";
const char eos_header[] = "----";

struct rtp_header_restorer
{
	rtp_header_restorer(janus_rtp_header* header) :
		_header(header),
		_ssrc(header->ssrc),
		_seq_number(header->seq_number),
		_timestamp(header->timestamp) {}

	~rtp_header_restorer() {
		_header->ssrc = _ssrc;
		_header->seq_number = _seq_number;
		_header->timestamp = _timestamp;
	}

private:
	janus_rtp_header *const _header;
	const uint32_t _ssrc;
	const uint16_t _seq_number;
	const uint32_t _timestamp;
};

}

namespace ptt_audioroom {

audio_recorder::audio_recorder(
	const std::string& recording_path,
	const std::string& codec) :
	_created_at(janus_get_real_time()),
	_recording_path(recording_path),
	_codec(codec)
{
	janus_rtp_switching_context_reset(&_rtp_context);
}

audio_recorder::~audio_recorder()
{
	close();
}

bool audio_recorder::open()
{
	if(_file) {
		JANUS_LOG(LOG_ERR, "Trying open audio_recorder second time\n");
		return false;
	}

	if(_recording_path.empty()) {
		JANUS_LOG(LOG_ERR, "Missing recordign path\n");
		return false;
	}

	if(_codec.empty()) {
		JANUS_LOG(LOG_ERR, "Missing codec information\n");
		return false;
	}

	if(strcasecmp(_codec.c_str(), "opus") != 0 && strcasecmp(_codec.c_str(), "multiopus") != 0) {
		JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", _codec.c_str());
		return false;
	}

	gchar_ptr recording_dir_ptr(g_path_get_dirname(_recording_path.c_str()));
	const gchar* recording_dir = recording_dir_ptr.get();
	if(g_strcmp0(recording_dir, ".") != 0) {
		if(g_mkdir_with_parents(recording_dir, 0700) < 0) {
			JANUS_LOG(LOG_ERR, "Failed to create dir \"%s\" for recording\n", recording_dir);
			return false;
		}
	}

	if(g_unlink(_recording_path.c_str()) != 0 && errno != ENOENT) {
		JANUS_LOG(LOG_ERR, "Failed to delete file \"%s\" %s\n", _recording_path.c_str(), g_strerror(errno));
		return false;
	}

	_file = fopen(_recording_path.c_str(), "ab");
	if(!_file) {
		JANUS_LOG(LOG_ERR, "Failed to open file \"%s\" for recording\n", _recording_path.c_str());
		return false;
	}

	if(fwrite(header, sizeof(header) - 1, 1, _file) != 1) {
		_write_failed = true;
		JANUS_LOG(LOG_ERR, "Failed to write .mjr header (%s)\n", g_strerror(errno));
		return false;
	}

	return true;
}

bool audio_recorder::add_extmap(int id, const std::string& extmap)
{
	if(_header_saved || id < 1 || id > 15 || extmap.empty()) {
		return false;
	}

	_extensions[id] = extmap;

	return true;
}

bool audio_recorder::save_header()
{
	if(_header_saved) {
		return false;
	}

	if(_write_failed) {
		return false;
	}

	if(!_file) {
		return false;
	}

	json_ptr info_ptr(json_object());
	json_t* info = info_ptr.get();
	json_object_set_new(info, "t", json_string("a")); // type = audio
	json_object_set_new(info, "c", json_string(_codec.c_str()));
	if(!_extensions.empty()) {
		/* Add the extmaps to the JSON object */
		json_t* extmaps = NULL;
		for(const auto& id2extmap: _extensions) {
			const int id = id2extmap.first;
			const std::string& extmap = id2extmap.second;

			if(id > 0 && id < 16 && !extmap.empty()) {
				if(!extmaps)
					extmaps = json_object();

				json_object_set_new(
					extmaps,
					std::to_string(id).c_str(),
					json_string(extmap.c_str()));
			}
		}
		if(extmaps != NULL)
			json_object_set_new(info, "x", extmaps);
	}
	json_object_set_new(info, "s", json_integer(_created_at)); /* Created time */
	json_object_set_new(info, "u", json_integer(janus_get_real_time())); /* First frame written time */

	char_ptr info_text_ptr(json_dumps(info, JSON_PRESERVE_ORDER));
	const gchar* info_text = info_text_ptr.get();
	if(!info_text) {
		JANUS_LOG(LOG_ERR, "Error converting header to text...\n");

		return false;
	}

	const uint16_t info_bytes = htons(strlen(info_text));
	if(fwrite(&info_bytes, sizeof(uint16_t), 1, _file) != 1) {
		JANUS_LOG(
			LOG_WARN,
			"Failed to write size of JSON header to .mjr file (%s)\n",
			g_strerror(errno));

		_write_failed = true;

		return false;
	}

	const size_t info_text_len = strlen(info_text);
	if(fwrite(info_text, info_text_len, 1, _file) != 1) {
		JANUS_LOG(
			LOG_WARN,
			"Failed to write JSON header to .mjr file (%s)\n",
			g_strerror(errno));

		_write_failed = true;

		return false;
	}

	_header_saved = true;
	_started_at = janus_get_monotonic_time();

	return true;
}

bool audio_recorder::save_frame(void* frame, short frame_size)
{
	if(_write_failed) {
		return false;
	}

	if(!_file) {
		return false;
	}

	if(!frame || frame_size == 0) {
		return false;
	}

	if(!_header_saved && !save_header()) {
		return false;
	}

	const gint64 now = janus_get_monotonic_time();

	/* Write frame header (fixed part[4], timestamp[4], length[2]) */
	if(fwrite(frame_header, sizeof(frame_header) - 1, 1, _file) != 1) {
		JANUS_LOG(
			LOG_WARN,
			"Failed to write frame header to .mjr file (%s)\n",
			g_strerror(errno));

		_write_failed = true;

		return false;
	}

	const uint32_t timestamp = htonl((now > (_started_at ? (now - _started_at) / 1000 : 0)));
	if(fwrite(&timestamp, sizeof(timestamp), 1, _file) != 1) {
		JANUS_LOG(
			LOG_WARN,
			"Failed to write frame timestamp to .mjr file (%s)\n",
			g_strerror(errno));

		_write_failed = true;

		return false;
	}

	const uint16_t header_bytes = htons(frame_size);
	if(fwrite(&header_bytes, sizeof(header_bytes), 1, _file) != 1) {
		JANUS_LOG(
			LOG_WARN,
			"Failed to write size of frame to .mjr file (%s)\n",
			g_strerror(errno));

		_write_failed = true;

		return false;
	}

	/* Edit packet header if needed */
	janus_rtp_header* header = (janus_rtp_header*) frame;
	rtp_header_restorer header_restore(header);

	janus_rtp_header_update(header, &_rtp_context, false, 0);

	/* Save packet on file */
	if(fwrite(frame, frame_size, 1, _file) != 1) {
		JANUS_LOG(
			LOG_WARN,
			"Failed to write frame to .mjr file (%s)\n",
			g_strerror(errno));

		JANUS_LOG(LOG_ERR, "Error saving frame...\n");

		_write_failed = true;

		return false;
	}

	fflush(_file);

	return true;
}

bool audio_recorder::save_eos()
{
	if(!is_open()) {
		return false;
	}

	if(!_header_saved && !save_header()) {
		return false;
	}

	if(!_write_failed) {
		if(fwrite(eos_header, sizeof(eos_header) - 1, 1, _file) != 1) {
			JANUS_LOG(
				LOG_WARN,
				"Failed to write EOS header to .mjr file (%s)\n",
				g_strerror(errno));
		}

		fflush(_file);
	}

	return true;
}

void audio_recorder::close() {
	if(_file) {
		save_eos();

		size_t fsize = ftell(_file);
		JANUS_LOG(LOG_INFO, "File is %zu bytes: %s\n", fsize, _recording_path.c_str());

		fclose(_file);
		_file = nullptr;
	}

	_extensions.clear();
	_header_saved = false;
	_started_at = 0;
	janus_rtp_switching_context_reset(&_rtp_context);
	_write_failed = false;
}

}
