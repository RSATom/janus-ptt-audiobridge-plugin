/*! \file
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#pragma once

#include <string>
#include <map>

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" {
#include "janus/mutex.h"
#include "janus/refcount.h"
#include "janus/rtp.h"
}

namespace ptt_audiobridge {

class audio_recorder {
public:
	audio_recorder(const std::string& recording_path, const std::string& codec);
	~audio_recorder();

	bool add_extmap(int id, const std::string& extmap);

	bool is_open() const { return _file != nullptr; }
	bool open();

	bool save_frame(void*, short);

private:
	bool save_header();
	bool save_eos();
	void close();

private:
	const std::string _recording_path;
	const std::string _codec;
	const gint64 _created_at;

	FILE* _file = nullptr;

	std::map<int, std::string> _extensions;

	bool _header_saved = false;
	gint64 _started_at = 0;

	janus_rtp_switching_context _rtp_context;

	bool _write_failed = false;
};

int audio_recorder_add_extmap(audio_recorder *recorder, int id, const char *extmap);
int audio_recorder_opusred(audio_recorder *recorder, int red_pt);
int audio_recorder_save_frame(audio_recorder *recorder, char *buffer, uint length);
int audio_recorder_close(audio_recorder *recorder);

}
