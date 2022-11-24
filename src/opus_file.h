/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#pragma once

#include <string>

#include <stdio.h>

#include <glib.h>

#include <ogg/ogg.h>


namespace ptt_audiobridge
{

struct opus_file
{
public:
	enum class ReadResult {
		NotOpened,
		Success,
		Continue,
		Eof,
		OggSyncBufferFailed,
		OggSyncWroteFailed,
		OggStreamInitFailed,
		NoOpusStream,
		OggStreamPageinFailed,
	};

	opus_file() = default;
	opus_file(const opus_file& ) = delete;
	opus_file(const opus_file&& ) = delete;
	~opus_file();

	opus_file& operator = (const opus_file& ) = delete;
	opus_file& operator = (const opus_file&& ) = delete;

	bool is_open() const { return _file != nullptr; }
	bool open(const std::string& file_path);
	void close();

	ReadResult read_next_packet();
	ReadResult last_read_result() const { return _last_read_result; }
	const ogg_packet& last_read_packet() const { return _packet; }

private:
	ReadResult read();

private:
	enum class Stage {
		RawRead,
		SyncPageout,
		ReadPacket
	};

	std::string _file_path;
	FILE* _file = nullptr;

	Stage _stage = Stage::RawRead;
	ReadResult _last_read_result = ReadResult::NotOpened;

	ogg_sync_state _sync_state = {};
	ogg_stream_state _stream_state = {};
	ogg_page _page = {};
	ogg_packet _packet = {};

	gint _headers = 0;
};

}
