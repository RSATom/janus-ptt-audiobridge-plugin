/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "opus_file.h"

#include <cassert>

extern "C" {
#include "janus/debug.h"
}


namespace ptt_audiobridge
{

opus_file::~opus_file()
{
	close();
}

bool opus_file::open(const std::string& file_path)
{
	assert(!_file); // already opened
	if(_file) return false;

	assert(_last_read_result == ReadResult::NotOpened);

	_file = fopen(file_path.c_str(), "rb");
	if(!_file) {
		JANUS_LOG(LOG_ERR, "Error opening file\n");
		return false;
	}

	_file_path = file_path;

	if(ogg_sync_init(&_sync_state) < 0) {
		JANUS_LOG(LOG_ERR, "Error re-initializing Ogg sync state...\n");
		close();
		return false;
	}

	_last_read_result = ReadResult::Success;

	return true;
}

void opus_file::close()
{
	_file_path.clear();

	if(_file) {
		fclose(_file);
		_file = nullptr;
	}

	_stage = Stage::RawRead;
	_last_read_result = ReadResult::NotOpened;

	ogg_sync_clear(&_sync_state);
	ogg_stream_clear(&_stream_state);
	// according to docs for ogg_stream_packetout it's _stream_state owns memory pointed by _packet.
	// so just zero it
	_packet = {};
	_page = {};

	_headers = 0;
}

static bool ogg_is_opus(ogg_page* page)
{
	ogg_stream_state state;
	ogg_packet packet;
	ogg_stream_init(&state, ogg_page_serialno(page));
	ogg_stream_pagein(&state, page);
	if(ogg_stream_packetout(&state, &packet) == 1) {
		if(packet.bytes >= 19 && !memcmp(packet.packet, "OpusHead", 8)) {
			ogg_stream_clear(&state);
			return 1;
		}
	}
	ogg_stream_clear(&state);

	return false;
}

opus_file::ReadResult opus_file::read_next_packet()
{
	switch(_last_read_result) {
	case ReadResult::Success:
	case ReadResult::Continue: {
		_last_read_result = read();
		if(_last_read_result != ReadResult::Success)
			_packet = {};

		break;
	}
	default:
		break;
	}

	return _last_read_result;
}

/* Helper method to traverse the Opus file until we get a packet we can send */
opus_file::ReadResult opus_file::read()
{
	assert(_file);
	if(!_file) return ReadResult::NotOpened;

	/* Check our current state in processing the Ogg file */
	if(_stage == Stage::RawRead) {
		/* Prepare a buffer, and read from the Ogg file... */
		char* oggbuf = ogg_sync_buffer(&_sync_state, 8192);
		if(oggbuf == NULL) {
			JANUS_LOG(LOG_ERR, "ogg_sync_buffer failed...\n");
			return ReadResult::OggSyncBufferFailed;
		}

		const int bytes_read = fread(oggbuf, 1, 8192, _file);
		if(bytes_read == 0 && feof(_file)) {
			/* done */
			return ReadResult::Eof;
		}

		if(ogg_sync_wrote(&_sync_state, bytes_read) < 0) {
			JANUS_LOG(LOG_ERR, "ogg_sync_wrote failed...\n");
			return ReadResult::OggSyncWroteFailed;
		}
		/* Next state: sync pageout */
		_stage = Stage::SyncPageout;
	}

	if(_stage == Stage::SyncPageout) {
		int sync_state;
		/* Prepare an ogg_page out of the buffer */
		while((sync_state = ogg_sync_pageout(&_sync_state, &_page)) == 1) {
			/* Let's look for an Opus stream, first of all */
			if(_headers == 0) {
				if(ogg_is_opus(&_page)) {
					/* This is the start of an Opus stream */
					if(ogg_stream_init(&_stream_state, ogg_page_serialno(&_page)) < 0) {
						JANUS_LOG(LOG_ERR, "ogg_stream_init failed...\n");
						return ReadResult::OggStreamInitFailed;
					}
					_headers++;
				} else if(!ogg_page_bos(&_page)) {
					/* No Opus stream? */
					JANUS_LOG(LOG_ERR, "No Opus stream...\n");
					return ReadResult::NoOpusStream;
				} else {
					/* Still waiting for an Opus stream */
					return read();
				}
			}

			/* Submit the page for packetization */
			if(ogg_stream_pagein(&_stream_state, &_page) < 0) {
				JANUS_LOG(LOG_ERR, "ogg_stream_pagein failed...\n");
				return ReadResult::OggStreamPageinFailed;
			}

			/* Time to start reading packets */
			_stage = Stage::ReadPacket;
			break;
		}

		if(sync_state != 1) {
			/* Go back to reading from the file */
			_stage = Stage::RawRead;
			return read();
		}
	}

	if(_stage == Stage::ReadPacket) {
		/* Read and process available packets */
		if(ogg_stream_packetout(&_stream_state, &_packet) != 1) {
			/* Go back to reading pages */
			_stage = Stage::SyncPageout;
			return read();
		} else {
			/* Skip header packets */
			if(_headers == 1 && _packet.bytes >= 19 && !memcmp(_packet.packet, "OpusHead", 8)) {
				_headers++;
				return read();
			}
			if(_headers == 2 && _packet.bytes >= 16 && !memcmp(_packet.packet, "OpusTags", 8)) {
				_headers++;
				return read();
			}

			return ReadResult::Success;
		}
	}

	/* If we got here, continue with the iteration */
	return ReadResult::Continue;
}

}
