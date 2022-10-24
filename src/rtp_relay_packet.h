#pragma once

#include <glib.h>

extern "C" {
#include "janus/rtp.h"
}


namespace ptt_audiobridge
{

struct rtp_relay_packet {
	janus_rtp_header *data;
	gint length;
	uint32_t ssrc;
	uint32_t timestamp;
	uint16_t seq_number;
	gboolean silence;
};

gint rtp_sort(gconstpointer a, gconstpointer b);

}
