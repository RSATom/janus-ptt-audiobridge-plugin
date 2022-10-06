#include "janus_audiobridge_rtp_relay_packet.h"


namespace ptt_audioroom
{

/* Helper to sort incoming RTP packets by sequence numbers */
gint janus_audiobridge_rtp_sort(gconstpointer a, gconstpointer b) {
	janus_audiobridge_rtp_relay_packet *pkt1 = (janus_audiobridge_rtp_relay_packet *)a;
	janus_audiobridge_rtp_relay_packet *pkt2 = (janus_audiobridge_rtp_relay_packet *)b;
	if(pkt1->seq_number < 100 && pkt2->seq_number > 65000) {
		/* Sequence number was probably reset, pkt2 is older */
		return 1;
	} else if(pkt2->seq_number < 100 && pkt1->seq_number > 65000) {
		/* Sequence number was probably reset, pkt1 is older */
		return -1;
	}
	/* Simply compare timestamps */
	if(pkt1->seq_number < pkt2->seq_number)
		return -1;
	else if(pkt1->seq_number > pkt2->seq_number)
		return 1;
	return 0;
}

}
