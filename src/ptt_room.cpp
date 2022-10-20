#include "ptt_room.h"

#include <type_traits>

#include <sys/socket.h>
#include <netinet/in.h>

#include "ptt_audioroom_plugin.h"


namespace ptt_audioroom
{

int create_udp_socket_if_needed(ptt_room *audiobridge) {
	if(audiobridge->rtp_udp_sock > 0) {
		return 0;
	}

	audiobridge->rtp_udp_sock = socket(!ipv6_disabled ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(audiobridge->rtp_udp_sock <= 0) {
		JANUS_LOG(LOG_ERR, "Could not open UDP socket for RTP forwarder (room %s), %d (%s)\n",
			audiobridge->room_id_str, errno, g_strerror(errno));
		return -1;
	}
	if(!ipv6_disabled) {
		int v6only = 0;
		if(setsockopt(audiobridge->rtp_udp_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
			JANUS_LOG(LOG_ERR, "Could not configure UDP socket for RTP forwarder (room %s), %d (%s))\n",
				audiobridge->room_id_str, errno, g_strerror(errno));
			return -1;
		}
	}

	return 0;
}

void ptt_room_destroy(ptt_room *audiobridge) {
	if(!audiobridge)
		return;
	if(!g_atomic_int_compare_and_exchange(&audiobridge->destroyed, 0, 1))
		return;
	/* Decrease the counter */
	janus_refcount_decrease(&audiobridge->ref);
}

void ptt_room_free(const janus_refcount *audiobridge_ref) {
	static_assert(std::is_standard_layout<ptt_room>::value);
	ptt_room *audiobridge =(ptt_room*)audiobridge_ref;
	/* This room can be destroyed, free all the resources */
	g_free(audiobridge->room_id_str);
	g_free(audiobridge->room_name);
	g_free(audiobridge->room_secret);
	g_free(audiobridge->room_pin);
	g_hash_table_destroy(audiobridge->participants);
	g_hash_table_destroy(audiobridge->allowed);
	if(audiobridge->rtp_udp_sock > 0)
		close(audiobridge->rtp_udp_sock);
	g_hash_table_destroy(audiobridge->rtp_forwarders);
	delete audiobridge;
}

}
