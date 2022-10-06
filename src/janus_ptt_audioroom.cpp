/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include <memory>

#include <glib.h>

extern "C" {
#include "plugin.h"
}

#include <jansson.h>
#include <opus/opus.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <poll.h>

extern "C" {
#include "janus/debug.h"
#include "janus/apierror.h"
#include "janus/config.h"
#include "janus/mutex.h"
#include "janus/rtp.h"
#include "janus/rtpsrtp.h"
#include "janus/rtcp.h"
#include "janus/sdp-utils.h"
#include "janus/utils.h"
#include "janus/ip-utils.h"
}

#include "janus_audiobridge_session.h"
#include "janus_audiobridge_room.h"
#include "janus_audiobridge_participant.h"
#include "janus_audiobridge_rtp_relay_packet.h"
#include "janus_audiobridge_rtp_forwarder.h"
#include "janus_audiobridge_message.h"
#include "record.h"
using namespace ptt_audioroom;

/* Plugin information */
#define JANUS_AUDIOBRIDGE_VERSION			12
#define JANUS_AUDIOBRIDGE_VERSION_STRING	"0.0.12"
#define JANUS_AUDIOBRIDGE_DESCRIPTION		""
#define JANUS_AUDIOBRIDGE_NAME				"JANUS PTT Audio Room plugin"
#define JANUS_AUDIOBRIDGE_AUTHOR			"Meetecho s.r.l. && Sergey Radionov <rsatom@gmail.com>"
#define JANUS_AUDIOBRIDGE_PACKAGE			"janus.plugin.ptt-audioroom"

#define MIN_SEQUENTIAL 						2
#define MAX_MISORDER						50

static const gint64 PTT_NO_AUDIO_TIMEOUT = 5; // seconds

/* Plugin methods */
extern "C" janus_plugin *create(void);
static int janus_audiobridge_init(janus_callbacks *callback, const char *config_path);
static void janus_audiobridge_destroy(void);
static int janus_audiobridge_get_api_compatibility(void);
static int janus_audiobridge_get_version(void);
static const char *janus_audiobridge_get_version_string(void);
static const char *janus_audiobridge_get_description(void);
static const char *janus_audiobridge_get_name(void);
static const char *janus_audiobridge_get_author(void);
static const char *janus_audiobridge_get_package(void);
static void janus_audiobridge_create_session(janus_plugin_session *handle, int *error);
static struct janus_plugin_result *janus_audiobridge_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
static json_t *janus_audiobridge_handle_admin_message(json_t *message);
static void janus_audiobridge_setup_media(janus_plugin_session *handle);
static void janus_audiobridge_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet);
static void janus_audiobridge_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet);
static void janus_audiobridge_hangup_media(janus_plugin_session *handle);
static void janus_audiobridge_destroy_session(janus_plugin_session *handle, int *error);
static json_t *janus_audiobridge_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_audiobridge_plugin =
	janus_plugin{
		.init = janus_audiobridge_init,
		.destroy = janus_audiobridge_destroy,

		.get_api_compatibility = janus_audiobridge_get_api_compatibility,
		.get_version = janus_audiobridge_get_version,
		.get_version_string = janus_audiobridge_get_version_string,
		.get_description = janus_audiobridge_get_description,
		.get_name = janus_audiobridge_get_name,
		.get_author = janus_audiobridge_get_author,
		.get_package = janus_audiobridge_get_package,

		.create_session = janus_audiobridge_create_session,
		.handle_message = janus_audiobridge_handle_message,
		.handle_admin_message = janus_audiobridge_handle_admin_message,
		.setup_media = janus_audiobridge_setup_media,
		.incoming_rtp = janus_audiobridge_incoming_rtp,
		.incoming_rtcp = janus_audiobridge_incoming_rtcp,
		.hangup_media = janus_audiobridge_hangup_media,
		.destroy_session = janus_audiobridge_destroy_session,
		.query_session = janus_audiobridge_query_session,
	};

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_AUDIOBRIDGE_NAME);
	return &janus_audiobridge_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter adminkey_parameters[] = {
	{"admin_key", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter roomstr_parameters[] = {
	{"room", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter roomstropt_parameters[] = {
	{"room", JSON_STRING, 0}
};
static struct janus_json_parameter idstr_parameters[] = {
	{"id", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter idstropt_parameters[] = {
	{"id", JSON_STRING, 0}
};
static struct janus_json_parameter create_parameters[] = {
	{"description", JSON_STRING, 0},
	{"secret", JSON_STRING, 0},
	{"pin", JSON_STRING, 0},
	{"is_private", JANUS_JSON_BOOL, 0},
	{"allowed", JSON_ARRAY, 0},
	{"sampling_rate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"sampling", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},	/* We keep this to be backwards compatible */
	{"spatial_audio", JANUS_JSON_BOOL, 0},
	{"mjrs", JANUS_JSON_BOOL, 0},
	{"mjrs_dir", JSON_STRING, 0},
	{"permanent", JANUS_JSON_BOOL, 0},
	{"audiolevel_ext", JANUS_JSON_BOOL, 0},
	{"audiolevel_event", JANUS_JSON_BOOL, 0},
	{"audio_active_packets", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_level_average", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"default_prebuffering", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"default_expectedloss", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"default_bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
};
static struct janus_json_parameter edit_parameters[] = {
	{"secret", JSON_STRING, 0},
	{"new_description", JSON_STRING, 0},
	{"new_secret", JSON_STRING, 0},
	{"new_pin", JSON_STRING, 0},
	{"new_is_private", JANUS_JSON_BOOL, 0},
	{"new_mjrs_dir", JSON_STRING, 0},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter destroy_parameters[] = {
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter allowed_parameters[] = {
	{"secret", JSON_STRING, 0},
	{"action", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"allowed", JSON_ARRAY, 0}
};
static struct janus_json_parameter secret_parameters[] = {
	{"secret", JSON_STRING, 0}
};
static struct janus_json_parameter join_parameters[] = {
	{"display", JSON_STRING, 0},
	{"token", JSON_STRING, 0},
	{"prebuffer", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"quality", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"expected_loss", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"volume", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"spatial_position", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_level_average", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_active_packets", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"generate_offer", JANUS_JSON_BOOL, 0},
	{"secret", JSON_STRING, 0}
};
static struct janus_json_parameter mjrs_parameters[] = {
	{"mjrs", JANUS_JSON_BOOL, JANUS_JSON_PARAM_REQUIRED},
	{"mjrs_dir", JSON_STRING, 0}
};
static struct janus_json_parameter configure_parameters[] = {
	{"prebuffer", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"quality", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"expected_loss", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"volume", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"spatial_position", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"display", JSON_STRING, 0},
	{"generate_offer", JANUS_JSON_BOOL, 0},
	{"update", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter rtp_forward_parameters[] = {
	{"ssrc", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"ptype", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"port", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"host", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"host_family", JSON_STRING, 0},
	{"srtp_suite", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"srtp_crypto", JSON_STRING, 0},
	{"always_on", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter stop_rtp_forward_parameters[] = {
	{"stream_id", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter checkstop_file_parameters[] = {
	{"file_id", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};

/* Static configuration instance */
static janus_config *config = NULL;
static const char *config_folder = NULL;
static janus_mutex config_mutex = JANUS_MUTEX_INITIALIZER;

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static gboolean ipv6_disabled = FALSE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_audiobridge_handler(void *data);
static void janus_audiobridge_relay_rtp_packet(gpointer data, gpointer user_data);
static void *janus_audiobridge_mixer_thread(void *data);
static void *janus_audiobridge_participant_thread(void *data);
static void janus_audiobridge_hangup_media_internal(janus_plugin_session *handle);

static GAsyncQueue *messages = NULL;

static GHashTable *rooms;
static janus_mutex rooms_mutex = JANUS_MUTEX_INITIALIZER;
static char *admin_key = NULL;
static gboolean lock_rtpfwd = FALSE;

static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;


static guint32 janus_audiobridge_rtp_forwarder_add_helper(janus_audiobridge_room *room,
		const gchar *host, uint16_t port, uint32_t ssrc, int pt,
		int srtp_suite, const char *srtp_crypto,
		gboolean always_on, guint32 stream_id) {
	if(room == NULL || host == NULL)
		return 0;
	janus_audiobridge_rtp_forwarder *rf = (janus_audiobridge_rtp_forwarder *)g_malloc0(sizeof(janus_audiobridge_rtp_forwarder));
	/* First of all, let's check if we need to setup an SRTP forwarder */
	if(srtp_suite > 0 && srtp_crypto != NULL) {
		/* Base64 decode the crypto string and set it as the SRTP context */
		gsize len = 0;
		guchar *decoded = g_base64_decode(srtp_crypto, &len);
		if(len < SRTP_MASTER_LENGTH) {
			JANUS_LOG(LOG_ERR, "Invalid SRTP crypto (%s)\n", srtp_crypto);
			g_free(decoded);
			g_free(rf);
			return 0;
		}
		/* Set SRTP policy */
		srtp_policy_t *policy = &rf->srtp_policy;
		srtp_crypto_policy_set_rtp_default(&(policy->rtp));
		if(srtp_suite == 32) {
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy->rtp));
		} else if(srtp_suite == 80) {
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtp));
		}
		policy->ssrc.type = ssrc_any_outbound;
		policy->key = decoded;
		policy->next = NULL;
		/* Create SRTP context */
		srtp_err_status_t res = srtp_create(&rf->srtp_ctx, policy);
		if(res != srtp_err_status_ok) {
			/* Something went wrong... */
			JANUS_LOG(LOG_ERR, "Error creating forwarder SRTP session: %d (%s)\n", res, janus_srtp_error_str(res));
			g_free(decoded);
			policy->key = NULL;
			g_free(rf);
			return 0;
		}
		rf->is_srtp = TRUE;
	}
	/* Check if the host address is IPv4 or IPv6 */
	if(strstr(host, ":") != NULL) {
		rf->serv_addr6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, host, &(rf->serv_addr6.sin6_addr));
		rf->serv_addr6.sin6_port = htons(port);
	} else {
		rf->serv_addr.sin_family = AF_INET;
		inet_pton(AF_INET, host, &(rf->serv_addr.sin_addr));
		rf->serv_addr.sin_port = htons(port);
	}
	/* Setup RTP info (we'll use the stream ID as SSRC) */
	rf->ssrc = ssrc;
	rf->payload_type = pt;
	rf->seq_number = 0;
	rf->timestamp = 0;
	rf->always_on = always_on;

	janus_mutex_lock(&room->rtp_mutex);

	guint32 actual_stream_id;
	if(stream_id > 0) {
		actual_stream_id = stream_id;
	} else {
		actual_stream_id = janus_random_uint32();
	}

	while(g_hash_table_lookup(room->rtp_forwarders, GUINT_TO_POINTER(actual_stream_id)) != NULL) {
		actual_stream_id = janus_random_uint32();
	}
	janus_refcount_init(&rf->ref, janus_audiobridge_rtp_forwarder_free);
	g_hash_table_insert(room->rtp_forwarders, GUINT_TO_POINTER(actual_stream_id), rf);

	janus_mutex_unlock(&room->rtp_mutex);

	JANUS_LOG(LOG_VERB, "Added RTP forwarder to room %s: %s:%d (ID: %" SCNu32 ")\n",
		room->room_id_str, host, port, actual_stream_id);

	return actual_stream_id;
}


/* Mixer settings */
#define DEFAULT_PREBUFFERING	6
#define MAX_PREBUFFERING		50


/* Opus settings */
#define	OPUS_SAMPLES	960
#define	BUFFER_SAMPLES	OPUS_SAMPLES*12
#define DEFAULT_COMPLEXITY	4


/* Error codes */
#define JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR	499
#define JANUS_AUDIOBRIDGE_ERROR_NO_MESSAGE		480
#define JANUS_AUDIOBRIDGE_ERROR_INVALID_JSON	481
#define JANUS_AUDIOBRIDGE_ERROR_INVALID_REQUEST	482
#define JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT	483
#define JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT	484
#define JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM	485
#define JANUS_AUDIOBRIDGE_ERROR_ROOM_EXISTS		486
#define JANUS_AUDIOBRIDGE_ERROR_NOT_JOINED		487
#define JANUS_AUDIOBRIDGE_ERROR_LIBOPUS_ERROR	488
#define JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED	489
#define JANUS_AUDIOBRIDGE_ERROR_ID_EXISTS		490
#define JANUS_AUDIOBRIDGE_ERROR_ALREADY_JOINED	491
#define JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_USER	492
#define JANUS_AUDIOBRIDGE_ERROR_INVALID_SDP		493
#define JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_GROUP	494
#define JANUS_AUDIOBRIDGE_ERROR_ROOM_ALREADY_HAS_UNMUTED_USER	600

static int janus_audiobridge_create_udp_socket_if_needed(janus_audiobridge_room *audiobridge) {
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

static int janus_audiobridge_create_opus_encoder_if_needed(janus_audiobridge_room *audiobridge) {
	if(audiobridge->rtp_encoder != NULL) {
		return 0;
	}

	int error = 0;
	audiobridge->rtp_encoder = opus_encoder_create(audiobridge->sampling_rate,
		audiobridge->spatial_audio ? 2 : 1, OPUS_APPLICATION_VOIP, &error);
	if(error != OPUS_OK) {
		JANUS_LOG(LOG_ERR, "Error creating Opus encoder for RTP forwarder (room %s)\n", audiobridge->room_id_str);
		return -1;
	}

	if(audiobridge->sampling_rate == 8000) {
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
	} else if(audiobridge->sampling_rate == 12000) {
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_MEDIUMBAND));
	} else if(audiobridge->sampling_rate == 16000) {
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
	} else if(audiobridge->sampling_rate == 24000) {
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_SUPERWIDEBAND));
	} else if(audiobridge->sampling_rate == 48000) {
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND));
	} else {
		JANUS_LOG(LOG_WARN, "Unsupported sampling rate %d, setting 16kHz\n", audiobridge->sampling_rate);
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
	}

	/* Check if we need FEC */
	if(audiobridge->default_expectedloss > 0) {
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_INBAND_FEC(TRUE));
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_PACKET_LOSS_PERC(audiobridge->default_expectedloss));
	}
	/* Also check if we need to enforce a bitrate */
	if(audiobridge->default_bitrate > 0)
		opus_encoder_ctl(audiobridge->rtp_encoder, OPUS_SET_BITRATE(audiobridge->default_bitrate));

	return 0;
}

static int janus_audiobridge_create_static_rtp_forwarder(janus_config_category *cat, janus_audiobridge_room *audiobridge) {
	guint32 forwarder_id = 0;
	janus_config_item *forwarder_id_item = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_id");
	if(forwarder_id_item != NULL && forwarder_id_item->value != NULL &&
			janus_string_to_uint32(forwarder_id_item->value, &forwarder_id) < 0) {
		JANUS_LOG(LOG_ERR, "Invalid forwarder ID\n");
		return 0;
	}

	guint32 ssrc_value = 0;
	janus_config_item *ssrc = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_ssrc");
	if(ssrc != NULL && ssrc->value != NULL && janus_string_to_uint32(ssrc->value, &ssrc_value) < 0) {
		JANUS_LOG(LOG_ERR, "Invalid SSRC (%s)\n", ssrc->value);
		return 0;
	}

	int ptype = 100;
	janus_config_item *pt = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_ptype");
	if(pt != NULL && pt->value != NULL) {
		ptype = atoi(pt->value);
		if(ptype < 0 || ptype > 127) {
			JANUS_LOG(LOG_ERR, "Invalid payload type (%s)\n", pt->value);
			return 0;
		}
	}

	janus_config_item *port_item = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_port");
	uint16_t port = 0;
	if(port_item != NULL && port_item->value != NULL && janus_string_to_uint16(port_item->value, &port) < 0) {
		JANUS_LOG(LOG_ERR, "Invalid port (%s)\n", port_item->value);
		return 0;
	}
	if(port == 0) {
		return 0;
	}

	janus_config_item *host_item = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_host");
	if(host_item == NULL || host_item->value == NULL || strlen(host_item->value) == 0) {
		return 0;
	}
	const char *host = host_item->value, *resolved_host = NULL;
	int family = 0;
	janus_config_item *host_family_item = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_host_family");
	if(host_family_item != NULL && host_family_item->value != NULL) {
		const char *host_family = host_family_item->value;
		if(host_family) {
			if(!strcasecmp(host_family, "ipv4")) {
				family = AF_INET;
			} else if(!strcasecmp(host_family, "ipv6")) {
				family = AF_INET6;
			} else {
				JANUS_LOG(LOG_ERR, "Unsupported protocol family (%s)\n", host_family);
				return 0;
			}
		}
	}
	/* Check if we need to resolve this host address */
	struct addrinfo *res = NULL, *start = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	if(family != 0)
		hints.ai_family = family;
	if(getaddrinfo(host, NULL, family != 0 ? &hints : NULL, &res) == 0) {
		start = res;
		while(res != NULL) {
			if(janus_network_address_from_sockaddr(res->ai_addr, &addr) == 0 &&
					janus_network_address_to_string_buffer(&addr, &addr_buf) == 0) {
				/* Resolved */
				resolved_host = janus_network_address_string_from_buffer(&addr_buf);
				freeaddrinfo(start);
				start = NULL;
				break;
			}
			res = res->ai_next;
		}
	}
	if(resolved_host == NULL) {
		if(start)
			freeaddrinfo(start);
		JANUS_LOG(LOG_ERR, "Could not resolve address (%s)...\n", host);
		return 0;
	}
	host = resolved_host;

	/* We may need to SRTP-encrypt this stream */
	int srtp_suite = 0;
	const char *srtp_crypto = NULL;
	janus_config_item *s_suite = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_srtp_suite");
	janus_config_item *s_crypto = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_srtp_crypto");
	if(s_suite && s_suite->value) {
		srtp_suite = atoi(s_suite->value);
		if(srtp_suite != 32 && srtp_suite != 80) {
			JANUS_LOG(LOG_ERR, "Can't add static RTP forwarder for room %s, invalid SRTP suite...\n", audiobridge->room_id_str);
			return 0;
		}
		if(s_crypto && s_crypto->value)
			srtp_crypto = s_crypto->value;
	}

	janus_config_item *always_on_item = janus_config_get(config, cat, janus_config_type_item, "rtp_forward_always_on");
	gboolean always_on = FALSE;
	if(always_on_item != NULL && always_on_item->value != NULL && strlen(always_on_item->value) > 0) {
		always_on = janus_is_true(always_on_item->value);
	}

	/* Update room */
	janus_mutex_lock(&rooms_mutex);
	janus_mutex_lock(&audiobridge->mutex);

	if(janus_audiobridge_create_udp_socket_if_needed(audiobridge)) {
		janus_mutex_unlock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);
		return -1;
	}

	if(janus_audiobridge_create_opus_encoder_if_needed(audiobridge)) {
		janus_mutex_unlock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);
		return -1;
	}

	janus_audiobridge_rtp_forwarder_add_helper(audiobridge,
		host, port, ssrc_value, ptype, srtp_suite, srtp_crypto,
		always_on, forwarder_id);

	janus_mutex_unlock(&audiobridge->mutex);
	janus_mutex_unlock(&rooms_mutex);

	return 0;
}

/* Plugin implementation */
int janus_audiobridge_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_AUDIOBRIDGE_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_AUDIOBRIDGE_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_AUDIOBRIDGE_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	config_folder = config_path;
	if(config != NULL)
		janus_config_print(config);

	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_audiobridge_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) janus_audiobridge_message_free);
	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	/* Parse configuration to populate the rooms list */
	if(config != NULL) {
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		/* Any admin key to limit who can "create"? */
		janus_config_item *key = janus_config_get(config, config_general, janus_config_type_item, "admin_key");
		if(key != NULL && key->value != NULL)
			admin_key = g_strdup(key->value);
		janus_config_item *lrf = janus_config_get(config, config_general, janus_config_type_item, "lock_rtp_forward");
		if(admin_key && lrf != NULL && lrf->value != NULL)
			lock_rtpfwd = janus_is_true(lrf->value);
		janus_config_item *events = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(events != NULL && events->value != NULL)
			notify_events = janus_is_true(events->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_AUDIOBRIDGE_NAME);
		}
	}

	/* Iterate on all rooms */
	rooms = g_hash_table_new_full(g_str_hash, g_str_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)janus_audiobridge_room_destroy);
	if(config != NULL) {
		GList *clist = janus_config_get_categories(config, NULL), *cl = clist;
		while(cl != NULL) {
			janus_config_category *cat = (janus_config_category *)cl->data;
			if(cat->name == NULL || !strcasecmp(cat->name, "general")) {
				cl = cl->next;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Adding AudioBridge room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get(config, cat, janus_config_type_item, "description");
			janus_config_item *priv = janus_config_get(config, cat, janus_config_type_item, "is_private");
			janus_config_item *sampling = janus_config_get(config, cat, janus_config_type_item, "sampling_rate");
			janus_config_item *spatial = janus_config_get(config, cat, janus_config_type_item, "spatial_audio");
			janus_config_item *audiolevel_ext = janus_config_get(config, cat, janus_config_type_item, "audiolevel_ext");
			janus_config_item *audiolevel_event = janus_config_get(config, cat, janus_config_type_item, "audiolevel_event");
			janus_config_item *audio_active_packets = janus_config_get(config, cat, janus_config_type_item, "audio_active_packets");
			janus_config_item *audio_level_average = janus_config_get(config, cat, janus_config_type_item, "audio_level_average");
			janus_config_item *default_prebuffering = janus_config_get(config, cat, janus_config_type_item, "default_prebuffering");
			janus_config_item *default_expectedloss = janus_config_get(config, cat, janus_config_type_item, "default_expectedloss");
			janus_config_item *default_bitrate = janus_config_get(config, cat, janus_config_type_item, "default_bitrate");
			janus_config_item *secret = janus_config_get(config, cat, janus_config_type_item, "secret");
			janus_config_item *pin = janus_config_get(config, cat, janus_config_type_item, "pin");
			janus_config_item *mjrs = janus_config_get(config, cat, janus_config_type_item, "mjrs");
			janus_config_item *mjrsdir = janus_config_get(config, cat, janus_config_type_item, "mjrs_dir");
			if(sampling == NULL || sampling->value == NULL) {
				JANUS_LOG(LOG_ERR, "Can't add the AudioBridge room, missing mandatory information...\n");
				cl = cl->next;
				continue;
			}
			/* Create the AudioBridge room */
			janus_audiobridge_room *audiobridge = new janus_audiobridge_room {};
			janus_refcount_init(&audiobridge->ref, janus_audiobridge_room_free);
			const char *room_num = cat->name;
			if(strstr(room_num, "room-") == room_num)
				room_num += 5;
			/* Let's make sure the room doesn't exist already */
			janus_mutex_lock(&rooms_mutex);
			if(g_hash_table_lookup(rooms, (gpointer)room_num) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Can't add the AudioBridge room, room %s already exists...\n", room_num);
				janus_audiobridge_room_destroy(audiobridge);
				cl = cl->next;
				continue;
			}
			janus_mutex_unlock(&rooms_mutex);
			audiobridge->room_id_str = g_strdup(room_num);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL && strlen(desc->value) > 0)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			audiobridge->room_name = description;
			audiobridge->is_private = priv && priv->value && janus_is_true(priv->value);
			audiobridge->sampling_rate = atol(sampling->value);
			switch(audiobridge->sampling_rate) {
				case 8000:
				case 12000:
				case 16000:
				case 24000:
				case 48000:
					JANUS_LOG(LOG_VERB, "Sampling rate for mixing: %" SCNu32 "\n", audiobridge->sampling_rate);
					break;
				default:
					JANUS_LOG(LOG_ERR, "Unsupported sampling rate %" SCNu32 "...\n", audiobridge->sampling_rate);
					janus_audiobridge_room_destroy(audiobridge);
					cl = cl->next;
					continue;
			}
			audiobridge->spatial_audio = spatial && spatial->value && janus_is_true(spatial->value);
			audiobridge->audiolevel_ext = TRUE;
			if(audiolevel_ext != NULL && audiolevel_ext->value != NULL)
				audiobridge->audiolevel_ext = janus_is_true(audiolevel_ext->value);
			audiobridge->audiolevel_event = FALSE;
			if(audiolevel_event != NULL && audiolevel_event->value != NULL)
				audiobridge->audiolevel_event = janus_is_true(audiolevel_event->value);
			if(audiobridge->audiolevel_event) {
				audiobridge->audio_active_packets = 100;
				if(audio_active_packets != NULL && audio_active_packets->value != NULL){
					if(atoi(audio_active_packets->value) > 0) {
						audiobridge->audio_active_packets = atoi(audio_active_packets->value);
					} else {
						JANUS_LOG(LOG_WARN, "Invalid audio_active_packets value provided, using default: %d\n", audiobridge->audio_active_packets);
					}
				}
				audiobridge->audio_level_average = 25;
				if(audio_level_average != NULL && audio_level_average->value != NULL) {
					if(atoi(audio_level_average->value) > 0) {
						audiobridge->audio_level_average = atoi(audio_level_average->value);
					} else {
						JANUS_LOG(LOG_WARN, "Invalid audio_level_average value provided, using default: %d\n", audiobridge->audio_level_average);
					}
				}
			}
			audiobridge->default_prebuffering = DEFAULT_PREBUFFERING;
			if(default_prebuffering != NULL && default_prebuffering->value != NULL) {
				int prebuffering = atoi(default_prebuffering->value);
				if(prebuffering < 0 || prebuffering > MAX_PREBUFFERING) {
					JANUS_LOG(LOG_WARN, "Invalid default_prebuffering value provided, using default: %d\n", audiobridge->default_prebuffering);
				} else {
					audiobridge->default_prebuffering = prebuffering;
				}
			}
			audiobridge->default_expectedloss = 0;
			if(default_expectedloss != NULL && default_expectedloss->value != NULL) {
				int expectedloss = atoi(default_expectedloss->value);
				if(expectedloss < 0 || expectedloss > 20) {
					JANUS_LOG(LOG_WARN, "Invalid expectedloss value provided, using default: 0\n");
				} else {
					audiobridge->default_expectedloss = expectedloss;
				}
			}
			audiobridge->default_bitrate = 0;
			if(default_bitrate != NULL && default_bitrate->value != NULL) {
				audiobridge->default_bitrate = atoi(default_bitrate->value);
				if(audiobridge->default_bitrate < 500 || audiobridge->default_bitrate > 512000) {
					JANUS_LOG(LOG_WARN, "Invalid bitrate %" SCNi32 ", falling back to auto\n", audiobridge->default_bitrate);
					audiobridge->default_bitrate = 0;
				}
			}
			audiobridge->room_ssrc = janus_random_uint32();
			if(secret != NULL && secret->value != NULL) {
				audiobridge->room_secret = g_strdup(secret->value);
			}
			if(pin != NULL && pin->value != NULL) {
				audiobridge->room_pin = g_strdup(pin->value);
			}
			if(mjrs && mjrs->value && janus_is_true(mjrs->value))
				audiobridge->mjrs = TRUE;
			if(mjrsdir && mjrsdir->value)
				audiobridge->mjrs_dir = g_strdup(mjrsdir->value);
			audiobridge->destroy = 0;
			audiobridge->participants = g_hash_table_new_full(
				g_str_hash, g_str_equal,
				(GDestroyNotify)g_free, (GDestroyNotify)janus_audiobridge_participant_unref);
			audiobridge->check_tokens = FALSE;	/* Static rooms can't have an "allowed" list yet, no hooks to the configuration file */
			audiobridge->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
			g_atomic_int_set(&audiobridge->destroyed, 0);
			janus_mutex_init(&audiobridge->mutex);
			audiobridge->rtp_forwarders = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_audiobridge_rtp_forwarder_destroy);
			audiobridge->rtp_encoder = NULL;
			audiobridge->rtp_udp_sock = -1;
			janus_mutex_init(&audiobridge->rtp_mutex);
			JANUS_LOG(LOG_VERB, "Created AudioBridge room: %s (%s, %s, secret: %s, pin: %s)\n",
				audiobridge->room_id_str, audiobridge->room_name,
				audiobridge->is_private ? "private" : "public",
				audiobridge->room_secret ? audiobridge->room_secret : "no secret",
				audiobridge->room_pin ? audiobridge->room_pin : "no pin");

			if(janus_audiobridge_create_static_rtp_forwarder(cat, audiobridge)) {
				JANUS_LOG(LOG_ERR, "Error creating static RTP forwarder (room %s)\n", audiobridge->room_id_str);
			}

			/* We need a thread for the mix */
			GError *error = NULL;
			char tname[16];
			g_snprintf(tname, sizeof(tname), "mixer %s", audiobridge->room_id_str);
			janus_refcount_increase(&audiobridge->ref);
			audiobridge->thread = g_thread_try_new(tname, &janus_audiobridge_mixer_thread, audiobridge, &error);
			if(error != NULL) {
				/* FIXME We should clear some resources... */
				janus_refcount_decrease(&audiobridge->ref);
				JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the mixer thread...\n",
					error->code, error->message ? error->message : "??");
				g_error_free(error);
			} else {
				janus_mutex_lock(&rooms_mutex);
				g_hash_table_insert(rooms,
					(gpointer)g_strdup(audiobridge->room_id_str),
					audiobridge);
				janus_mutex_unlock(&rooms_mutex);
			}
			cl = cl->next;
		}
		g_list_free(clist);
		/* Done: we keep the configuration file open in case we get a "create" or "destroy" with permanent=true */
	}

	/* Show available rooms */
	janus_mutex_lock(&rooms_mutex);
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, rooms);
	while(g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_audiobridge_room *ar = (janus_audiobridge_room *)value;
		JANUS_LOG(LOG_VERB, "  ::: [%s][%s] %" SCNu32 "\n",
			ar->room_id_str, ar->room_name, ar->sampling_rate);
	}
	janus_mutex_unlock(&rooms_mutex);

	/* Finally, let's check if IPv6 is disabled, as we may need to know for forwarders */
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if(fd <= 0) {
		ipv6_disabled = TRUE;
	} else {
		int v6only = 0;
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0)
			ipv6_disabled = TRUE;
	}
	if(fd > 0)
		close(fd);
	if(ipv6_disabled) {
		JANUS_LOG(LOG_WARN, "IPv6 disabled, will only create VideoRoom forwarders to IPv4 addresses\n");
	}

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("audiobridge handler", janus_audiobridge_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the AudioBridge handler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		janus_config_destroy(config);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_AUDIOBRIDGE_NAME);
	return 0;
}

void janus_audiobridge_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);
	janus_mutex_lock(&rooms_mutex);
	g_hash_table_destroy(rooms);
	rooms = NULL;
	janus_mutex_unlock(&rooms_mutex);
	g_async_queue_unref(messages);
	messages = NULL;

	janus_config_destroy(config);
	g_free(admin_key);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_AUDIOBRIDGE_NAME);
}

int janus_audiobridge_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_audiobridge_get_version(void) {
	return JANUS_AUDIOBRIDGE_VERSION;
}

const char *janus_audiobridge_get_version_string(void) {
	return JANUS_AUDIOBRIDGE_VERSION_STRING;
}

const char *janus_audiobridge_get_description(void) {
	return JANUS_AUDIOBRIDGE_DESCRIPTION;
}

const char *janus_audiobridge_get_name(void) {
	return JANUS_AUDIOBRIDGE_NAME;
}

const char *janus_audiobridge_get_author(void) {
	return JANUS_AUDIOBRIDGE_AUTHOR;
}

const char *janus_audiobridge_get_package(void) {
	return JANUS_AUDIOBRIDGE_PACKAGE;
}

static janus_audiobridge_session *janus_audiobridge_lookup_session(janus_plugin_session *handle) {
	janus_audiobridge_session *session = NULL;
	if(g_hash_table_contains(sessions, handle)) {
		session = (janus_audiobridge_session *)handle->plugin_handle;
	}
	return session;
}

void janus_audiobridge_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_audiobridge_session *session = (janus_audiobridge_session *)g_malloc0(sizeof(janus_audiobridge_session));
	session->handle = handle;
	g_atomic_int_set(&session->started, 0);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	handle->plugin_handle = session;
	janus_refcount_init(&session->ref, janus_audiobridge_session_free);

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_audiobridge_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_audiobridge_session *session = janus_audiobridge_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No AudioBridge session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing AudioBridge session...\n");
	janus_audiobridge_hangup_media_internal(handle);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

static void janus_audiobridge_notify_participants(janus_audiobridge_participant *participant, json_t *msg, gboolean notify_source_participant) {
	/* participant->room->participants_mutex has to be locked. */
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, participant->room->participants);
	while(!participant->room->destroyed && g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
		if(p && p->session && (p != participant || notify_source_participant)) {
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, msg, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
	}
}

json_t *janus_audiobridge_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_audiobridge_session *session = janus_audiobridge_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* Show the participant/room info, if any */
	json_t *info = json_object();
	janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
	json_object_set_new(info, "state", json_string(participant && participant->room ? "inroom" : "idle"));
	if(participant) {
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *room = participant->room;
		if(room != NULL)
			json_object_set_new(info, "room", json_string(room->room_id_str));
		janus_mutex_unlock(&rooms_mutex);
		json_object_set_new(info, "id", json_string(participant->user_id_str));
		if(participant->display)
			json_object_set_new(info, "display", json_string(participant->display));
		if(participant->admin)
			json_object_set_new(info, "admin", json_true());
		json_object_set_new(info, "muted", participant->muted ? json_true() : json_false());
		json_object_set_new(info, "active", g_atomic_int_get(&participant->active) ? json_true() : json_false());
		json_object_set_new(info, "pre-buffering", participant->prebuffering ? json_true() : json_false());
		json_object_set_new(info, "prebuffer-count", json_integer(participant->prebuffer_count));
		if(participant->inbuf) {
			janus_mutex_lock(&participant->qmutex);
			json_object_set_new(info, "queue-in", json_integer(g_list_length(participant->inbuf)));
			janus_mutex_unlock(&participant->qmutex);
		}
		if(participant->outbuf)
			json_object_set_new(info, "queue-out", json_integer(g_async_queue_length(participant->outbuf)));
		if(participant->last_drop > 0)
			json_object_set_new(info, "last-drop", json_integer(participant->last_drop));
		if(participant->stereo)
			json_object_set_new(info, "spatial_position", json_integer(participant->spatial_position));
		if(participant->arc && participant->arc->filename)
			json_object_set_new(info, "audio-recording", json_string(participant->arc->filename));
		if(participant->extmap_id > 0) {
			json_object_set_new(info, "audio-level-dBov", json_integer(participant->dBov_level));
			json_object_set_new(info, "talking", participant->talking ? json_true() : json_false());
		}
		json_object_set_new(info, "fec", participant->fec ? json_true() : json_false());
		if(participant->fec)
			json_object_set_new(info, "expected-loss", json_integer(participant->expected_loss));
		if(participant->opus_bitrate)
			json_object_set_new(info, "opus-bitrate", json_integer(participant->opus_bitrate));
	}
	if(session->plugin_offer)
		json_object_set_new(info, "plugin-offer", json_true());
	json_object_set_new(info, "started", g_atomic_int_get(&session->started) ? json_true() : json_false());
	json_object_set_new(info, "hangingup", g_atomic_int_get(&session->hangingup) ? json_true() : json_false());
	json_object_set_new(info, "destroyed", g_atomic_int_get(&session->destroyed) ? json_true() : json_false());
	janus_refcount_decrease(&session->ref);
	return info;
}

static int janus_audiobridge_access_room(json_t *root, gboolean check_modify, janus_audiobridge_room **audiobridge, char *error_cause, int error_cause_size) {
	/* rooms_mutex has to be locked */
	int error_code = 0;
	json_t *room = json_object_get(root, "room");
	char room_id_num[30], *room_id_str = NULL;
	room_id_str = (char *)json_string_value(room);
	*audiobridge = (janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
	if(*audiobridge == NULL) {
		JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
		error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
		if(error_cause)
			g_snprintf(error_cause, error_cause_size, "No such room (%s)", room_id_str);
		return error_code;
	}
	if(g_atomic_int_get(&((*audiobridge)->destroyed))) {
		JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
		error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
		if(error_cause)
			g_snprintf(error_cause, error_cause_size, "No such room (%s)", room_id_str);
		return error_code;
	}
	if(check_modify) {
		char error_cause2[100];
		JANUS_CHECK_SECRET((*audiobridge)->room_secret, root, "secret", error_code, error_cause2,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			g_strlcpy(error_cause, error_cause2, error_cause_size);
			return error_code;
		}
	}
	return 0;
}

static void mute_participant(
	janus_audiobridge_session *session,
	janus_audiobridge_participant *participant,
	gboolean mute,
	gboolean self_notify,
	gboolean lock_qmutex)
{
	if(participant->muted == mute)
		return;

	janus_audiobridge_room *audiobridge = participant->room;

	JANUS_LOG(LOG_VERB, "Setting muted property: %s (room %s, user %s)\n",
		mute ? "true" : "false", participant->room->room_id_str, participant->user_id_str);
	participant->muted = mute;
	if(participant->muted) {
		audiobridge->unmutedParticipant = NULL;
		/* Clear the queued packets waiting to be handled */
		if(lock_qmutex) janus_mutex_lock(&participant->qmutex);
		while(participant->inbuf) {
			GList *first = g_list_first(participant->inbuf);
			janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)first->data;
			participant->inbuf = g_list_delete_link(participant->inbuf, first);
			first = NULL;
			if(pkt == NULL)
				continue;
			if(pkt->data)
				g_free(pkt->data);
			pkt->data = NULL;
			g_free(pkt);
			pkt = NULL;
		}
		if(lock_qmutex) janus_mutex_unlock(&participant->qmutex);
	} else {
		gint64 now = janus_get_monotonic_time();
		audiobridge->unmutedParticipant = participant;
		participant->unmuted_timestamp = now;
	}

	/* Notify all other participants about the mute/unmute */
	json_t *participantInfo = json_object();
	json_object_set_new(participantInfo, "id", json_string(participant->user_id_str));
	if(participant->display)
		json_object_set_new(participantInfo, "display", json_string(participant->display));

	json_t *pub = json_object();
	json_object_set_new(pub, "audiobridge", participant->muted ? json_string("muted") : json_string("unmuted"));
	json_object_set_new(pub, "room", json_string(participant->room->room_id_str));
	json_object_set(pub, "participant", participantInfo);

	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, audiobridge->participants);
	while(g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
		if(!self_notify && p == participant) {
			continue;	/* Skip participant itself */
		}
		JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n",
			p->user_id_str, p->display ? p->display : "??");
		int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, pub, NULL);
		JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	}
	json_decref(pub);

	/* Also notify event handlers */
	if(notify_events && gateway->events_is_enabled()) {
		janus_audiobridge_room *audiobridge = participant->room;
		json_t *info = json_object();
		json_object_set_new(info, "event", participant->muted ? json_string("muted") : json_string("unmuted"));
		json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
		json_object_set(info, "participant", participantInfo);

		gateway->notify_event(&janus_audiobridge_plugin, session ? session->handle : NULL, info);
	}
	json_decref(participantInfo);
}

/* Helper method to process synchronous requests */
static json_t *janus_audiobridge_process_synchronous_request(janus_audiobridge_session *session, json_t *message) {
	json_t *request = json_object_get(message, "request");
	const char *request_text = json_string_value(request);

	/* Parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	if(!strcasecmp(request_text, "create")) {
		/* Create a new AudioBridge */
		JANUS_LOG(LOG_VERB, "Creating a new AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, create_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstropt_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto prepare_response;
		}
		json_t *desc = json_object_get(root, "description");
		json_t *secret = json_object_get(root, "secret");
		json_t *pin = json_object_get(root, "pin");
		json_t *is_private = json_object_get(root, "is_private");
		json_t *allowed = json_object_get(root, "allowed");
		json_t *sampling = json_object_get(root, "sampling_rate");
		if(sampling == NULL)
			sampling = json_object_get(root, "sampling");
		json_t *spatial = json_object_get(root, "spatial_audio");
		json_t *audiolevel_ext = json_object_get(root, "audiolevel_ext");
		json_t *audiolevel_event = json_object_get(root, "audiolevel_event");
		json_t *audio_active_packets = json_object_get(root, "audio_active_packets");
		json_t *audio_level_average = json_object_get(root, "audio_level_average");
		json_t *default_prebuffering = json_object_get(root, "default_prebuffering");
		json_t *default_expectedloss = json_object_get(root, "default_expectedloss");
		json_t *default_bitrate = json_object_get(root, "default_bitrate");
		json_t *mjrs = json_object_get(root, "mjrs");
		json_t *mjrsdir = json_object_get(root, "mjrs_dir");
		json_t *permanent = json_object_get(root, "permanent");
		if(allowed) {
			/* Make sure the "allowed" array only contains strings */
			gboolean ok = TRUE;
			if(json_array_size(allowed) > 0) {
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					json_t *a = json_array_get(allowed, i);
					if(!a || !json_is_string(a)) {
						ok = FALSE;
						break;
					}
				}
			}
			if(!ok) {
				JANUS_LOG(LOG_ERR, "Invalid element in the allowed array (not a string)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
				goto prepare_response;
			}
		}
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't create permanent room\n");
			error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't create permanent room");
			goto prepare_response;
		}
		char room_id_num[30], *room_id_str = NULL;
		json_t *room = json_object_get(root, "room");
		room_id_str = (char *)json_string_value(room);
		if(room_id_str == NULL) {
			JANUS_LOG(LOG_WARN, "Desired room ID is empty, which is not allowed... picking random ID instead\n");
		}
		janus_mutex_lock(&rooms_mutex);
		if(room_id_str != NULL) {
			/* Let's make sure the room doesn't exist already */
			if(g_hash_table_lookup(rooms, (gpointer)room_id_str) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				error_code = JANUS_AUDIOBRIDGE_ERROR_ROOM_EXISTS;
				JANUS_LOG(LOG_ERR, "Room %s already exists!\n", room_id_str);
				g_snprintf(error_cause, 512, "Room %s already exists", room_id_str);
				goto prepare_response;
			}
		}
		/* Create the AudioBridge room */
		janus_audiobridge_room *audiobridge = new janus_audiobridge_room {};
		janus_refcount_init(&audiobridge->ref, janus_audiobridge_room_free);
		/* Generate a random ID, if needed */
		gboolean room_id_allocated = FALSE;
		if(room_id_str == NULL) {
			while(room_id_str == NULL) {
				room_id_str = janus_random_uuid();
				if(g_hash_table_lookup(rooms, room_id_str) != NULL) {
					/* Room ID already taken, try another one */
					g_clear_pointer(&room_id_str, g_free);
				}
			}
			room_id_allocated = TRUE;
		}
		audiobridge->room_id_str = room_id_str ? g_strdup(room_id_str) : NULL;
		char *description = NULL;
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			description = g_strdup(json_string_value(desc));
		} else {
			char roomname[255];
			g_snprintf(roomname, 255, "Room %s", audiobridge->room_id_str);
			description = g_strdup(roomname);
		}
		audiobridge->room_name = description;
		audiobridge->is_private = is_private ? json_is_true(is_private) : FALSE;
		if(secret)
			audiobridge->room_secret = g_strdup(json_string_value(secret));
		if(pin)
			audiobridge->room_pin = g_strdup(json_string_value(pin));
		if(sampling)
			audiobridge->sampling_rate = json_integer_value(sampling);
		else
			audiobridge->sampling_rate = 16000;
		audiobridge->spatial_audio = spatial ? json_is_true(spatial) : FALSE;
		audiobridge->audiolevel_ext = audiolevel_ext ? json_is_true(audiolevel_ext) : TRUE;
		audiobridge->audiolevel_event = audiolevel_event ? json_is_true(audiolevel_event) : FALSE;
		if(audiobridge->audiolevel_event) {
			audiobridge->audio_active_packets = 100;
			if(json_integer_value(audio_active_packets) > 0) {
				audiobridge->audio_active_packets = json_integer_value(audio_active_packets);
			} else {
				JANUS_LOG(LOG_WARN, "Invalid audio_active_packets value provided, using default: %d\n",
					audiobridge->audio_active_packets);
			}
			audiobridge->audio_level_average = 25;
			if(json_integer_value(audio_level_average) > 0) {
				audiobridge->audio_level_average = json_integer_value(audio_level_average);
			} else {
				JANUS_LOG(LOG_WARN, "Invalid audio_level_average value provided, using default: %d\n",
					audiobridge->audio_level_average);
			}
		}
		audiobridge->default_prebuffering = default_prebuffering ?
			json_integer_value(default_prebuffering) : DEFAULT_PREBUFFERING;
		if(audiobridge->default_prebuffering > MAX_PREBUFFERING) {
			audiobridge->default_prebuffering = DEFAULT_PREBUFFERING;
			JANUS_LOG(LOG_WARN, "Invalid default_prebuffering value provided (too high), using default: %d\n",
				audiobridge->default_prebuffering);
		}
		audiobridge->default_expectedloss = 0;
		if(default_expectedloss != NULL) {
			int expectedloss = json_integer_value(default_expectedloss);
			if(expectedloss > 20) {
				JANUS_LOG(LOG_WARN, "Invalid expectedloss value provided, using default: 0\n");
			} else {
				audiobridge->default_expectedloss = expectedloss;
			}
		}
		audiobridge->default_bitrate = 0;
		if(default_bitrate != NULL) {
			audiobridge->default_bitrate = json_integer_value(default_bitrate);
			if(audiobridge->default_bitrate < 500 || audiobridge->default_bitrate > 512000) {
				JANUS_LOG(LOG_WARN, "Invalid bitrate %" SCNi32 ", falling back to auto\n", audiobridge->default_bitrate);
				audiobridge->default_bitrate = 0;
			}
		}
		switch(audiobridge->sampling_rate) {
			case 8000:
			case 12000:
			case 16000:
			case 24000:
			case 48000:
				JANUS_LOG(LOG_VERB, "Sampling rate for mixing: %" SCNu32 "\n", audiobridge->sampling_rate);
				break;
			default:
				if(room_id_allocated)
					g_free(room_id_str);
				janus_audiobridge_room_destroy(audiobridge);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Unsupported sampling rate %" SCNu32 "...\n", audiobridge->sampling_rate);
				error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Unsupported sampling rate %" SCNu32, audiobridge->sampling_rate);
				janus_audiobridge_room_destroy(audiobridge);
				goto prepare_response;
		}
		audiobridge->room_ssrc = janus_random_uint32();
		if(mjrs && json_is_true(mjrs))
			audiobridge->mjrs = TRUE;
		if(mjrsdir)
			audiobridge->mjrs_dir = g_strdup(json_string_value(mjrsdir));
		audiobridge->destroy = 0;
		audiobridge->participants = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			(GDestroyNotify)g_free, (GDestroyNotify)janus_audiobridge_participant_unref);
		audiobridge->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
		if(allowed != NULL) {
			/* Populate the "allowed" list as an ACL for people trying to join */
			if(json_array_size(allowed) > 0) {
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					const char *token = json_string_value(json_array_get(allowed, i));
					if(!g_hash_table_lookup(audiobridge->allowed, token))
						g_hash_table_insert(audiobridge->allowed, g_strdup(token), GINT_TO_POINTER(TRUE));
				}
			}
			audiobridge->check_tokens = TRUE;
		}
		g_atomic_int_set(&audiobridge->destroyed, 0);
		janus_mutex_init(&audiobridge->mutex);
		audiobridge->rtp_forwarders = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_audiobridge_rtp_forwarder_destroy);
		audiobridge->rtp_encoder = NULL;
		audiobridge->rtp_udp_sock = -1;
		janus_mutex_init(&audiobridge->rtp_mutex);
		g_hash_table_insert(rooms,
			(gpointer)g_strdup(audiobridge->room_id_str),
			audiobridge);
		JANUS_LOG(LOG_VERB, "Created AudioBridge: %s (%s, %s, secret: %s, pin: %s)\n",
			audiobridge->room_id_str, audiobridge->room_name,
			audiobridge->is_private ? "private" : "public",
			audiobridge->room_secret ? audiobridge->room_secret : "no secret",
			audiobridge->room_pin ? audiobridge->room_pin : "no pin");
		/* We need a thread for the mix */
		GError *error = NULL;
		char tname[16];
		g_snprintf(tname, sizeof(tname), "mixer %s", audiobridge->room_id_str);
		janus_refcount_increase(&audiobridge->ref);
		audiobridge->thread = g_thread_try_new(tname, &janus_audiobridge_mixer_thread, audiobridge, &error);
		if(error != NULL) {
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the mixer thread...\n",
				error->code, error->message ? error->message : "??");
			error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "Got error %d (%s) trying to launch the mixer thread",
				error->code, error->message ? error->message : "??");
			g_error_free(error);
			janus_refcount_decrease(&audiobridge->ref);
			g_hash_table_remove(rooms, (gpointer)audiobridge->room_id_str);
			janus_mutex_unlock(&rooms_mutex);
			if(room_id_allocated)
				g_free(room_id_str);
			goto prepare_response;
		}
		if(save) {
			/* This room is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Saving room %s permanently in config file\n", audiobridge->room_id_str);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ], value[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%s", audiobridge->room_id_str);
			janus_config_category *c = janus_config_get_create(config, NULL, janus_config_type_category, cat);
			/* Now for the values */
			janus_config_add(config, c, janus_config_item_create("description", audiobridge->room_name));
			if(audiobridge->is_private)
				janus_config_add(config, c, janus_config_item_create("is_private", "yes"));
			g_snprintf(value, BUFSIZ, "%" SCNu32, audiobridge->sampling_rate);
			janus_config_add(config, c, janus_config_item_create("sampling_rate", value));
			if(audiobridge->room_secret)
				janus_config_add(config, c, janus_config_item_create("secret", audiobridge->room_secret));
			if(audiobridge->room_pin)
				janus_config_add(config, c, janus_config_item_create("pin", audiobridge->room_pin));
			if(audiobridge->audiolevel_ext) {
				janus_config_add(config, c, janus_config_item_create("audiolevel_ext", "yes"));
				if(audiobridge->audiolevel_event)
					janus_config_add(config, c, janus_config_item_create("audiolevel_event", "yes"));
				if(audiobridge->audio_active_packets > 0) {
					g_snprintf(value, BUFSIZ, "%d", audiobridge->audio_active_packets);
					janus_config_add(config, c, janus_config_item_create("audio_active_packets", value));
				}
				if(audiobridge->audio_level_average > 0) {
					g_snprintf(value, BUFSIZ, "%d", audiobridge->audio_level_average);
					janus_config_add(config, c, janus_config_item_create("audio_level_average", value));
				}
			}
			if(audiobridge->default_prebuffering != DEFAULT_PREBUFFERING) {
				g_snprintf(value, BUFSIZ, "%d", audiobridge->default_prebuffering);
				janus_config_add(config, c, janus_config_item_create("default_prebuffering", value));
			}
			if(audiobridge->mjrs)
				janus_config_add(config, c, janus_config_item_create("mjrs", "yes"));
			if(audiobridge->mjrs_dir)
				janus_config_add(config, c, janus_config_item_create("mjrs_dir", audiobridge->mjrs_dir));
			if(audiobridge->spatial_audio)
				janus_config_add(config, c, janus_config_item_create("spatial_audio", "yes"));
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_AUDIOBRIDGE_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room is not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		/* Send info back */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("created"));
		json_object_set_new(response, "room", json_string(audiobridge->room_id_str));
		json_object_set_new(response, "permanent", save ? json_true() : json_false());
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("created"));
			json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
			gateway->notify_event(&janus_audiobridge_plugin, session ? session->handle : NULL, info);
		}
		if(room_id_allocated)
			g_free(room_id_str);
		janus_mutex_unlock(&rooms_mutex);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "edit")) {
		JANUS_LOG(LOG_VERB, "Attempt to edit an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, edit_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		/* We only allow for a limited set of properties to be edited */
		json_t *room = json_object_get(root, "room");
		json_t *desc = json_object_get(root, "new_description");
		json_t *secret = json_object_get(root, "new_secret");
		json_t *pin = json_object_get(root, "new_pin");
		json_t *is_private = json_object_get(root, "new_is_private");
		json_t *mjrsdir = json_object_get(root, "new_mjrs_dir");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't edit room permanently\n");
			error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't edit room permanently");
			goto prepare_response;
		}
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* Edit the room properties that were provided */
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			char *old_description = audiobridge->room_name;
			char *new_description = g_strdup(json_string_value(desc));
			audiobridge->room_name = new_description;
			g_free(old_description);
		}
		if(is_private)
			audiobridge->is_private = json_is_true(is_private);
		if(secret && strlen(json_string_value(secret)) > 0) {
			char *old_secret = audiobridge->room_secret;
			char *new_secret = g_strdup(json_string_value(secret));
			audiobridge->room_secret = new_secret;
			g_free(old_secret);
		}
		if(pin) {
			char *old_pin = audiobridge->room_pin;
			if(strlen(json_string_value(pin)) > 0) {
				char *new_pin = g_strdup(json_string_value(pin));
				audiobridge->room_pin = new_pin;
			} else {
				audiobridge->room_pin = NULL;
			}
			g_free(old_pin);
		}
		if(mjrsdir) {
			char *old_mjrs_dir = audiobridge->mjrs_dir;
			char *new_mjrs_dir = g_strdup(json_string_value(mjrsdir));
			audiobridge->mjrs_dir = new_mjrs_dir;
			g_free(old_mjrs_dir);
		}
		if(save) {
			/* This change is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Modifying room %s permanently in config file\n", room_id_str);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ], value[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%s", room_id_str);
			/* Remove the old category first */
			janus_config_remove(config, NULL, cat);
			/* Now write the room details again */
			janus_config_category *c = janus_config_get_create(config, NULL, janus_config_type_category, cat);
			janus_config_add(config, c, janus_config_item_create("description", audiobridge->room_name));
			if(audiobridge->is_private)
				janus_config_add(config, c, janus_config_item_create("is_private", "yes"));
			g_snprintf(value, BUFSIZ, "%" SCNu32, audiobridge->sampling_rate);
			janus_config_add(config, c, janus_config_item_create("sampling_rate", value));
			if(audiobridge->room_secret)
				janus_config_add(config, c, janus_config_item_create("secret", audiobridge->room_secret));
			if(audiobridge->room_pin)
				janus_config_add(config, c, janus_config_item_create("pin", audiobridge->room_pin));
			if(audiobridge->audiolevel_ext) {
				janus_config_add(config, c, janus_config_item_create("audiolevel_ext", "yes"));
				if(audiobridge->audiolevel_event)
					janus_config_add(config, c, janus_config_item_create("audiolevel_event", "yes"));
				if(audiobridge->audio_active_packets > 0) {
					g_snprintf(value, BUFSIZ, "%d", audiobridge->audio_active_packets);
					janus_config_add(config, c, janus_config_item_create("audio_active_packets", value));
				}
				if(audiobridge->audio_level_average > 0) {
					g_snprintf(value, BUFSIZ, "%d", audiobridge->audio_level_average);
					janus_config_add(config, c, janus_config_item_create("audio_level_average", value));
				}
			}
			if(audiobridge->default_prebuffering != DEFAULT_PREBUFFERING) {
				g_snprintf(value, BUFSIZ, "%d", audiobridge->default_prebuffering);
				janus_config_add(config, c, janus_config_item_create("default_prebuffering", value));
			}
			if(audiobridge->mjrs)
				janus_config_add(config, c, janus_config_item_create("mjrs", "yes"));
			if(audiobridge->mjrs_dir)
				janus_config_add(config, c, janus_config_item_create("mjrs_dir", audiobridge->mjrs_dir));
			if(audiobridge->spatial_audio)
				janus_config_add(config, c, janus_config_item_create("spatial_audio", "yes"));
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_AUDIOBRIDGE_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room changes are not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		/* Prepare response/notification */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("edited"));
		json_object_set_new(response, "room", json_string(audiobridge->room_id_str));
		json_object_set_new(response, "permanent", save ? json_true() : json_false());
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("edited"));
			json_object_set_new(info, "room", json_string(room_id_str));
			gateway->notify_event(&janus_audiobridge_plugin, session ? session->handle : NULL, info);
		}
		janus_mutex_unlock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);
		/* Done */
		JANUS_LOG(LOG_VERB, "Audiobridge room edited\n");
		goto prepare_response;
	} else if(!strcasecmp(request_text, "destroy")) {
		JANUS_LOG(LOG_VERB, "Attempt to destroy an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, destroy_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't destroy room permanently\n");
			error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't destroy room permanently");
			goto prepare_response;
		}
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* Remove room */
		janus_refcount_increase(&audiobridge->ref);
		g_hash_table_remove(rooms, (gpointer)room_id_str);
		if(save) {
			/* This change is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Destroying room %s permanently in config file\n", room_id_str);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%s", room_id_str);
			janus_config_remove(config, NULL, cat);
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_AUDIOBRIDGE_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room destruction is not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		/* Prepare response/notification */
		json_t *destroyed = json_object();
		json_object_set_new(destroyed, "audiobridge", json_string("destroyed"));
		json_object_set_new(destroyed, "room", json_string(room_id_str));
		/* Notify all participants that the fun is over, and that they'll be kicked */
		JANUS_LOG(LOG_VERB, "Notifying all participants\n");
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, audiobridge->participants);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
			if(p && p->session) {
				if(p->room) {
					p->room = NULL;
					janus_refcount_decrease(&audiobridge->ref);
				}
				int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, destroyed, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				/* Get rid of queued packets */
				janus_mutex_lock(&p->qmutex);
				g_atomic_int_set(&p->active, 0);
				while(p->inbuf) {
					GList *first = g_list_first(p->inbuf);
					janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)first->data;
					p->inbuf = g_list_delete_link(p->inbuf, first);
					first = NULL;
					if(pkt == NULL)
						continue;
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
				}
				janus_mutex_unlock(&p->qmutex);
				/* Request a WebRTC hangup */
				gateway->close_pc(p->session->handle);
			}
		}
		json_decref(destroyed);
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("destroyed"));
			json_object_set_new(info, "room", json_string(room_id_str));
			gateway->notify_event(&janus_audiobridge_plugin, session ? session->handle : NULL, info);
		}
		janus_mutex_unlock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);
		janus_refcount_decrease(&audiobridge->ref);
		/* Done */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("destroyed"));
		json_object_set_new(response, "room", json_string(room_id_str));
		json_object_set_new(response, "permanent", save ? json_true() : json_false());
		JANUS_LOG(LOG_VERB, "Audiobridge room destroyed\n");
		goto prepare_response;
	} else if(!strcasecmp(request_text, "enable_mjrs")) {
		JANUS_VALIDATE_JSON_OBJECT(root, mjrs_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *mjrs = json_object_get(root, "mjrs");
		json_t *mjrsdir = json_object_get(root, "mjrs_dir");
		gboolean mjrs_active = json_is_true(mjrs);
		JANUS_LOG(LOG_VERB, "Enable MJR recording: %d\n", (mjrs_active ? 1 : 0));
		/* Lookup room */
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge = NULL;
		error_code = janus_audiobridge_access_room(root, TRUE, &audiobridge, error_cause, sizeof(error_cause));
		if(error_code != 0) {
			JANUS_LOG(LOG_ERR, "Failed to access room\n");
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&audiobridge->mutex);
		/* Set MJR recording status */
		gboolean room_prev_mjrs_active = mjrs_active;
		if(mjrs_active && mjrsdir) {
			/* Update the path where to save the MJR files */
			char *old_mjrs_dir = audiobridge->mjrs_dir;
			char *new_mjrs_dir = g_strdup(json_string_value(mjrsdir));
			audiobridge->mjrs_dir = new_mjrs_dir;
			g_free(old_mjrs_dir);
		}
		if(room_prev_mjrs_active != audiobridge->mjrs) {
			/* Room recording state has changed */
			audiobridge->mjrs = room_prev_mjrs_active;
		}
		janus_mutex_unlock(&audiobridge->mutex);
		janus_refcount_decrease(&audiobridge->ref);
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		json_object_set_new(response, "mjrs", json_boolean(mjrs_active));
		goto prepare_response;
	} else if(!strcasecmp(request_text, "list")) {
		/* List all rooms (but private ones) and their details (except for the secret, of course...) */
		JANUS_LOG(LOG_VERB, "Request for the list for all audiobridge rooms\n");
		gboolean lock_room_list = TRUE;
		if(admin_key != NULL) {
			json_t *admin_key_json = json_object_get(root, "admin_key");
			/* Verify admin_key if it was provided */
			if(admin_key_json != NULL && json_is_string(admin_key_json) && strlen(json_string_value(admin_key_json)) > 0) {
				JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
					JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
				if(error_code != 0) {
					goto prepare_response;
				} else {
					lock_room_list = FALSE;
				}
			}
		}
		json_t *list = json_array();
		janus_mutex_lock(&rooms_mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_audiobridge_room *room = (janus_audiobridge_room *)value;
			if(!room || g_atomic_int_get(&room->destroyed))
				continue;
			janus_refcount_increase(&room->ref);
			if(room->is_private && lock_room_list) {
				/* Skip private room if no valid admin_key was provided */
				JANUS_LOG(LOG_VERB, "Skipping private room '%s'\n", room->room_name);
				janus_refcount_decrease(&room->ref);
				continue;
			}
			json_t *rl = json_object();
			json_object_set_new(rl, "room", json_string(room->room_id_str));
			json_object_set_new(rl, "description", json_string(room->room_name));
			json_object_set_new(rl, "sampling_rate", json_integer(room->sampling_rate));
			json_object_set_new(rl, "spatial_audio", room->spatial_audio ? json_true() : json_false());
			json_object_set_new(rl, "pin_required", room->room_pin ? json_true() : json_false());
			json_object_set_new(rl, "muted", room->muted ? json_true() : json_false());
			json_object_set_new(rl, "num_participants", json_integer(g_hash_table_size(room->participants)));
			json_array_append_new(list, rl);
			janus_refcount_decrease(&room->ref);
		}
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		json_object_set_new(response, "list", list);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "exists")) {
		/* Check whether a given room exists or not, returns true/false */
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		gboolean room_exists = g_hash_table_contains(rooms, (gpointer)room_id_str);
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		json_object_set_new(response, "room", json_string(room_id_str));
		json_object_set_new(response, "exists", room_exists ? json_true() : json_false());
		goto prepare_response;
	} else if(!strcasecmp(request_text, "allowed")) {
		JANUS_LOG(LOG_VERB, "Attempt to edit the list of allowed participants in an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, allowed_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *action = json_object_get(root, "action");
		json_t *room = json_object_get(root, "room");
		json_t *allowed = json_object_get(root, "allowed");
		const char *action_text = json_string_value(action);
		if(strcasecmp(action_text, "enable") && strcasecmp(action_text, "disable") &&
				strcasecmp(action_text, "add") && strcasecmp(action_text, "remove")) {
			JANUS_LOG(LOG_ERR, "Unsupported action '%s' (allowed)\n", action_text);
			error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Unsupported action '%s' (allowed)", action_text);
			goto prepare_response;
		}
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		if(!strcasecmp(action_text, "enable")) {
			JANUS_LOG(LOG_VERB, "Enabling the check on allowed authorization tokens for room %s\n", room_id_str);
			audiobridge->check_tokens = TRUE;
		} else if(!strcasecmp(action_text, "disable")) {
			JANUS_LOG(LOG_VERB, "Disabling the check on allowed authorization tokens for room %s (free entry)\n", room_id_str);
			audiobridge->check_tokens = FALSE;
		} else {
			gboolean add = !strcasecmp(action_text, "add");
			if(allowed) {
				/* Make sure the "allowed" array only contains strings */
				gboolean ok = TRUE;
				if(json_array_size(allowed) > 0) {
					size_t i = 0;
					for(i=0; i<json_array_size(allowed); i++) {
						json_t *a = json_array_get(allowed, i);
						if(!a || !json_is_string(a)) {
							ok = FALSE;
							break;
						}
					}
				}
				if(!ok) {
					JANUS_LOG(LOG_ERR, "Invalid element in the allowed array (not a string)\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
					janus_mutex_unlock(&audiobridge->mutex);
					janus_mutex_unlock(&rooms_mutex);
					goto prepare_response;
				}
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					const char *token = json_string_value(json_array_get(allowed, i));
					if(add) {
						if(!g_hash_table_lookup(audiobridge->allowed, token))
							g_hash_table_insert(audiobridge->allowed, g_strdup(token), GINT_TO_POINTER(TRUE));
					} else {
						g_hash_table_remove(audiobridge->allowed, token);
					}
				}
			}
		}
		/* Prepare response */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		json_object_set_new(response, "room", json_string(audiobridge->room_id_str));
		json_t *list = json_array();
		if(strcasecmp(action_text, "disable")) {
			if(g_hash_table_size(audiobridge->allowed) > 0) {
				GHashTableIter iter;
				gpointer key;
				g_hash_table_iter_init(&iter, audiobridge->allowed);
				while(g_hash_table_iter_next(&iter, &key, NULL)) {
					char *token = (char *)key;
					json_array_append_new(list, json_string(token));
				}
			}
			json_object_set_new(response, "allowed", list);
		}
		/* Done */
		janus_mutex_unlock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);
		JANUS_LOG(LOG_VERB, "Audiobridge room allowed list updated\n");
		goto prepare_response;
	} else if(!strcasecmp(request_text, "mute") || !strcasecmp(request_text, "unmute")) {
		JANUS_LOG(LOG_VERB, "Attempt to mute a participant from an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, secret_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, idstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		json_t *id = json_object_get(root, "id");
		gboolean muted = (!strcasecmp(request_text, "mute")) ? TRUE : FALSE;
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		janus_mutex_lock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);

		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}

		char user_id_num[30], *user_id_str = NULL;
		user_id_str = (char *)json_string_value(id);
		janus_audiobridge_participant *participant =
			(janus_audiobridge_participant *)g_hash_table_lookup(audiobridge->participants, (gpointer)user_id_str);
		if(participant == NULL) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			JANUS_LOG(LOG_ERR, "No such user %s in room %s\n", user_id_str, room_id_str);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_USER;
			g_snprintf(error_cause, 512, "No such user %s in room %s", user_id_str, room_id_str);
			goto prepare_response;
		}

		if(!muted && audiobridge->unmutedParticipant && audiobridge->unmutedParticipant != participant) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			JANUS_LOG(LOG_ERR, "Room \"%s\" already has unmuted user\n", room_id_str);
			error_code = JANUS_AUDIOBRIDGE_ERROR_ROOM_ALREADY_HAS_UNMUTED_USER;
			g_snprintf(error_cause, 512, "Room \"%s\" already has unmuted user\n", room_id_str);
			goto prepare_response;
		}

		if(participant->muted == muted) {
			/* If someone trying to mute an already muted user, or trying to unmute a user that is not mute),
			then we should do nothing */

			/* Nothing to do, just prepare response */
			response = json_object();
			json_object_set_new(response, "audiobridge", json_string("success"));

			/* Done */
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}

		mute_participant(session, participant, muted, TRUE, TRUE);

		/* Prepare response */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		json_object_set_new(response, "room", json_string(room_id_str));

		/* Done */
		janus_mutex_unlock(&audiobridge->mutex);
		janus_refcount_decrease(&audiobridge->ref);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "mute_room") || !strcasecmp(request_text, "unmute_room")) {
		JANUS_LOG(LOG_VERB, "Attempt to mute all participants in an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, secret_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		gboolean muted = (!strcasecmp(request_text, "mute_room")) ? TRUE : FALSE;
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		janus_mutex_lock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);

		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}

		if(audiobridge->muted == muted) {
			/* If we're already in the right state, just prepare the response */
			response = json_object();
			json_object_set_new(response, "audiobridge", json_string("success"));

			/* Done */
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}
		audiobridge->muted = muted;

		/* Prepare an event to notify all participants */
		json_t *event = json_object();
		json_object_set_new(event, "audiobridge", json_string("event"));
		json_object_set_new(event, "room", json_string(room_id_str));
		json_object_set_new(event, "muted", audiobridge->muted ? json_true() : json_false());
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, audiobridge->participants);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
		json_decref(event);

		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string(request_text));
			json_object_set_new(info, "room", json_string(room_id_str));
			gateway->notify_event(&janus_audiobridge_plugin, session ? session->handle : NULL, info);
		}

		JANUS_LOG(LOG_VERB, "%s all users in room %s\n", muted ? "Muted" : "Unmuted", room_id_str);

		/* Prepare response */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		json_object_set_new(response, "room", json_string(room_id_str));

		/* Done */
		janus_mutex_unlock(&audiobridge->mutex);
		janus_refcount_decrease(&audiobridge->ref);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "kick")) {
		JANUS_LOG(LOG_VERB, "Attempt to kick a participant from an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, secret_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, idstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		json_t *id = json_object_get(root, "id");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}
		char user_id_num[30], *user_id_str = NULL;
		user_id_str = (char *)json_string_value(id);
		janus_audiobridge_participant *participant =
			(janus_audiobridge_participant *)g_hash_table_lookup(audiobridge->participants, (gpointer)user_id_str);
		if(participant == NULL) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			JANUS_LOG(LOG_ERR, "No such user %s in room %s\n", user_id_str, room_id_str);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_USER;
			g_snprintf(error_cause, 512, "No such user %s in room %s", user_id_str, room_id_str);
			goto prepare_response;
		}
		/* Notify all participants about the kick */
		json_t *event = json_object();
		json_object_set_new(event, "audiobridge", json_string("event"));
		json_object_set_new(event, "room", json_string(room_id_str));
		json_object_set_new(event, "kicked", json_string(user_id_str));
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, audiobridge->participants);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
		json_decref(event);
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("kicked"));
			json_object_set_new(info, "room", json_string(room_id_str));
			json_object_set_new(info, "id", json_string(user_id_str));
			gateway->notify_event(&janus_audiobridge_plugin, session ? session->handle : NULL, info);
		}
		/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
		if(participant && participant->session)
			gateway->close_pc(participant->session->handle);
		JANUS_LOG(LOG_VERB, "Kicked user %s from room %s\n", user_id_str, room_id_str);
		/* Prepare response */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		/* Done */
		janus_mutex_unlock(&audiobridge->mutex);
		janus_refcount_decrease(&audiobridge->ref);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "kick_all")) {
		JANUS_LOG(LOG_VERB, "Attempt to kick all participants from an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, secret_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}
		GHashTableIter kick_iter;
		gpointer kick_value;
		g_hash_table_iter_init(&kick_iter, audiobridge->participants);
		while(g_hash_table_iter_next(&kick_iter, NULL, &kick_value)) {
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)kick_value;
			JANUS_LOG(LOG_VERB, "Kicking participant %s (%s)\n",
					participant->user_id_str, participant->display ? participant->display : "??");
			char user_id_num[30], *user_id_str = NULL;
			user_id_str = participant->user_id_str;
			/* Notify all participants about the kick */
			json_t *event = json_object();
			json_object_set_new(event, "audiobridge", json_string("event"));
			json_object_set_new(event, "room", json_string(room_id_str));
			json_object_set_new(event, "kicked_all", json_string(user_id_str));
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", participant->user_id_str, participant->display ? participant->display : "??");
			int ret = gateway->push_event(participant->session->handle, &janus_audiobridge_plugin, NULL, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("kicked_all"));
				json_object_set_new(info, "room", json_string(room_id_str));
				json_object_set_new(info, "id", json_string(user_id_str));
				gateway->notify_event(&janus_audiobridge_plugin, session ? session->handle : NULL, info);
			}
			/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
			if(participant && participant->session)
				gateway->close_pc(participant->session->handle);
			JANUS_LOG(LOG_VERB, "Kicked user %s from room %s\n", user_id_str, room_id_str);
		}
		/* Prepare response */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		/* Done */
		janus_mutex_unlock(&audiobridge->mutex);
		janus_refcount_decrease(&audiobridge->ref);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "listparticipants")) {
		/* List all participants in a room */
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		/* Return a list of all participants */
		json_t *list = json_array();
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, audiobridge->participants);
		while(!g_atomic_int_get(&audiobridge->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
			json_t *pl = json_object();
			json_object_set_new(pl, "id", json_string(p->user_id_str));
			if(p->display)
				json_object_set_new(pl, "display", json_string(p->display));
			json_object_set_new(pl, "setup", g_atomic_int_get(&p->session->started) ? json_true() : json_false());
			json_object_set_new(pl, "muted", p->muted ? json_true() : json_false());
			if(p->extmap_id > 0)
				json_object_set_new(pl, "talking", p->talking ? json_true() : json_false());
			if(audiobridge->spatial_audio)
				json_object_set_new(pl, "spatial_position", json_integer(p->spatial_position));
			json_array_append_new(list, pl);
		}
		janus_refcount_decrease(&audiobridge->ref);
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("participants"));
		json_object_set_new(response, "room", json_string(room_id_str));
		json_object_set_new(response, "participants", list);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "resetdecoder")) {
		/* Mark the Opus decoder for the participant invalid and recreate it */
		janus_audiobridge_participant *participant = (janus_audiobridge_participant *)(session ? session->participant : NULL);
		if(participant == NULL || participant->room == NULL) {
			JANUS_LOG(LOG_ERR, "Can't reset (not in a room)\n");
			error_code = JANUS_AUDIOBRIDGE_ERROR_NOT_JOINED;
			g_snprintf(error_cause, 512, "Can't reset (not in a room)");
			goto prepare_response;
		}
		participant->reset = TRUE;
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		goto prepare_response;
	} else if(!strcasecmp(request_text, "rtp_forward")) {
		JANUS_VALIDATE_JSON_OBJECT(root, rtp_forward_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(lock_rtpfwd && admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto prepare_response;
		}
		/* Parse arguments */
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		guint32 ssrc_value = 0;
		json_t *ssrc = json_object_get(root, "ssrc");
		if(ssrc)
			ssrc_value = json_integer_value(ssrc);
		int ptype = 100;
		json_t *pt = json_object_get(root, "ptype");
		if(pt)
			ptype = json_integer_value(pt);
		uint16_t port = json_integer_value(json_object_get(root, "port"));
		if(port == 0) {
			JANUS_LOG(LOG_ERR, "Invalid port number (%d)\n", port);
			error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid port number (%d)", port);
			goto prepare_response;
		}
		json_t *json_host = json_object_get(root, "host");
		const char *host = json_string_value(json_host), *resolved_host = NULL;
		json_t *json_host_family = json_object_get(root, "host_family");
		const char *host_family = json_string_value(json_host_family);
		int family = 0;
		if(host_family) {
			if(!strcasecmp(host_family, "ipv4")) {
				family = AF_INET;
			} else if(!strcasecmp(host_family, "ipv6")) {
				family = AF_INET6;
			} else {
				JANUS_LOG(LOG_ERR, "Unsupported protocol family (%s)\n", host_family);
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Unsupported protocol family (%s)", host_family);
				goto prepare_response;
			}
		}
		/* Check if we need to resolve this host address */
		struct addrinfo *res = NULL, *start = NULL;
		janus_network_address addr;
		janus_network_address_string_buffer addr_buf;
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		if(family != 0)
			hints.ai_family = family;
		if(getaddrinfo(host, NULL, family != 0 ? &hints : NULL, &res) == 0) {
			start = res;
			while(res != NULL) {
				if(janus_network_address_from_sockaddr(res->ai_addr, &addr) == 0 &&
						janus_network_address_to_string_buffer(&addr, &addr_buf) == 0) {
					/* Resolved */
					resolved_host = janus_network_address_string_from_buffer(&addr_buf);
					freeaddrinfo(start);
					start = NULL;
					break;
				}
				res = res->ai_next;
			}
		}
		if(resolved_host == NULL) {
			if(start)
				freeaddrinfo(start);
			JANUS_LOG(LOG_ERR, "Could not resolve address (%s)...\n", host);
			error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Could not resolve address (%s)...", host);
			goto prepare_response;
		}
		host = resolved_host;
		if(ipv6_disabled && strstr(host, ":") != NULL) {
			JANUS_LOG(LOG_ERR, "Attempt to create an IPv6 forwarder, but IPv6 networking is not available\n");
			error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Attempt to create an IPv6 forwarder, but IPv6 networking is not available");
			goto prepare_response;
		}
		json_t *always = json_object_get(root, "always_on");
		gboolean always_on = always ? json_is_true(always) : FALSE;
		/* Besides, we may need to SRTP-encrypt this stream */
		int srtp_suite = 0;
		const char *srtp_crypto = NULL;
		json_t *s_suite = json_object_get(root, "srtp_suite");
		json_t *s_crypto = json_object_get(root, "srtp_crypto");
		if(s_suite && s_crypto) {
			srtp_suite = json_integer_value(s_suite);
			if(srtp_suite != 32 && srtp_suite != 80) {
				JANUS_LOG(LOG_ERR, "Invalid SRTP suite (%d)\n", srtp_suite);
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid SRTP suite (%d)", srtp_suite);
				goto prepare_response;
			}
			srtp_crypto = json_string_value(s_crypto);
		}
		/* Update room */
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s", room_id_str);
			goto prepare_response;
		}
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		if(audiobridge->destroyed) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}

		if(janus_audiobridge_create_udp_socket_if_needed(audiobridge)) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "Could not open UDP socket for RTP forwarder");
			goto prepare_response;
		}

		if(janus_audiobridge_create_opus_encoder_if_needed(audiobridge)) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_LIBOPUS_ERROR;
			g_snprintf(error_cause, 512, "Error creating Opus encoder for RTP forwarder");
			goto prepare_response;
		}

		guint32 stream_id = janus_audiobridge_rtp_forwarder_add_helper(audiobridge,
			host, port, ssrc_value, ptype, srtp_suite, srtp_crypto, always_on, 0);
		janus_mutex_unlock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);

		/* Done, prepare response */
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		json_object_set_new(response, "room", json_string(room_id_str));
		json_object_set_new(response, "stream_id", json_integer(stream_id));
		json_object_set_new(response, "host", json_string(host));
		json_object_set_new(response, "port", json_integer(port));
		goto prepare_response;
	} else if(!strcasecmp(request_text, "stop_rtp_forward")) {
		JANUS_VALIDATE_JSON_OBJECT(root, stop_rtp_forward_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(lock_rtpfwd && admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto prepare_response;
		}
		/* Parse parameters */
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		guint32 stream_id = json_integer_value(json_object_get(root, "stream_id"));
		/* Update room */
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge = (janus_audiobridge_room *)g_hash_table_lookup(rooms,
			(gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		if(audiobridge->destroyed) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->rtp_mutex);
		g_hash_table_remove(audiobridge->rtp_forwarders, GUINT_TO_POINTER(stream_id));
		janus_mutex_unlock(&audiobridge->rtp_mutex);
		janus_mutex_unlock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("success"));
		json_object_set_new(response, "room", json_string(room_id_str));
		json_object_set_new(response, "stream_id", json_integer(stream_id));
		goto prepare_response;
	} else if(!strcasecmp(request_text, "listforwarders")) {
		/* List all forwarders in a room */
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_audiobridge_room *audiobridge =
			(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		if(audiobridge->destroyed) {
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* Return a list of all forwarders */
		json_t *list = json_array();
		GHashTableIter iter;
		gpointer key, value;
		janus_mutex_lock(&audiobridge->rtp_mutex);
		g_hash_table_iter_init(&iter, audiobridge->rtp_forwarders);
		while(g_hash_table_iter_next(&iter, &key, &value)) {
			guint32 stream_id = GPOINTER_TO_UINT(key);
			janus_audiobridge_rtp_forwarder *rf = (janus_audiobridge_rtp_forwarder *)value;
			json_t *fl = json_object();
			json_object_set_new(fl, "stream_id", json_integer(stream_id));
			char address[100];
			if(rf->serv_addr.sin_family == AF_INET) {
				json_object_set_new(fl, "ip", json_string(
					inet_ntop(AF_INET, &rf->serv_addr.sin_addr, address, sizeof(address))));
			} else {
				json_object_set_new(fl, "ip", json_string(
					inet_ntop(AF_INET6, &rf->serv_addr6.sin6_addr, address, sizeof(address))));
			}
			json_object_set_new(fl, "port", json_integer(ntohs(rf->serv_addr.sin_port)));
			json_object_set_new(fl, "ssrc", json_integer(rf->ssrc ? rf->ssrc : stream_id));
			json_object_set_new(fl, "codec", json_string(janus_audiocodec_name(JANUS_AUDIOCODEC_OPUS)));
			json_object_set_new(fl, "ptype", json_integer(rf->payload_type));
			if(rf->is_srtp)
				json_object_set_new(fl, "srtp", json_true());
			json_object_set_new(fl, "always_on", rf->always_on ? json_true() : json_false());
			json_array_append_new(list, fl);
		}
		janus_mutex_unlock(&audiobridge->rtp_mutex);
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "audiobridge", json_string("forwarders"));
		json_object_set_new(response, "room", json_string(room_id_str));
		json_object_set_new(response, "rtp_forwarders", list);
		goto prepare_response;
	} else {
		/* Not a request we recognize, don't do anything */
		return NULL;
	}

prepare_response:
		{
			if(error_code == 0 && !response) {
				error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid response");
			}
			if(error_code != 0) {
				/* Prepare JSON error event */
				response = json_object();
				json_object_set_new(response, "audiobridge", json_string("event"));
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}

}

struct janus_plugin_result *janus_audiobridge_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	janus_mutex_lock(&sessions_mutex);
	janus_audiobridge_session *session = janus_audiobridge_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "No session associated with this handle...");
		goto plugin_response;
	}
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been marked as destroyed...\n");
		error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been marked as destroyed...");
		goto plugin_response;
	}

	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_AUDIOBRIDGE_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto plugin_response;
	}
	if(!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto plugin_response;
	}
	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	json_t *request; request = json_object_get(root, "request");
	/* Some requests ('create', 'destroy', 'exists', 'list') can be handled synchronously */
	const char *request_text; request_text = json_string_value(request);
	/* We have a separate method to process synchronous requests, as those may
	 * arrive from the Admin API as well, and so we handle them the same way */
	response = janus_audiobridge_process_synchronous_request(session, root);
	if(response != NULL) {
		/* We got a response, send it back */
		goto plugin_response;
	} else if(!strcasecmp(request_text, "join") || !strcasecmp(request_text, "configure")
			|| !strcasecmp(request_text, "self-unmute") || !strcasecmp(request_text, "self-mute")
			|| !strcasecmp(request_text, "changeroom") || !strcasecmp(request_text, "leave")
			|| !strcasecmp(request_text, "hangup")) {
		/* These messages are handled asynchronously */
		janus_audiobridge_message *msg = (janus_audiobridge_message *)g_malloc(sizeof(janus_audiobridge_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;

		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(error_code == 0 && !response) {
				error_code = JANUS_AUDIOBRIDGE_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid response");
			}
			if(error_code != 0) {
				/* Prepare JSON error event */
				json_t *event = json_object();
				json_object_set_new(event, "audiobridge", json_string("event"));
				json_object_set_new(event, "error_code", json_integer(error_code));
				json_object_set_new(event, "error", json_string(error_cause));
				response = event;
			}
			if(root != NULL)
				json_decref(root);
			if(jsep != NULL)
				json_decref(jsep);
			g_free(transaction);

			if(session != NULL)
				janus_refcount_decrease(&session->ref);
			return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
		}

}

json_t *janus_audiobridge_handle_admin_message(json_t *message) {
	/* Some requests (e.g., 'create' and 'destroy') can be handled via Admin API */
	int error_code = 0;
	char error_cause[512];
	json_t *response = NULL;

	JANUS_VALIDATE_JSON_OBJECT(message, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto admin_response;
	json_t *request; request = json_object_get(message, "request");
	const char *request_text; request_text = json_string_value(request);
	if((response = janus_audiobridge_process_synchronous_request(NULL, message)) != NULL) {
		/* We got a response, send it back */
		goto admin_response;
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

admin_response:
		{
			if(!response) {
				/* Prepare JSON error event */
				response = json_object();
				json_object_set_new(response, "audiobridge", json_string("event"));
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}

}

void janus_audiobridge_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_AUDIOBRIDGE_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_audiobridge_session *session = janus_audiobridge_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
	if(!participant) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	g_atomic_int_set(&session->hangingup, 0);
	/* FIXME Only send this peer the audio mix when we get this event */
	g_atomic_int_set(&session->started, 1);
	janus_mutex_unlock(&sessions_mutex);
	/* Notify all other participants that there's a new boy in town */
	janus_mutex_lock(&rooms_mutex);
	janus_audiobridge_room *audiobridge = participant->room;
	if(audiobridge == NULL) {
		/* No room..? Shouldn't happen */
		janus_mutex_unlock(&rooms_mutex);
		JANUS_LOG(LOG_WARN, "PeerConnection created, but AudioBridge participant not in a room...\n");
		return;
	}
	janus_mutex_lock(&audiobridge->mutex);
	json_t *list = json_array();
	json_t *pl = json_object();
	json_object_set_new(pl, "id", json_string(participant->user_id_str));
	if(participant->display)
		json_object_set_new(pl, "display", json_string(participant->display));
	json_object_set_new(pl, "setup", json_true());
	json_object_set_new(pl, "muted", participant->muted ? json_true() : json_false());
	if(audiobridge->spatial_audio)
		json_object_set_new(pl, "spatial_position", json_integer(participant->spatial_position));
	json_array_append_new(list, pl);
	json_t *pub = json_object();
	json_object_set_new(pub, "audiobridge", json_string("event"));
	json_object_set_new(pub, "room", json_string(participant->room->room_id_str));
	json_object_set_new(pub, "participants", list);
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, audiobridge->participants);
	while(g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
		if(p == participant) {
			continue;	/* Skip the new participant itself */
		}
		JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
		int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, pub, NULL);
		JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	}
	json_decref(pub);
	g_atomic_int_set(&participant->active, 1);
	janus_mutex_unlock(&audiobridge->mutex);
	janus_mutex_unlock(&rooms_mutex);
}

void janus_audiobridge_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_audiobridge_session *session = (janus_audiobridge_session *)handle->plugin_handle;
	if(!session || g_atomic_int_get(&session->destroyed) || !session->participant)
		return;
	janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
	if(!g_atomic_int_get(&participant->active) || participant->muted || !participant->decoder || !participant->room)
		return;
	if(participant->room && participant->room->muted && !participant->admin)
		return;
	char *buf = packet->buffer;
	uint16_t len = packet->length;
	/* Save the frame if we're recording this leg */
	janus_recorder_save_frame(participant->arc, buf, len);
	if(g_atomic_int_get(&participant->active) && participant->decoder) {
		/* First of all, check if a reset on the decoder is due */
		/* Create a new decoder and get rid of the old one */
		int error = 0;
		OpusDecoder *decoder = opus_decoder_create(participant->room->sampling_rate,
			participant->stereo ? 2 : 1, &error);
		if(error != OPUS_OK) {
			JANUS_LOG(LOG_ERR, "Error resetting Opus decoder...\n");
		} else {
			if(participant->decoder)
				opus_decoder_destroy(participant->decoder);
			participant->decoder = decoder;
			JANUS_LOG(LOG_VERB, "Opus decoder reset\n");
		}
		participant->reset = FALSE;

		/* Decode frame (Opus -> slinear) */
		janus_rtp_header *rtp = (janus_rtp_header *)buf;
		janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)g_malloc(sizeof(janus_audiobridge_rtp_relay_packet));
		pkt->data = (janus_rtp_header *)g_malloc0(BUFFER_SAMPLES*sizeof(opus_int16));
		pkt->ssrc = 0;
		pkt->timestamp = ntohl(rtp->timestamp);
		pkt->seq_number = ntohs(rtp->seq_number);
		/* We might check the audio level extension to see if this is silence */
		pkt->silence = FALSE;
		pkt->length = 0;

		/* First check if probation period */
		if(participant->probation == MIN_SEQUENTIAL) {
			participant->probation--;
			participant->expected_seq = pkt->seq_number + 1;
			JANUS_LOG(LOG_VERB, "Probation started with ssrc = %" SCNu32 ", seq = %" SCNu16 " \n", ntohl(rtp->ssrc), pkt->seq_number);
			g_free(pkt->data);
			g_free(pkt);
			return;
		} else if(participant->probation != 0) {
			/* Decrease probation */
			participant->probation--;
			/* TODO: Reset probation if sequence number is incorrect and DSSRC also; must have a correct sequence */
			if(!participant->probation){
				/* Probation is ended */
				JANUS_LOG(LOG_VERB, "Probation ended with ssrc = %" SCNu32 ", seq = %" SCNu16 " \n", ntohl(rtp->ssrc), pkt->seq_number);
			}
			participant->expected_seq = pkt->seq_number + 1;
			g_free(pkt->data);
			g_free(pkt);
			return;
		}

		if(participant->extmap_id > 0) {
			/* Check the audio levels, in case we need to notify participants about who's talking */
			int level = packet->extensions.audio_level;
			if(level != -1) {
				/* Is this silence? */
				pkt->silence = (level == 127);
				if(participant->room && participant->room->audiolevel_event) {
					/* We also need to detect who's talking: update our monitoring stuff */
					int audio_active_packets = participant->room ? participant->room->audio_active_packets : 100;
					int audio_level_average = participant->room ? participant->room->audio_level_average : 25;
					/* Check if we need to override those with user specific properties */
					if(participant->user_audio_active_packets > 0)
						audio_active_packets = participant->user_audio_active_packets;
					if(participant->user_audio_level_average > 0)
						audio_level_average = participant->user_audio_level_average;
					participant->audio_dBov_sum += level;
					participant->audio_active_packets++;
					participant->dBov_level = level;
					if(participant->audio_active_packets > 0 && participant->audio_active_packets == audio_active_packets) {
						gboolean notify_talk_event = FALSE;
						if((float) participant->audio_dBov_sum / (float) participant->audio_active_packets < audio_level_average) {
							/* Participant talking, should we notify all participants? */
							if(!participant->talking)
								notify_talk_event = TRUE;
							participant->talking = TRUE;
						} else {
							/* Participant not talking anymore, should we notify all participants? */
							if(participant->talking)
								notify_talk_event = TRUE;
							participant->talking = FALSE;
						}
						participant->audio_active_packets = 0;
						participant->audio_dBov_sum = 0;
						/* Only notify in case of state changes */
						if(participant->room && notify_talk_event) {
							janus_mutex_lock(&participant->room->mutex);
							json_t *event = json_object();
							json_object_set_new(event, "audiobridge", json_string(participant->talking ? "talking" : "stopped-talking"));
							json_object_set_new(event, "room", json_string(participant->room ? participant->room->room_id_str : NULL));
							json_object_set_new(event, "id", json_string(participant->user_id_str));
							/* Notify the speaker this event is related to as well */
							janus_audiobridge_notify_participants(participant, event, TRUE);
							json_decref(event);
							janus_mutex_unlock(&participant->room->mutex);
							/* Also notify event handlers */
							if(notify_events && gateway->events_is_enabled()) {
								json_t *info = json_object();
								json_object_set_new(info, "audiobridge", json_string(participant->talking ? "talking" : "stopped-talking"));
								json_object_set_new(info, "room", json_string(participant->room ? participant->room->room_id_str : NULL));
								json_object_set_new(info, "id", json_string(participant->user_id_str));
								gateway->notify_event(&janus_audiobridge_plugin, session->handle, info);
							}
						}
					}
				}
			}
		}
		if(!g_atomic_int_compare_and_exchange(&participant->decoding, 0, 1)) {
			/* This means we're cleaning up, so don't try to decode */
			g_free(pkt->data);
			g_free(pkt);
			return;
		}
		int plen = 0;
		const unsigned char *payload = (const unsigned char *)janus_rtp_payload(buf, len, &plen);
		if(!payload) {
			g_atomic_int_set(&participant->decoding, 0);
			JANUS_LOG(LOG_ERR, "Ops! got an error accessing the RTP payload\n");
			g_free(pkt->data);
			g_free(pkt);
			return;
		}
		/* Check sequence number received, verify if it's relevant to the expected one */
		if(pkt->seq_number == participant->expected_seq) {
			/* Regular decode */
			/* Opus */
			pkt->length = opus_decode(participant->decoder, payload, plen, (opus_int16 *)pkt->data, BUFFER_SAMPLES, 0);
			/* Update last_timestamp */
			participant->last_timestamp = pkt->timestamp;
			/* Increment according to previous seq_number */
			participant->expected_seq = pkt->seq_number + 1;
		} else if(pkt->seq_number > participant->expected_seq) {
			/* Sequence(s) losts */
			uint16_t gap = pkt->seq_number - participant->expected_seq;
			JANUS_LOG(LOG_HUGE, "%" SCNu16 " sequence(s) lost, sequence = %" SCNu16 ", expected seq = %" SCNu16 "\n",
				gap, pkt->seq_number, participant->expected_seq);

			/* Use FEC if sequence lost < DEFAULT_PREBUFFERING (or any custom value) */
			uint16_t start_lost_seq = participant->expected_seq;
			if(participant->fec && gap < participant->prebuffer_count) {
				uint8_t i=0;
				for(i=1; i<=gap ; i++) {
					int32_t output_samples;
					janus_audiobridge_rtp_relay_packet *lost_pkt = (janus_audiobridge_rtp_relay_packet *)g_malloc(sizeof(janus_audiobridge_rtp_relay_packet));
					lost_pkt->data = (janus_rtp_header *)g_malloc0(BUFFER_SAMPLES*sizeof(opus_int16));
					lost_pkt->ssrc = 0;
					lost_pkt->timestamp = participant->last_timestamp + (i * OPUS_SAMPLES);
					lost_pkt->seq_number = start_lost_seq++;
					lost_pkt->silence = FALSE;
					lost_pkt->length = 0;
					if(i == gap) {
						/* Attempt to decode with in-band FEC from next packet */
						opus_decoder_ctl(participant->decoder, OPUS_GET_LAST_PACKET_DURATION(&output_samples));
						lost_pkt->length = opus_decode(participant->decoder, payload, plen, (opus_int16 *)lost_pkt->data, output_samples, 1);
					} else {
						opus_decoder_ctl(participant->decoder, OPUS_GET_LAST_PACKET_DURATION(&output_samples));
						lost_pkt->length = opus_decode(participant->decoder, NULL, plen, (opus_int16 *)lost_pkt->data, output_samples, 1);
					}
					if(lost_pkt->length < 0) {
						g_atomic_int_set(&participant->decoding, 0);
						JANUS_LOG(LOG_ERR, "[Opus] Ops! got an error decoding the Opus frame: %d (%s)\n", lost_pkt->length, opus_strerror(lost_pkt->length));
						g_free(lost_pkt->data);
						g_free(lost_pkt);
						g_free(pkt->data);
						g_free(pkt);
						return;
					}
					/* Enqueue the decoded frame */
					janus_mutex_lock(&participant->qmutex);
					/* Insert packets sorting by sequence number */
					participant->inbuf = g_list_insert_sorted(participant->inbuf, lost_pkt, &janus_audiobridge_rtp_sort);
					janus_mutex_unlock(&participant->qmutex);
				}
			}
			/* Then go with the regular decode (no FEC) */
			/* Opus */
			pkt->length = opus_decode(participant->decoder, payload, plen, (opus_int16 *)pkt->data, BUFFER_SAMPLES, 0);
			/* Increment according to previous seq_number */
			participant->expected_seq = pkt->seq_number + 1;
		} else {
			/* In late sequence or sequence wrapped */
			g_atomic_int_set(&participant->decoding, 0);
			if((participant->expected_seq - pkt->seq_number) > MAX_MISORDER){
				JANUS_LOG(LOG_HUGE, "SN WRAPPED seq =  %" SCNu16 ", expected_seq = %" SCNu16 "\n", pkt->seq_number, participant->expected_seq);
				participant->expected_seq = pkt->seq_number + 1;
			} else {
				JANUS_LOG(LOG_WARN, "IN LATE SN seq =  %" SCNu16 ", expected_seq = %" SCNu16 "\n", pkt->seq_number, participant->expected_seq);
			}
			g_free(pkt->data);
			g_free(pkt);
			return;
		}
		g_atomic_int_set(&participant->decoding, 0);
		if(pkt->length < 0) {
			JANUS_LOG(LOG_ERR, "[Opus] Ops! got an error decoding the Opus frame: %d (%s)\n", pkt->length, opus_strerror(pkt->length));
			g_free(pkt->data);
			g_free(pkt);
			return;
		}
		/* Enqueue the decoded frame */
		janus_mutex_lock(&participant->qmutex);
		gint64 now = janus_get_monotonic_time();
		participant->inbuf_timestamp = now;
		/* Insert packets sorting by sequence number */
		participant->inbuf = g_list_insert_sorted(participant->inbuf, pkt, &janus_audiobridge_rtp_sort);
		if(participant->prebuffering) {
			/* Still pre-buffering: do we have enough packets now? */
			if(g_list_length(participant->inbuf) > participant->prebuffer_count) {
				participant->prebuffering = FALSE;
				JANUS_LOG(LOG_VERB, "Prebuffering done! Finally adding the user to the mix\n");
			} else {
				JANUS_LOG(LOG_VERB, "Still prebuffering (got %d packets), not adding the user to the mix yet\n", g_list_length(participant->inbuf));
			}
		} else {
			/* Make sure we're not queueing too many packets: if so, get rid of the older ones */
			if(g_list_length(participant->inbuf) >= participant->prebuffer_count*2) {
				if(now - participant->last_drop > 5*G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "Too many packets in queue (%d > %d), removing older ones\n",
						g_list_length(participant->inbuf), participant->prebuffer_count*2);
					participant->last_drop = now;
				}
				while(g_list_length(participant->inbuf) > participant->prebuffer_count) {
					/* Remove this packet: it's too old */
					GList *first = g_list_first(participant->inbuf);
					janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)first->data;
					JANUS_LOG(LOG_VERB, "List length = %d, Remove sequence = %d\n",
						g_list_length(participant->inbuf), pkt->seq_number);
					participant->inbuf = g_list_delete_link(participant->inbuf, first);
					first = NULL;
					if(pkt == NULL)
						continue;
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
				}
			}
		}
		janus_mutex_unlock(&participant->qmutex);
	}
}

void janus_audiobridge_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* janus_audiobridge_room *FIXME Should we care? */
}

void janus_audiobridge_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_AUDIOBRIDGE_PACKAGE, handle);
	janus_mutex_lock(&sessions_mutex);
	janus_audiobridge_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_audiobridge_hangup_media_internal(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_audiobridge_session *session = janus_audiobridge_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	g_atomic_int_set(&session->started, 0);
	if(session->participant == NULL)
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	/* Get rid of participant */
	janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
	janus_mutex_lock(&rooms_mutex);
	janus_audiobridge_room *audiobridge = participant->room;
	gboolean removed = FALSE;
	if(audiobridge != NULL) {
		participant->room = NULL;
		janus_mutex_lock(&audiobridge->mutex);

		json_t *participantInfo = json_object();
		json_object_set_new(participantInfo, "id", json_string(participant->user_id_str));
		if(participant->display)
			json_object_set_new(participantInfo, "display", json_string(participant->display));
		json_object_set_new(participantInfo, "muted", json_boolean(participant->muted));

		json_t *event = json_object();
		json_object_set_new(event, "audiobridge", json_string("leaving"));
		json_object_set_new(event, "room", json_string(audiobridge->room_id_str));
		json_object_set(event, "participant", participantInfo);

		if(audiobridge->unmutedParticipant == participant) {
			audiobridge->unmutedParticipant = NULL;
		}
		removed = g_hash_table_remove(audiobridge->participants, (gpointer)participant->user_id_str);

		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, audiobridge->participants);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
			if(p == participant) {
				continue;	/* Skip the leaving participant itself */
			}
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
		json_decref(event);

		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("left"));
			json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
			json_object_set(info, "participant", participantInfo);

			gateway->notify_event(&janus_audiobridge_plugin, NULL, info);
		}
		json_decref(participantInfo);
	}
	/* Get rid of the recorders, if available */
	janus_mutex_lock(&participant->rec_mutex);
	janus_audiobridge_recorder_close(participant);
	janus_mutex_unlock(&participant->rec_mutex);
	/* Free the participant resources */
	janus_mutex_lock(&participant->qmutex);
	g_atomic_int_set(&participant->active, 0);
	participant->muted = TRUE;
	g_free(participant->display);
	participant->display = NULL;
	participant->prebuffering = TRUE;
	/* Make sure we're not using the encoder/decoder right now, we're going to destroy them */
	while(!g_atomic_int_compare_and_exchange(&participant->encoding, 0, 1))
		g_usleep(5000);
	if(participant->encoder)
		opus_encoder_destroy(participant->encoder);
	participant->encoder = NULL;
	g_atomic_int_set(&participant->encoding, 0);
	while(!g_atomic_int_compare_and_exchange(&participant->decoding, 0, 1))
		g_usleep(5000);
	if(participant->decoder)
		opus_decoder_destroy(participant->decoder);
	participant->decoder = NULL;
	g_atomic_int_set(&participant->decoding, 0);
	participant->reset = FALSE;
	participant->audio_active_packets = 0;
	participant->audio_dBov_sum = 0;
	participant->talking = FALSE;
	/* Get rid of queued packets */
	while(participant->inbuf) {
		GList *first = g_list_first(participant->inbuf);
		janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)first->data;
		participant->inbuf = g_list_delete_link(participant->inbuf, first);
		first = NULL;
		if(pkt == NULL)
			continue;
		g_free(pkt->data);
		pkt->data = NULL;
		g_free(pkt);
		pkt = NULL;
	}
	participant->last_drop = 0;
	janus_mutex_unlock(&participant->qmutex);
	if(audiobridge != NULL) {
		janus_mutex_unlock(&audiobridge->mutex);
		if(removed) {
			janus_refcount_decrease(&audiobridge->ref);
		}
	}
	janus_mutex_unlock(&rooms_mutex);
	session->plugin_offer = FALSE;
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_audiobridge_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining AudioBridge handler thread\n");
	janus_audiobridge_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = (janus_audiobridge_message *)g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_audiobridge_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_audiobridge_session *session = janus_audiobridge_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_audiobridge_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_audiobridge_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = NULL;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_AUDIOBRIDGE_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		root = msg->message;
		/* Get the request first */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request; request = json_object_get(root, "request");
		const char *request_text; request_text = json_string_value(request);
		json_t *event; event = NULL;
		gboolean sdp_update; sdp_update = FALSE;
		if(json_object_get(msg->jsep, "update") != NULL)
			sdp_update = json_is_true(json_object_get(msg->jsep, "update"));
		gboolean got_offer, got_answer, generate_offer;
		got_offer = FALSE; got_answer = FALSE; generate_offer = FALSE;
		const char *msg_sdp_type; msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp; msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		if(msg_sdp_type != NULL) {
			got_offer = !strcasecmp(msg_sdp_type, "offer");
			got_answer = !strcasecmp(msg_sdp_type, "answer");
			if(!got_offer && !got_answer) {
				JANUS_LOG(LOG_ERR, "Unsupported SDP type '%s'\n", msg_sdp_type);
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Unsupported SDP type '%s'\n", msg_sdp_type);
				goto error;
			}
		}
		if(!strcasecmp(request_text, "join")) {
			JANUS_LOG(LOG_VERB, "Configuring new participant\n");
			janus_audiobridge_participant *participant = session->participant;
			if(participant != NULL && participant->room != NULL) {
				JANUS_LOG(LOG_ERR, "Already in a room (use changeroom to join another one)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_ALREADY_JOINED;
				g_snprintf(error_cause, 512, "Already in a room (use changeroom to join another one)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			JANUS_VALIDATE_JSON_OBJECT(root, idstropt_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *room = json_object_get(root, "room");
			char room_id_num[30], *room_id_str = NULL;
			room_id_str = (char *)json_string_value(room);
			janus_mutex_lock(&rooms_mutex);
			janus_audiobridge_room *audiobridge =
				(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
			if(audiobridge == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
				JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
				g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
				goto error;
			}
			janus_refcount_increase(&audiobridge->ref);
			janus_mutex_lock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			/* A pin may be required for this action */
			JANUS_CHECK_SECRET(audiobridge->room_pin, root, "pin", error_code, error_cause,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
			if(error_code != 0) {
				janus_mutex_unlock(&audiobridge->mutex);
				janus_refcount_decrease(&audiobridge->ref);
				goto error;
			}
			/* A token might be required too */
			if(audiobridge->check_tokens) {
				json_t *token = json_object_get(root, "token");
				const char *token_text = token ? json_string_value(token) : NULL;
				if(token_text == NULL || g_hash_table_lookup(audiobridge->allowed, token_text) == NULL) {
					JANUS_LOG(LOG_ERR, "Unauthorized (not in the allowed list)\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED;
					g_snprintf(error_cause, 512, "Unauthorized (not in the allowed list)");
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					goto error;
				}
			}
			gboolean admin = FALSE;
			if(json_object_get(root, "secret") != NULL) {
				/* The user is trying to present themselves as an admin */
				JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
					JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
				if(error_code != 0) {
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					goto error;
				}
				admin = TRUE;
			}
			json_t *display = json_object_get(root, "display");
			const char *display_text = display ? json_string_value(display) : NULL;
			json_t *prebuffer = json_object_get(root, "prebuffer");
			json_t *gain = json_object_get(root, "volume");
			json_t *spatial = json_object_get(root, "spatial_position");
			json_t *bitrate = json_object_get(root, "bitrate");
			json_t *quality = json_object_get(root, "quality");
			json_t *exploss = json_object_get(root, "expected_loss");
			json_t *acodec = json_object_get(root, "codec");
			json_t *user_audio_level_average = json_object_get(root, "audio_level_average");
			json_t *user_audio_active_packets = json_object_get(root, "audio_active_packets");
			json_t *gen_offer = json_object_get(root, "generate_offer");
			uint prebuffer_count = prebuffer ? json_integer_value(prebuffer) : audiobridge->default_prebuffering;
			if(prebuffer_count > MAX_PREBUFFERING) {
				prebuffer_count = audiobridge->default_prebuffering;
				JANUS_LOG(LOG_WARN, "Invalid prebuffering value provided (too high), using room default: %d\n",
					audiobridge->default_prebuffering);
			}
			int volume = gain ? json_integer_value(gain) : 100;
			int spatial_position = spatial ? json_integer_value(spatial) : 50;
			int32_t opus_bitrate = audiobridge->default_bitrate;
			if(bitrate) {
				opus_bitrate = json_integer_value(bitrate);
				if(opus_bitrate < 500 || opus_bitrate > 512000) {
					JANUS_LOG(LOG_WARN, "Invalid bitrate %" SCNi32 ", falling back to default/auto\n", opus_bitrate);
					opus_bitrate = audiobridge->default_bitrate;
				}
			}
			int complexity = quality ? json_integer_value(quality) : DEFAULT_COMPLEXITY;
			if(complexity < 1 || complexity > 10) {
				janus_mutex_unlock(&audiobridge->mutex);
				janus_refcount_decrease(&audiobridge->ref);
				JANUS_LOG(LOG_ERR, "Invalid element (quality should be a positive integer between 1 and 10)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (quality should be a positive integer between 1 and 10)");
				goto error;
			}
			int expected_loss = exploss ? json_integer_value(exploss) : audiobridge->default_expectedloss;
			if(expected_loss > 20) {
				janus_mutex_unlock(&audiobridge->mutex);
				janus_refcount_decrease(&audiobridge->ref);
				JANUS_LOG(LOG_ERR, "Invalid element (expected_loss should be a positive integer between 0 and 20)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (expected_loss should be a positive integer between 0 and 20)");
				goto error;
			}
			char user_id_num[30], *user_id_str = NULL;
			gboolean user_id_allocated = FALSE;
			json_t *id = json_object_get(root, "id");
			if(id) {
				user_id_str = (char *)json_string_value(id);
				if(g_hash_table_lookup(audiobridge->participants, (gpointer)user_id_str)) {
					/* User ID already taken */
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					error_code = JANUS_AUDIOBRIDGE_ERROR_ID_EXISTS;
					JANUS_LOG(LOG_ERR, "User ID %s already exists\n", user_id_str);
					g_snprintf(error_cause, 512, "User ID %s already exists", user_id_str);
					goto error;
				}
			}
			if(user_id_str == NULL) {
				/* Generate a random ID */
				while(user_id_str == NULL) {
					user_id_str = janus_random_uuid();
					if(g_hash_table_lookup(audiobridge->participants, user_id_str) != NULL) {
						/* User ID already taken, try another one */
						g_clear_pointer(&user_id_str, g_free);
					}
				}
				user_id_allocated = TRUE;
			}
			JANUS_LOG(LOG_VERB, "  -- Participant ID: %s\n", user_id_str);
			if(participant == NULL) {
				participant = new janus_audiobridge_participant {};
				janus_refcount_init(&participant->ref, janus_audiobridge_participant_free);
				g_atomic_int_set(&participant->active, 0);
				participant->prebuffering = TRUE;
				participant->display = NULL;
				participant->inbuf = NULL;
				participant->outbuf = NULL;
				participant->last_drop = 0;
				participant->encoder = NULL;
				participant->decoder = NULL;
				participant->reset = FALSE;
				participant->fec = FALSE;
				participant->expected_seq = 0;
				participant->probation = 0;
				participant->last_timestamp = 0;
				janus_mutex_init(&participant->qmutex);
				participant->arc = NULL;
				janus_mutex_init(&participant->rec_mutex);
			}
			participant->session = session;
			participant->room = audiobridge;
			participant->user_id_str = g_strdup(user_id_str);
			g_free(participant->display);
			participant->admin = admin;
			participant->display = display_text ? g_strdup(display_text) : NULL;
			participant->muted = TRUE;	/* By default, everyone's muted when joining */
			participant->prebuffer_count = prebuffer_count;
			participant->volume_gain = volume;
			participant->opus_complexity = complexity;
			participant->opus_bitrate = opus_bitrate;
			participant->expected_loss = expected_loss;
			participant->stereo = audiobridge->spatial_audio;
			if(participant->stereo) {
				if(spatial_position > 100)
					spatial_position = 100;
				participant->spatial_position = spatial_position;
			}
			participant->user_audio_active_packets = json_integer_value(user_audio_active_packets);
			participant->user_audio_level_average = json_integer_value(user_audio_level_average);
			if(participant->outbuf == NULL)
				participant->outbuf = g_async_queue_new();
			g_atomic_int_set(&participant->active, g_atomic_int_get(&session->started));
			if(!g_atomic_int_get(&session->started)) {
				/* Initialize the RTP context only if we're renegotiating */
				janus_rtp_switching_context_reset(&participant->context);
				participant->opus_pt = 0;
				participant->extmap_id = 0;
				participant->dBov_level = 0;
				participant->talking = FALSE;
			}
			JANUS_LOG(LOG_VERB, "Creating Opus encoder/decoder (sampling rate %d)\n", audiobridge->sampling_rate);
			/* Opus encoder */
			int error = 0;
			if(participant->encoder == NULL) {
				participant->encoder = opus_encoder_create(audiobridge->sampling_rate,
					audiobridge->spatial_audio ? 2 : 1, OPUS_APPLICATION_VOIP, &error);
				if(error != OPUS_OK) {
					if(user_id_allocated) {
						g_free(user_id_str);
						g_free(participant->user_id_str);
					}
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					g_free(participant->display);
					delete participant;
					JANUS_LOG(LOG_ERR, "Error creating Opus encoder\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_LIBOPUS_ERROR;
					g_snprintf(error_cause, 512, "Error creating Opus encoder");
					goto error;
				}
				if(audiobridge->sampling_rate == 8000) {
					opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
				} else if(audiobridge->sampling_rate == 12000) {
					opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_MEDIUMBAND));
				} else if(audiobridge->sampling_rate == 16000) {
					opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
				} else if(audiobridge->sampling_rate == 24000) {
					opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_SUPERWIDEBAND));
				} else if(audiobridge->sampling_rate == 48000) {
					opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND));
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported sampling rate %d, setting 16kHz\n", audiobridge->sampling_rate);
					audiobridge->sampling_rate = 16000;
					opus_encoder_ctl(participant->encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
				}
				opus_encoder_ctl(participant->encoder, OPUS_SET_INBAND_FEC(participant->fec));
				opus_encoder_ctl(participant->encoder, OPUS_SET_PACKET_LOSS_PERC(participant->expected_loss));
			}
			opus_encoder_ctl(participant->encoder, OPUS_SET_COMPLEXITY(participant->opus_complexity));
			if(participant->opus_bitrate > 0)
				opus_encoder_ctl(participant->encoder, OPUS_SET_BITRATE(participant->opus_bitrate));
			if(participant->decoder == NULL) {
				/* Opus decoder */
				error = 0;
				participant->decoder = opus_decoder_create(audiobridge->sampling_rate,
					audiobridge->spatial_audio ? 2 : 1, &error);
				if(error != OPUS_OK) {
					if(user_id_allocated) {
						g_free(user_id_str);
						g_free(participant->user_id_str);
					}
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					g_free(participant->display);
					if(participant->encoder)
						opus_encoder_destroy(participant->encoder);
					participant->encoder = NULL;
					if(participant->decoder)
						opus_decoder_destroy(participant->decoder);
					participant->decoder = NULL;
					delete participant;
					JANUS_LOG(LOG_ERR, "Error creating Opus decoder\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_LIBOPUS_ERROR;
					g_snprintf(error_cause, 512, "Error creating Opus decoder");
					goto error;
				}
			}
			participant->reset = FALSE;
			/* Finally, start the encoding thread if it hasn't already */
			if(participant->thread == NULL) {
				GError *error = NULL;
				char roomtrunc[5], parttrunc[5];
				g_snprintf(roomtrunc, sizeof(roomtrunc), "%s", audiobridge->room_id_str);
				g_snprintf(parttrunc, sizeof(parttrunc), "%s", participant->user_id_str);
				char tname[16];
				g_snprintf(tname, sizeof(tname), "mixer %s %s", roomtrunc, parttrunc);
				janus_refcount_increase(&session->ref);
				janus_refcount_increase(&participant->ref);
				participant->thread = g_thread_try_new(tname, &janus_audiobridge_participant_thread, participant, &error);
				if(error != NULL) {
					janus_refcount_decrease(&participant->ref);
					janus_refcount_decrease(&session->ref);
					/* FIXME We should fail here... */
					JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the participant thread...\n",
						error->code, error->message ? error->message : "??");
					g_error_free(error);
				}
			}
			/* If a PeerConnection exists, make sure to update the RTP headers */
			if(g_atomic_int_get(&session->started) == 1)
				participant->context.last_ssrc = 0;

			/* Done */
			session->participant = participant;
			janus_refcount_increase(&participant->ref);
			g_hash_table_insert(audiobridge->participants, (gpointer)g_strdup(participant->user_id_str), participant);
			/* Notify the other participants */
			json_t *newuser = json_object();
			json_object_set_new(newuser, "audiobridge", json_string("joined"));
			json_object_set_new(newuser, "room", json_string(room_id_str));
			json_t *newuserlist = json_array();
			json_t *pl = json_object();
			json_object_set_new(pl, "id", json_string(participant->user_id_str));
			if(participant->display)
				json_object_set_new(pl, "display", json_string(participant->display));
			/* Clarify we're still waiting for the user to negotiate a PeerConnection */
			json_object_set_new(pl, "setup", json_false());
			json_object_set_new(pl, "muted", participant->muted ? json_true() : json_false());
			if(audiobridge->spatial_audio)
				json_object_set_new(pl, "spatial_position", json_integer(participant->spatial_position));
			json_array_append_new(newuserlist, pl);
			json_object_set_new(newuser, "participants", newuserlist);
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
				if(p == participant) {
					continue;
				}
				JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
				int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, newuser, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(newuser);
			/* Return a list of all available participants for the new participant now */
			json_t *list = json_array();
			g_hash_table_iter_init(&iter, audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
				if(p == participant) {
					continue;
				}
				json_t *pl = json_object();
				json_object_set_new(pl, "id", json_string(p->user_id_str));
				if(p->display)
					json_object_set_new(pl, "display", json_string(p->display));
				json_object_set_new(pl, "setup", g_atomic_int_get(&p->session->started) ? json_true() : json_false());
				json_object_set_new(pl, "muted", p->muted ? json_true() : json_false());
				if(p->extmap_id > 0)
					json_object_set_new(pl, "talking", p->talking ? json_true() : json_false());
				if(audiobridge->spatial_audio)
					json_object_set_new(pl, "spatial_position", json_integer(p->spatial_position));
				json_array_append_new(list, pl);
			}
			janus_mutex_unlock(&audiobridge->mutex);
			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("joined"));
			json_object_set_new(event, "room", json_string(room_id_str));
			json_object_set_new(event, "id", json_string(user_id_str));
			json_object_set_new(event, "participants", list);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("joined"));
				json_object_set_new(info, "room", json_string(room_id_str));
				json_object_set_new(info, "id", json_string(user_id_str));
				json_object_set_new(info, "display", json_string(participant->display));
				json_object_set_new(info, "setup", g_atomic_int_get(&participant->session->started) ? json_true() : json_false());
				json_object_set_new(info, "muted", participant->muted ? json_true() : json_false());
				if(participant->stereo)
					json_object_set_new(info, "spatial_position", json_integer(participant->spatial_position));
				gateway->notify_event(&janus_audiobridge_plugin, session->handle, info);
			}
			if(user_id_allocated)
				g_free(user_id_str);
			/* If we need to generate an offer ourselves, do that */
			if(gen_offer != NULL)
				generate_offer = json_is_true(gen_offer);
			if(generate_offer)
				session->plugin_offer = generate_offer;
		} else if(!strcasecmp(request_text, "configure")) {
			/* Handle this participant */
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				JANUS_LOG(LOG_ERR, "Can't configure (not in a room)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't configure (not in a room)");
				goto error;
			}
			/* Configure settings for this participant */
			JANUS_VALIDATE_JSON_OBJECT(root, configure_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *prebuffer = json_object_get(root, "prebuffer");
			json_t *bitrate = json_object_get(root, "bitrate");
			json_t *quality = json_object_get(root, "quality");
			json_t *exploss = json_object_get(root, "expected_loss");
			json_t *gain = json_object_get(root, "volume");
			json_t *spatial = json_object_get(root, "spatial_position");
			json_t *display = json_object_get(root, "display");
			json_t *gen_offer = json_object_get(root, "generate_offer");
			json_t *update = json_object_get(root, "update");
			if(prebuffer) {
				uint prebuffer_count = json_integer_value(prebuffer);
				if(prebuffer_count > MAX_PREBUFFERING) {
					JANUS_LOG(LOG_WARN, "Invalid prebuffering value provided (too high), keeping previous value: %d\n",
						participant->prebuffer_count);
				} else if(prebuffer_count != participant->prebuffer_count) {
					janus_mutex_lock(&participant->qmutex);
					if(prebuffer_count < participant->prebuffer_count) {
						/* We're switching to a shorter prebuffer, trim the incoming buffer */
						while(g_list_length(participant->inbuf) > prebuffer_count) {
							GList *first = g_list_first(participant->inbuf);
							janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)first->data;
							participant->inbuf = g_list_delete_link(participant->inbuf, first);
							if(pkt == NULL)
								continue;
							g_free(pkt->data);
							g_free(pkt);
						}
					} else {
						/* Reset the prebuffering state */
						participant->prebuffering = TRUE;
					}
					participant->prebuffer_count = prebuffer_count;
					janus_mutex_unlock(&participant->qmutex);
				}
			}
			if(gain)
				participant->volume_gain = json_integer_value(gain);
			if(bitrate) {
				int32_t opus_bitrate = bitrate ? json_integer_value(bitrate) : 0;
				if(opus_bitrate < 500 || opus_bitrate > 512000) {
					JANUS_LOG(LOG_WARN, "Invalid bitrate %" SCNi32 ", falling back to auto\n", opus_bitrate);
					opus_bitrate = 0;
				}
				participant->opus_bitrate = opus_bitrate;
				if(participant->encoder)
					opus_encoder_ctl(participant->encoder, OPUS_SET_BITRATE(participant->opus_bitrate ? participant->opus_bitrate : OPUS_AUTO));
			}
			if(quality) {
				int complexity = json_integer_value(quality);
				if(complexity < 1 || complexity > 10) {
					JANUS_LOG(LOG_ERR, "Invalid element (quality should be a positive integer between 1 and 10)\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (quality should be a positive integer between 1 and 10)");
					goto error;
				}
				participant->opus_complexity = complexity;
				if(participant->encoder)
					opus_encoder_ctl(participant->encoder, OPUS_SET_COMPLEXITY(participant->opus_complexity));
			}
			if(exploss) {
				int expected_loss = json_integer_value(exploss);
				if(expected_loss > 20) {
					JANUS_LOG(LOG_ERR, "Invalid element (expected_loss should be a positive integer between 0 and 20)\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (expected_loss should be a positive integer between 0 and 20)");
					goto error;
				}
				participant->expected_loss = expected_loss;
				if(participant->encoder)
					opus_encoder_ctl(participant->encoder, OPUS_SET_PACKET_LOSS_PERC(participant->expected_loss));
			}
			if(display || (participant->stereo && spatial)) {
				if(display) {
					char *old_display = participant->display;
					char *new_display = g_strdup(json_string_value(display));
					participant->display = new_display;
					g_free(old_display);
					JANUS_LOG(LOG_VERB, "Setting display property: %s (room %s, user %s)\n",
						participant->display, participant->room->room_id_str, participant->user_id_str);
				}
				if(participant->stereo && spatial) {
					int spatial_position = json_integer_value(spatial);
					if(spatial_position > 100)
						spatial_position = 100;
					participant->spatial_position = spatial_position;
				}
				/* Notify all other participants */
				janus_mutex_lock(&rooms_mutex);
				janus_audiobridge_room *audiobridge = participant->room;
				if(audiobridge != NULL) {
					janus_mutex_lock(&audiobridge->mutex);
					json_t *list = json_array();
					json_t *pl = json_object();
					json_object_set_new(pl, "id", json_string(participant->user_id_str));
					if(participant->display)
						json_object_set_new(pl, "display", json_string(participant->display));
					json_object_set_new(pl, "setup", g_atomic_int_get(&participant->session->started) ? json_true() : json_false());
					json_object_set_new(pl, "muted", participant->muted ? json_true() : json_false());
					if(audiobridge->spatial_audio)
						json_object_set_new(pl, "spatial_position", json_integer(participant->spatial_position));
					json_array_append_new(list, pl);
					json_t *pub = json_object();
					json_object_set_new(pub, "audiobridge", json_string("event"));
					json_object_set_new(pub, "room", json_string(participant->room->room_id_str));
					json_object_set_new(pub, "participants", list);
					GHashTableIter iter;
					gpointer value;
					g_hash_table_iter_init(&iter, audiobridge->participants);
					while(g_hash_table_iter_next(&iter, NULL, &value)) {
						janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
						if(p == participant) {
							continue;	/* Skip the new participant itself */
						}
						JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n",
							p->user_id_str, p->display ? p->display : "??");
						int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, pub, NULL);
						JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
					}
					json_decref(pub);
					janus_mutex_unlock(&audiobridge->mutex);
				}
				janus_mutex_unlock(&rooms_mutex);
			}
			gboolean do_update = update ? json_is_true(update) : FALSE;
			if(do_update && (!sdp_update || !session->plugin_offer)) {
				JANUS_LOG(LOG_WARN, "Got a 'update' request, but no SDP update? Ignoring...\n");
			}
			/* Done */
			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("event"));
			json_object_set_new(event, "result", json_string("ok"));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				janus_audiobridge_room *audiobridge = participant->room;
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("configured"));
				json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
				json_object_set_new(info, "id", json_string(participant->user_id_str));
				json_object_set_new(info, "display", json_string(participant->display));
				json_object_set_new(info, "muted", participant->muted ? json_true() : json_false());
				if(participant->opus_bitrate > 0)
					json_object_set_new(info, "bitrate", json_integer(participant->opus_bitrate));
				json_object_set_new(info, "quality", json_integer(participant->opus_complexity));
				if(participant->stereo)
					json_object_set_new(info, "spatial_position", json_integer(participant->spatial_position));
				gateway->notify_event(&janus_audiobridge_plugin, session->handle, info);
			}
			/* If we need to generate an offer ourselves, do that */
			if(do_update && session->plugin_offer) {
				/* We need an update and we originated an offer before, let's do it again */
				generate_offer = TRUE;
			} else if(gen_offer != NULL) {
				generate_offer = json_is_true(gen_offer);
			}
			if(generate_offer) {
				/* We should check if this conflicts with a user-generated offer from before */
				session->plugin_offer = generate_offer;
			}
		} else if(!strcasecmp(request_text, "self-unmute") || !strcasecmp(request_text, "self-mute")) {
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				JANUS_LOG(LOG_ERR, "Can't mute/unmute (not in a room)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't configure (not in a room)");
				goto error;
			}

			janus_mutex_lock(&rooms_mutex);
			janus_audiobridge_room *audiobridge = participant->room;
			janus_mutex_lock(&audiobridge->mutex);

			const gboolean muting = !strcasecmp(request_text, "self-mute");
			if(!muting && audiobridge->unmutedParticipant && audiobridge->unmutedParticipant != participant) {
				// check if unmutedParticipant was not active for too long time
				gboolean mute_forced = FALSE;
				struct janus_audiobridge_participant* unmutedParticipant = audiobridge->unmutedParticipant;
				janus_mutex_lock(&unmutedParticipant->qmutex);
				gint64 now = janus_get_monotonic_time();
				if(now - MAX(unmutedParticipant->inbuf_timestamp, unmutedParticipant->unmuted_timestamp) > PTT_NO_AUDIO_TIMEOUT*G_USEC_PER_SEC) {
					mute_forced = TRUE;
					JANUS_LOG(LOG_WARN, "Room \"%s\" already has unmuted but inactive user. Forcing mute...\n", participant->room->room_id_str);
					mute_participant(session, unmutedParticipant, TRUE, FALSE, FALSE);

					// Notify participant about forced mute
					json_t *participantInfo = json_object();
					json_object_set_new(participantInfo, "id", json_string(unmutedParticipant->user_id_str));
					if(unmutedParticipant->display)
						json_object_set_new(participantInfo, "display", json_string(unmutedParticipant->display));

					json_t *pub = json_object();
					json_object_set_new(pub, "audiobridge", json_string("forcibly-muted"));
					json_object_set_new(pub, "room", json_string(unmutedParticipant->room->room_id_str));
					json_object_set_new(pub, "participant", participantInfo);

					JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n",
						unmutedParticipant->user_id_str, unmutedParticipant->display ? unmutedParticipant->display : "??");
					int ret = gateway->push_event(unmutedParticipant->session->handle, &janus_audiobridge_plugin, NULL, pub, NULL);
					JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
					json_decref(pub);
				}
				janus_mutex_unlock(&unmutedParticipant->qmutex);

				if(!mute_forced) {
					JANUS_LOG(LOG_INFO, "Room \"%s\" already has unmuted user\n", participant->room->room_id_str);
					error_code = JANUS_AUDIOBRIDGE_ERROR_ROOM_ALREADY_HAS_UNMUTED_USER;
					g_snprintf(error_cause, 512, "Room \"%s\" already has unmuted user\n", participant->room->room_id_str);
					janus_mutex_unlock(&audiobridge->mutex);
					janus_mutex_unlock(&rooms_mutex);
					goto error;
				}
			}

			mute_participant(session, participant, muting, FALSE, TRUE);

			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);

			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("event"));
			json_object_set_new(event, "result", json_string("ok"));
		} else if(!strcasecmp(request_text, "changeroom")) {
			/* The participant wants to leave the current room and join another one without reconnecting (e.g., a sidebar) */
			JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *room = json_object_get(root, "room");
			char room_id_num[30], *room_id_str = NULL;
			room_id_str = (char *)json_string_value(room);
			janus_mutex_lock(&rooms_mutex);
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Can't change room (not in a room in the first place)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't change room (not in a room in the first place)");
				goto error;
			}
			/* Is this the same room we're in? */
			if(participant->room && (participant->room->room_id_str && !strcmp(participant->room->room_id_str, room_id_str))) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Already in this room\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_ALREADY_JOINED;
				g_snprintf(error_cause, 512, "Already in this room");
				goto error;
			}
			janus_audiobridge_room *audiobridge =
				(janus_audiobridge_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
			if(audiobridge == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				error_code = JANUS_AUDIOBRIDGE_ERROR_NO_SUCH_ROOM;
				JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
				g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
				goto error;
			}
			janus_refcount_increase(&audiobridge->ref);
			janus_mutex_lock(&audiobridge->mutex);
			/* A pin may be required for this action */
			JANUS_CHECK_SECRET(audiobridge->room_pin, root, "pin", error_code, error_cause,
				JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
			if(error_code != 0) {
				janus_mutex_unlock(&audiobridge->mutex);
				janus_refcount_decrease(&audiobridge->ref);
				janus_mutex_unlock(&rooms_mutex);
				goto error;
			}
			/* A token might be required too */
			if(audiobridge->check_tokens) {
				json_t *token = json_object_get(root, "token");
				const char *token_text = token ? json_string_value(token) : NULL;
				if(token_text == NULL || g_hash_table_lookup(audiobridge->allowed, token_text) == NULL) {
					JANUS_LOG(LOG_ERR, "Unauthorized (not in the allowed list)\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED;
					g_snprintf(error_cause, 512, "Unauthorized (not in the allowed list)");
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					janus_mutex_unlock(&rooms_mutex);
					goto error;
				}
			}
			gboolean admin = FALSE;
			if(json_object_get(root, "secret") != NULL) {
				/* The user is trying to present themselves as an admin */
				JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
					JANUS_AUDIOBRIDGE_ERROR_MISSING_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT, JANUS_AUDIOBRIDGE_ERROR_UNAUTHORIZED);
				if(error_code != 0) {
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					goto error;
				}
				admin = TRUE;
			}
			json_t *display = json_object_get(root, "display");
			const char *display_text = display ? json_string_value(display) : NULL;
			json_t *gain = json_object_get(root, "volume");
			json_t *spatial = json_object_get(root, "spatial_position");
			json_t *bitrate = json_object_get(root, "bitrate");
			json_t *quality = json_object_get(root, "quality");
			json_t *exploss = json_object_get(root, "expected_loss");
			int volume = gain ? json_integer_value(gain) : 100;
			int spatial_position = spatial ? json_integer_value(spatial) : 64;
			int32_t opus_bitrate = audiobridge->default_bitrate;
			if(bitrate) {
				opus_bitrate = json_integer_value(bitrate);
				if(opus_bitrate < 500 || opus_bitrate > 512000) {
					JANUS_LOG(LOG_WARN, "Invalid bitrate %" SCNi32 ", falling back to default/auto\n", opus_bitrate);
					opus_bitrate = audiobridge->default_bitrate;
				}
			}
			int complexity = quality ? json_integer_value(quality) : DEFAULT_COMPLEXITY;
			if(complexity < 1 || complexity > 10) {
				janus_mutex_unlock(&audiobridge->mutex);
				janus_refcount_decrease(&audiobridge->ref);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Invalid element (quality should be a positive integer between 1 and 10)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (quality should be a positive integer between 1 and 10)");
				goto error;
			}
			int expected_loss = exploss ? json_integer_value(exploss) : audiobridge->default_expectedloss;
			if(expected_loss > 20) {
				janus_mutex_unlock(&audiobridge->mutex);
				janus_refcount_decrease(&audiobridge->ref);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Invalid element (expected_loss should be a positive integer between 0 and 20)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (expected_loss should be a positive integer between 0 and 20)");
				goto error;
			}
			char user_id_num[30], *user_id_str = NULL;
			gboolean user_id_allocated = FALSE;
			json_t *id = json_object_get(root, "id");
			if(id) {
				user_id_str = (char *)json_string_value(id);
				if(g_hash_table_lookup(audiobridge->participants, (gpointer)user_id_str) != NULL) {
					/* User ID already taken */
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					janus_mutex_unlock(&rooms_mutex);
					error_code = JANUS_AUDIOBRIDGE_ERROR_ID_EXISTS;
					JANUS_LOG(LOG_ERR, "User ID %s already exists\n", user_id_str);
					g_snprintf(error_cause, 512, "User ID %s already exists", user_id_str);
					goto error;
				}
			}
			if(user_id_str == NULL) {
				/* Generate a random ID */
				while(user_id_str == NULL) {
					user_id_str = janus_random_uuid();
					if(g_hash_table_lookup(audiobridge->participants, user_id_str) != NULL) {
						/* User ID already taken, try another one */
						g_clear_pointer(&user_id_str, g_free);
					}
				}
				user_id_allocated = TRUE;
			}
			JANUS_LOG(LOG_VERB, "  -- Participant ID in new room %s: %s\n", room_id_str, user_id_str);
			participant->prebuffering = TRUE;
			participant->audio_active_packets = 0;
			participant->audio_dBov_sum = 0;
			participant->talking = FALSE;
			/* Is the sampling rate of the new room the same as the one in the old room, or should we update the decoder/encoder? */
			janus_audiobridge_room *old_audiobridge = participant->room;
			/* Leave the old room first... */
			janus_refcount_increase(&participant->ref);
			janus_mutex_lock(&old_audiobridge->mutex);
			if(old_audiobridge->unmutedParticipant == participant) {
				old_audiobridge->unmutedParticipant = NULL;
			}
			g_hash_table_remove(old_audiobridge->participants, (gpointer)participant->user_id_str);
			if(old_audiobridge->sampling_rate != audiobridge->sampling_rate ||
					old_audiobridge->spatial_audio != audiobridge->spatial_audio) {
				/* Create a new one that takes into account the sampling rate we want now */
				participant->stereo = audiobridge->spatial_audio;
				participant->spatial_position = 50;
				int error = 0;
				OpusEncoder *new_encoder = opus_encoder_create(audiobridge->sampling_rate,
					audiobridge->spatial_audio ? 2 : 1, OPUS_APPLICATION_VOIP, &error);
				if(error != OPUS_OK) {
					if(user_id_allocated)
						g_free(user_id_str);
					janus_refcount_decrease(&audiobridge->ref);
					if(new_encoder)
						opus_encoder_destroy(new_encoder);
					new_encoder = NULL;
					JANUS_LOG(LOG_ERR, "Error creating Opus encoder\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_LIBOPUS_ERROR;
					g_snprintf(error_cause, 512, "Error creating Opus encoder");
					/* Join the old room again... */
					g_hash_table_insert(audiobridge->participants, (gpointer)g_strdup(participant->user_id_str), participant);
					janus_mutex_unlock(&old_audiobridge->mutex);
					janus_mutex_unlock(&audiobridge->mutex);
					janus_mutex_unlock(&rooms_mutex);
					goto error;
				}
				if(audiobridge->sampling_rate == 8000) {
					opus_encoder_ctl(new_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
				} else if(audiobridge->sampling_rate == 12000) {
					opus_encoder_ctl(new_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_MEDIUMBAND));
				} else if(audiobridge->sampling_rate == 16000) {
					opus_encoder_ctl(new_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
				} else if(audiobridge->sampling_rate == 24000) {
					opus_encoder_ctl(new_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_SUPERWIDEBAND));
				} else if(audiobridge->sampling_rate == 48000) {
					opus_encoder_ctl(new_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND));
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported sampling rate %d, setting 16kHz\n", audiobridge->sampling_rate);
					audiobridge->sampling_rate = 16000;
					opus_encoder_ctl(new_encoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
				}
				opus_encoder_ctl(new_encoder, OPUS_SET_INBAND_FEC(participant->fec));
				/* Opus decoder */
				error = 0;
				OpusDecoder *new_decoder = opus_decoder_create(audiobridge->sampling_rate,
					audiobridge->spatial_audio ? 2 : 1, &error);
				if(error != OPUS_OK) {
					if(user_id_allocated)
						g_free(user_id_str);
					janus_refcount_decrease(&audiobridge->ref);
					if(new_encoder)
						opus_encoder_destroy(new_encoder);
					new_encoder = NULL;
					if(new_decoder)
						opus_decoder_destroy(new_decoder);
					new_decoder = NULL;
					JANUS_LOG(LOG_ERR, "Error creating Opus decoder\n");
					error_code = JANUS_AUDIOBRIDGE_ERROR_LIBOPUS_ERROR;
					g_snprintf(error_cause, 512, "Error creating Opus decoder");
					/* Join the old room again... */
					g_hash_table_insert(audiobridge->participants, (gpointer)g_strdup(participant->user_id_str), participant);
					janus_mutex_unlock(&old_audiobridge->mutex);
					janus_mutex_unlock(&audiobridge->mutex);
					janus_mutex_unlock(&rooms_mutex);
					goto error;
				}
				participant->reset = FALSE;
				/* Destroy the previous encoder/decoder and update the references */
				if(participant->encoder)
					opus_encoder_destroy(participant->encoder);
				participant->encoder = new_encoder;
				if(participant->decoder)
					opus_decoder_destroy(participant->decoder);
				participant->decoder = new_decoder;
			}
			if(quality)
				opus_encoder_ctl(participant->encoder, OPUS_SET_COMPLEXITY(participant->opus_complexity));
			/* Everything looks fine, start by telling the folks in the old room this participant is going away */

			json_t *participantInfo = json_object();
			json_object_set_new(participantInfo, "id", json_string(participant->user_id_str));
			if(participant->display)
				json_object_set_new(participantInfo, "display", json_string(participant->display));
			json_object_set_new(participantInfo, "muted", json_boolean(participant->muted));

			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("leaving"));
			json_object_set_new(event, "room", json_string(old_audiobridge->room_id_str));
			json_object_set(event, "participant", participantInfo);

			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, old_audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
				if(p == participant) {
					continue;	/* Skip the new participant itself */
				}
				JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
				int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, event, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(event);

			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("left"));
				json_object_set_new(info, "room", json_string(old_audiobridge->room_id_str));
				json_object_set(info, "participant", participantInfo);

				gateway->notify_event(&janus_audiobridge_plugin, session->handle, info);
			}
			json_decref(participantInfo);
			janus_mutex_unlock(&old_audiobridge->mutex);

			/* Stop recording, if we were (since this is a new room, a new recording would be required, so a new configure) */
			janus_mutex_lock(&participant->rec_mutex);
			janus_audiobridge_recorder_close(participant);
			janus_mutex_unlock(&participant->rec_mutex);
			janus_refcount_decrease(&old_audiobridge->ref);
			/* Done, join the new one */
			g_free(participant->user_id_str);
			participant->user_id_str = user_id_str ? g_strdup(user_id_str) : NULL;
			participant->admin = admin;
			g_free(participant->display);
			participant->display = display_text ? g_strdup(display_text) : NULL;
			participant->room = audiobridge;
			participant->muted = TRUE;	/* When switching to a new room, you're muted by default */
			participant->audio_active_packets = 0;
			participant->audio_dBov_sum = 0;
			participant->talking = FALSE;
			participant->volume_gain = volume;
			participant->stereo = audiobridge->spatial_audio;
			participant->spatial_position = spatial_position;
			if(participant->spatial_position < 0)
				participant->spatial_position = 0;
			else if(participant->spatial_position > 100)
				participant->spatial_position = 100;
			participant->opus_bitrate = opus_bitrate;
			if(participant->encoder)
				opus_encoder_ctl(participant->encoder, OPUS_SET_BITRATE(participant->opus_bitrate ? participant->opus_bitrate : OPUS_AUTO));
			if(quality) {
				participant->opus_complexity = complexity;
				if(participant->encoder)
					opus_encoder_ctl(participant->encoder, OPUS_SET_COMPLEXITY(participant->opus_complexity));
			}
			if(exploss) {
				participant->expected_loss = expected_loss;
				opus_encoder_ctl(participant->encoder, OPUS_SET_PACKET_LOSS_PERC(participant->expected_loss));
			}
			g_hash_table_insert(audiobridge->participants, (gpointer)g_strdup(participant->user_id_str), participant);
			/* Notify the other participants */
			json_t *newuser = json_object();
			json_object_set_new(newuser, "audiobridge", json_string("joined"));
			json_object_set_new(newuser, "room", json_string(audiobridge->room_id_str));
			json_t *newuserlist = json_array();
			json_t *pl = json_object();
			json_object_set_new(pl, "id", json_string(participant->user_id_str));
			if(participant->display)
				json_object_set_new(pl, "display", json_string(participant->display));
			json_object_set_new(pl, "setup", g_atomic_int_get(&participant->session->started) ? json_true() : json_false());
			json_object_set_new(pl, "muted", participant->muted ? json_true() : json_false());
			if(audiobridge->spatial_audio)
				json_object_set_new(pl, "spatial_position", json_integer(participant->spatial_position));
			json_array_append_new(newuserlist, pl);
			json_object_set_new(newuser, "participants", newuserlist);
			g_hash_table_iter_init(&iter, audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
				if(p == participant) {
					continue;
				}
				JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
				int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, newuser, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(newuser);
			/* Return a list of all available participants for the new participant now */
			json_t *list = json_array();
			g_hash_table_iter_init(&iter, audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
				if(p == participant) {
					continue;
				}
				json_t *pl = json_object();
				json_object_set_new(pl, "id", json_string(p->user_id_str));
				if(p->display)
					json_object_set_new(pl, "display", json_string(p->display));
				json_object_set_new(pl, "setup", g_atomic_int_get(&p->session->started) ? json_true() : json_false());
				json_object_set_new(pl, "muted", p->muted ? json_true() : json_false());
				if(p->extmap_id > 0)
					json_object_set_new(pl, "talking", p->talking ? json_true() : json_false());
				if(audiobridge->spatial_audio)
					json_object_set_new(pl, "spatial_position", json_integer(p->spatial_position));
				json_array_append_new(list, pl);
			}
			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("roomchanged"));
			json_object_set_new(event, "room", json_string(audiobridge->room_id_str));
			json_object_set_new(event, "id", json_string(user_id_str));
			json_object_set_new(event, "participants", list);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("joined"));
				json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
				json_object_set_new(info, "id", json_string(participant->user_id_str));
				json_object_set_new(info, "display", json_string(participant->display));
				json_object_set_new(info, "muted", participant->muted ? json_true() : json_false());
				if(participant->stereo)
					json_object_set_new(info, "spatial_position", json_integer(participant->spatial_position));
				gateway->notify_event(&janus_audiobridge_plugin, session->handle, info);
			}
			if(user_id_allocated)
				g_free(user_id_str);
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Get rid of an ongoing session */
			gateway->close_pc(session->handle);
			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("hangingup"));
		} else if(!strcasecmp(request_text, "leave")) {
			/* This participant is leaving */
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				JANUS_LOG(LOG_ERR, "Can't leave (not in a room)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't leave (not in a room)");
				goto error;
			}
			/* Tell everybody */
			janus_mutex_lock(&rooms_mutex);
			janus_audiobridge_room *audiobridge = participant->room;
			gboolean removed = FALSE;
			if(audiobridge != NULL) {
				janus_refcount_increase(&audiobridge->ref);
				janus_mutex_lock(&audiobridge->mutex);

				json_t *participantInfo = json_object();
				json_object_set_new(participantInfo, "id", json_string(participant->user_id_str));
				if(participant->display)
					json_object_set_new(participantInfo, "display", json_string(participant->display));
				json_object_set_new(participantInfo, "muted", json_boolean(participant->muted));

				event = json_object();
				json_object_set_new(event, "audiobridge", json_string("leaving"));
				json_object_set_new(event, "room", json_string(audiobridge->room_id_str));
				json_object_set(event, "participant", participantInfo);

				GHashTableIter iter;
				gpointer value;
				g_hash_table_iter_init(&iter, audiobridge->participants);
				while(g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_audiobridge_participant *p = (janus_audiobridge_participant *)value;
					if(p == participant) {
						continue;	/* Skip the new participant itself */
					}
					JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
					int ret = gateway->push_event(p->session->handle, &janus_audiobridge_plugin, NULL, event, NULL);
					JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				}
				json_decref(event);
				json_decref(participantInfo);

				/* Actually leave the room... */
				if(audiobridge->unmutedParticipant == participant) {
					audiobridge->unmutedParticipant = NULL;
				}
				removed = g_hash_table_remove(audiobridge->participants, (gpointer)participant->user_id_str);
				participant->room = NULL;
			}
			/* Get rid of queued packets */
			janus_mutex_lock(&participant->qmutex);
			g_atomic_int_set(&participant->active, 0);
			participant->prebuffering = TRUE;
			while(participant->inbuf) {
				GList *first = g_list_first(participant->inbuf);
				janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)first->data;
				participant->inbuf = g_list_delete_link(participant->inbuf, first);
				first = NULL;
				if(pkt == NULL)
					continue;
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
			}
			janus_mutex_unlock(&participant->qmutex);
			/* Stop recording, if we were */
			janus_mutex_lock(&participant->rec_mutex);
			janus_audiobridge_recorder_close(participant);
			janus_mutex_unlock(&participant->rec_mutex);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *participantInfo = json_object();
				json_object_set_new(participantInfo, "id", json_string(participant->user_id_str));
				if(participant->display)
					json_object_set_new(participantInfo, "display", json_string(participant->display));
				json_object_set_new(participantInfo, "muted", json_boolean(participant->muted));

				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("left"));
				json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
				json_object_set_new(info, "participant", participantInfo);

				gateway->notify_event(&janus_audiobridge_plugin, session->handle, info);
			}
			/* Done */
			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("left"));
			if(audiobridge != NULL) {
				json_object_set_new(event, "room", json_string(audiobridge->room_id_str));
				janus_mutex_unlock(&audiobridge->mutex);
				janus_refcount_decrease(&audiobridge->ref);
			}
			json_object_set_new(event, "id", json_string(participant->user_id_str));
			janus_mutex_unlock(&rooms_mutex);
			if(removed) {
				/* Only decrease the counter if we were still there */
				janus_refcount_decrease(&audiobridge->ref);
			}
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
			error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
			goto error;
		}

		/* Prepare JSON event */
		JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
		/* Any SDP to handle? */
		if(!msg_sdp && !generate_offer) {
			int ret = gateway->push_event(msg->handle, &janus_audiobridge_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
		} else {
			if(msg_sdp) {
				JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			} else {
				JANUS_LOG(LOG_VERB, "This is involving a negotiation: generating offer\n");
			}
			/* Prepare an SDP offer or answer */
			if(msg_sdp && json_is_true(json_object_get(msg->jsep, "e2ee"))) {
				/* Media is encrypted, but we need unencrypted media frames to decode and mix */
				json_decref(event);
				JANUS_LOG(LOG_ERR, "Media encryption unsupported by this plugin\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Media encryption unsupported by this plugin");
				goto error;
			}
			/* We answer by default, unless the user asked the plugin for an offer */
			if(msg_sdp && got_offer && session->plugin_offer) {
				json_decref(event);
				JANUS_LOG(LOG_ERR, "Received an offer on a plugin-offered session\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Received an offer on a plugin-offered session");
				goto error;
			} else if(msg_sdp && got_answer && !session->plugin_offer) {
				json_decref(event);
				JANUS_LOG(LOG_ERR, "Received an answer when we didn't send an offer\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Received an answer when we didn't send an offer");
				goto error;
			}
			const char *type = session->plugin_offer ? "offer" : "answer";
			char error_str[512];
			janus_sdp *sdp = NULL;
			if(msg_sdp != NULL) {
				sdp = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
				if(sdp == NULL) {
					json_decref(event);
					JANUS_LOG(LOG_ERR, "Error parsing %s: %s\n", msg_sdp, error_str);
					error_code = JANUS_AUDIOBRIDGE_ERROR_INVALID_SDP;
					g_snprintf(error_cause, 512, "Error parsing %s: %s", msg_sdp, error_str);
					goto error;
				}
			}
			if(got_offer) {
				if(sdp_update) {
					/* Renegotiation */
					JANUS_LOG(LOG_VERB, "Request to update existing connection\n");
					session->sdp_version++;		/* This needs to be increased when it changes */
				} else {
					/* New PeerConnection */
					session->sdp_version = 1;	/* This needs to be increased when it changes */
					session->sdp_sessid = janus_get_real_time();
				}
			}
			/* What is the Opus payload type? */
			janus_audiobridge_participant *participant = (janus_audiobridge_participant *)session->participant;
			if(sdp != NULL) {
				participant->opus_pt = janus_sdp_get_codec_pt(sdp, -1, "opus");
				if(participant->opus_pt > 0 && strstr(msg_sdp, "useinbandfec=1")){
					/* Opus codec, inband FEC setted */
					participant->fec = TRUE;
					participant->probation = MIN_SEQUENTIAL;
					opus_encoder_ctl(participant->encoder, OPUS_SET_INBAND_FEC(participant->fec));
				}
				JANUS_LOG(LOG_VERB, "Opus payload type is %d, FEC %s\n", participant->opus_pt, participant->fec ? "enabled" : "disabled");
			}
			/* Check if the audio level extension was offered */
			int extmap_id = generate_offer ? 2 : -1;
			if(sdp != NULL) {
				GList *temp = sdp->m_lines;
				while(temp) {
					janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
					if(m->type == JANUS_SDP_AUDIO) {
						GList *ma = m->attributes;
						while(ma) {
							janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
							if(a->value) {
								if(strstr(a->value, JANUS_RTP_EXTMAP_AUDIO_LEVEL)) {
									extmap_id = atoi(a->value);
									if(extmap_id < 0)
										extmap_id = 0;
								}
							}
							ma = ma->next;
						}
					}
					temp = temp->next;
				}
			}
			/* If we're just processing an answer, we're done */
			if(got_answer) {
				gint64 start = janus_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_audiobridge_plugin, msg->transaction, event, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %" SCNu64 " us)\n", res, janus_get_monotonic_time()-start);
				json_decref(event);
				janus_sdp_destroy(sdp);
				if(msg)
					janus_audiobridge_message_free(msg);
				msg = NULL;
				continue;
			}
			if(participant == NULL || participant->room == NULL) {
				JANUS_LOG(LOG_ERR, "Can't handle SDP (not in a room)\n");
				error_code = JANUS_AUDIOBRIDGE_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't handle SDP (not in a room)");
				if(sdp)
					janus_sdp_destroy(sdp);
				goto error;
			}
			/* We use a custom session name in the SDP */
			char s_name[100];
			g_snprintf(s_name, sizeof(s_name), "AudioBridge %s", participant->room->room_id_str);
			/* Prepare a fmtp string too */
			char fmtp[100];
			g_snprintf(fmtp, sizeof(fmtp), "%d maxplaybackrate=%" SCNu32 "; stereo=%d; sprop-stereo=%d; useinbandfec=%d\r\n",
				participant->opus_pt, participant->room->sampling_rate,
				participant->stereo ? 1 : 0, participant->stereo ? 1 : 0, participant->fec ? 1 : 0);
			/* If we got an offer, we need to answer */
			janus_sdp *offer = NULL, *answer = NULL;
			if(got_offer) {
				answer = janus_sdp_generate_answer(sdp);
				/* Only accept the first audio line, and reject everything else if offered */
				GList *temp = sdp->m_lines;
				gboolean accepted = FALSE;
				while(temp) {
					janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
					if(m->type == JANUS_SDP_AUDIO && !accepted) {
						accepted = TRUE;
						janus_sdp_generate_answer_mline(sdp, answer, m,
							JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
							JANUS_SDP_OA_CODEC, janus_audiocodec_name(JANUS_AUDIOCODEC_OPUS),
							JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
							JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_AUDIO_LEVEL,
							JANUS_SDP_OA_DONE);
					}
					temp = temp->next;
				}
				/* Replace the session name */
				g_free(answer->s_name);
				answer->s_name = g_strdup(s_name);
				/* Add an fmtp attribute */
				janus_sdp_attribute *a = janus_sdp_attribute_create("fmtp", "%s", fmtp);
				janus_sdp_attribute_add_to_mline(janus_sdp_mline_find(answer, JANUS_SDP_AUDIO), a);
				/* Let's overwrite a couple o= fields, in case this is a renegotiation */
				answer->o_sessid = session->sdp_sessid;
				answer->o_version = session->sdp_version;
			} else if(generate_offer) {
				/* We need to generate an offer ourselves */
				int pt = 100;
				offer = janus_sdp_generate_offer(
					s_name, "1.1.1.1",
					JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
						JANUS_SDP_OA_CODEC, janus_audiocodec_name(JANUS_AUDIOCODEC_OPUS),
						JANUS_SDP_OA_PT, pt,
						JANUS_SDP_OA_FMTP, fmtp,
						JANUS_SDP_OA_DIRECTION, JANUS_SDP_SENDRECV,
						JANUS_SDP_OA_EXTENSION, JANUS_RTP_EXTMAP_MID, 1,
						JANUS_SDP_OA_EXTENSION, JANUS_RTP_EXTMAP_AUDIO_LEVEL, extmap_id,
					JANUS_SDP_OA_DONE);
				/* Let's overwrite a couple o= fields, in case this is a renegotiation */
				if(session->sdp_version == 1) {
					session->sdp_sessid = offer->o_sessid;
				} else {
					offer->o_sessid = session->sdp_sessid;
					offer->o_version = session->sdp_version;
				}
			}
			/* Was the audio level extension negotiated? */
			participant->extmap_id = 0;
			participant->dBov_level = 0;
			if(extmap_id > -1 && participant->room && participant->room->audiolevel_ext) {
				/* Add an extmap attribute too */
				participant->extmap_id = extmap_id;
				/* If there's a recording, add the extension there */
				janus_mutex_lock(&participant->rec_mutex);
				if(participant->arc != NULL)
					janus_recorder_add_extmap(participant->arc, participant->extmap_id, JANUS_RTP_EXTMAP_AUDIO_LEVEL);
				janus_mutex_unlock(&participant->rec_mutex);
			}
			/* Prepare the response */
			char *new_sdp = janus_sdp_write(answer ? answer : offer);
			janus_sdp_destroy(sdp);
			janus_sdp_destroy(answer ? answer : offer);
			json_t *jsep = json_pack("{ssss}", "type", type, "sdp", new_sdp);
			/* How long will the Janus core take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_audiobridge_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %" SCNu64 " us)\n", res, janus_get_monotonic_time()-start);
			json_decref(event);
			json_decref(jsep);
			g_free(new_sdp);
			if(res != JANUS_OK) {
				/* TODO Failed to negotiate? We should remove this participant */
			} else {
				/* We'll notify all other participants when the PeerConnection has been established */
			}
		}
		if(msg)
			janus_audiobridge_message_free(msg);
		msg = NULL;

		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "audiobridge", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_audiobridge_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_audiobridge_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving AudioBridge handler thread\n");
	return NULL;
}

/* Thread to mix the contributions from all participants */
static void *janus_audiobridge_mixer_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Audio bridge thread starting...\n");
	janus_audiobridge_room *audiobridge = (janus_audiobridge_room *)data;
	if(!audiobridge) {
		JANUS_LOG(LOG_ERR, "Invalid room!\n");
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Thread is for mixing room %s (%s) at rate %" SCNu32 "...\n",
		audiobridge->room_id_str, audiobridge->room_name, audiobridge->sampling_rate);

	/* Buffer (we allocate assuming 48kHz, although we'll likely use less than that) */
	int samples = audiobridge->sampling_rate/50;
	if(audiobridge->spatial_audio)
		samples = samples*2;
	opus_int32 buffer[audiobridge->spatial_audio ? OPUS_SAMPLES*2 : OPUS_SAMPLES],
		sumBuffer[audiobridge->spatial_audio ? OPUS_SAMPLES*2 : OPUS_SAMPLES];
	opus_int16 outBuffer[audiobridge->spatial_audio ? OPUS_SAMPLES*2 : OPUS_SAMPLES],
		resampled[audiobridge->spatial_audio ? OPUS_SAMPLES*2 : OPUS_SAMPLES], *curBuffer = NULL;
	memset(buffer, 0, OPUS_SAMPLES*(audiobridge->spatial_audio ? 8 : 4));
	memset(sumBuffer, 0, OPUS_SAMPLES*(audiobridge->spatial_audio ? 8 : 4));
	memset(outBuffer, 0, OPUS_SAMPLES*(audiobridge->spatial_audio ? 4 : 2));
	memset(resampled, 0, OPUS_SAMPLES*(audiobridge->spatial_audio ? 4 : 2));

	/* Base RTP packets, in case there are forwarders involved */
	gboolean have_opus;
	unsigned char *rtpbuffer = (unsigned char *)g_malloc0(1500);
	janus_rtp_header *rtph = NULL;

	/* Timer */
	struct timeval now, before;
	gettimeofday(&before, NULL);
	now.tv_sec = before.tv_sec;
	now.tv_usec = before.tv_usec;
	time_t passed, d_s, d_us;

	/* RTP */
	guint16 seq = 0;
	guint32 ts = 0;
	/* SRTP buffer, if needed */
	char sbuf[1500];

	/* Loop */
	int i=0;
	int count = 0, rf_count = 0, prev_count = 0;
	int lgain = 0, rgain = 0, diff = 0;
	while(!g_atomic_int_get(&stopping) && !g_atomic_int_get(&audiobridge->destroyed)) {
		/* See if it's time to prepare a frame */
		gettimeofday(&now, NULL);
		d_s = now.tv_sec - before.tv_sec;
		d_us = now.tv_usec - before.tv_usec;
		if(d_us < 0) {
			d_us += 1000000;
			--d_s;
		}
		passed = d_s*1000000 + d_us;
		if(passed < 15000) {	/* Let's wait about 15ms at max */
			g_usleep(5000);
			continue;
		}
		/* Update the reference time */
		before.tv_usec += 20000;
		if(before.tv_usec > 1000000) {
			before.tv_sec++;
			before.tv_usec -= 1000000;
		}
		/* Do we need to mix at all? */
		janus_mutex_lock_nodebug(&audiobridge->mutex);
		count = g_hash_table_size(audiobridge->participants);
		rf_count = g_hash_table_size(audiobridge->rtp_forwarders);
		if((count+rf_count) == 0) {
			janus_mutex_unlock_nodebug(&audiobridge->mutex);
			/* No participant and RTP forwarders, do nothing */
			if(prev_count > 0) {
				JANUS_LOG(LOG_INFO, "Last user/forwarder/file just left room %s, going idle...\n", audiobridge->room_id_str);
				prev_count = 0;
			}
			continue;
		}
		if(prev_count == 0) {
			JANUS_LOG(LOG_INFO, "First user/forwarder/file just joined room %s, waking it up...\n", audiobridge->room_id_str);
		}
		prev_count = count+rf_count;
		/* Update RTP header information */
		seq++;
		ts += OPUS_SAMPLES;
		/* Mix all contributions */
		GList *participants_list = g_hash_table_get_values(audiobridge->participants);
		/* Add a reference to all these participants, in case some leave while we're mixing */
		GList *ps = participants_list;
		while(ps) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
			janus_refcount_increase(&p->ref);
			ps = ps->next;
		}
		janus_mutex_unlock_nodebug(&audiobridge->mutex);
		for(i=0; i<samples; i++)
			buffer[i] = 0;
		ps = participants_list;
		while(ps) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
			janus_mutex_lock(&p->qmutex);
			if(g_atomic_int_get(&p->destroyed) || !p->session || !g_atomic_int_get(&p->session->started) || !g_atomic_int_get(&p->active) || p->muted || p->prebuffering || !p->inbuf) {
				janus_mutex_unlock(&p->qmutex);
				ps = ps->next;
				continue;
			}
			GList *peek = g_list_first(p->inbuf);
			janus_audiobridge_rtp_relay_packet *pkt = (janus_audiobridge_rtp_relay_packet *)(peek ? peek->data : NULL);
			if(pkt != NULL && !pkt->silence) {
				curBuffer = (opus_int16 *)pkt->data;
				/* Add to the main mix */
				if(!p->stereo) {
					for(i=0; i<samples; i++) {
						if(p->volume_gain == 100) {
							buffer[i] += curBuffer[i];
						} else {
							buffer[i] += (curBuffer[i]*p->volume_gain)/100;
						}
					}
				} else {
					diff = 50 - p->spatial_position;
					lgain = 50 + diff;
					rgain = 50 - diff;
					for(i=0; i<samples; i++) {
						if(i%2 == 0) {
							if(lgain == 100) {
								if(p->volume_gain == 100) {
									buffer[i] += curBuffer[i];
								} else {
									buffer[i] += (curBuffer[i]*p->volume_gain)/100;
								}
							} else {
								if(p->volume_gain == 100) {
									buffer[i] += (curBuffer[i]*lgain)/100;
								} else {
									buffer[i] += (((curBuffer[i]*lgain)/100)*p->volume_gain)/100;
								}
							}
						} else {
							if(rgain == 100) {
								if(p->volume_gain == 100) {
									buffer[i] += curBuffer[i];
								} else {
									buffer[i] += (curBuffer[i]*p->volume_gain)/100;
								}
							} else {
								if(p->volume_gain == 100) {
									buffer[i] += (curBuffer[i]*rgain)/100;
								} else {
									buffer[i] += (((curBuffer[i]*rgain)/100)*p->volume_gain)/100;
								}
							}
						}
					}
				}
			}
			janus_mutex_unlock(&p->qmutex);
			ps = ps->next;
		}
		/* Send proper packet to each participant (remove own contribution) */
		ps = participants_list;
		while(ps) {
			janus_audiobridge_participant *p = (janus_audiobridge_participant *)ps->data;
			if(g_atomic_int_get(&p->destroyed) || !p->session || !g_atomic_int_get(&p->session->started)) {
				janus_refcount_decrease(&p->ref);
				ps = ps->next;
				continue;
			}
			janus_audiobridge_rtp_relay_packet *pkt = NULL;
			janus_mutex_lock(&p->qmutex);
			if(g_atomic_int_get(&p->active) && !p->muted && !p->prebuffering && p->inbuf) {
				GList *first = g_list_first(p->inbuf);
				pkt = (janus_audiobridge_rtp_relay_packet *)(first ? first->data : NULL);
				p->inbuf = g_list_delete_link(p->inbuf, first);
			}
			janus_mutex_unlock(&p->qmutex);
			/* Remove the participant's own contribution */
			curBuffer = (opus_int16 *)((pkt && pkt->length && !pkt->silence) ? pkt->data : NULL);
			if(!p->stereo) {
				for(i=0; i<samples; i++) {
					if(p->volume_gain == 100)
						sumBuffer[i] = buffer[i] - (curBuffer ? (curBuffer[i]) : 0);
					else
						sumBuffer[i] = buffer[i] - (curBuffer ? (curBuffer[i]*p->volume_gain)/100 : 0);
				}
			} else {
				diff = 50 - p->spatial_position;
				lgain = 50 + diff;
				rgain = 50 - diff;
				for(i=0; i<samples; i++) {
					if(i%2 == 0) {
						if(lgain == 100) {
							sumBuffer[i] = buffer[i] - (curBuffer ? (curBuffer[i]) : 0);
						} else {
							sumBuffer[i] = buffer[i] - (curBuffer ? (curBuffer[i]*lgain)/100 : 0);
						}
					} else {
						if(rgain == 100) {
							sumBuffer[i] = buffer[i] - (curBuffer ? (curBuffer[i]) : 0);
						} else {
							sumBuffer[i] = buffer[i] - (curBuffer ? (curBuffer[i]*rgain)/100 : 0);
						}
					}
				}
			}
			for(i=0; i<samples; i++)
				/* FIXME Smoothen/Normalize instead of truncating? */
				outBuffer[i] = sumBuffer[i];
			/* Enqueue this mixed frame for encoding in the participant thread */
			janus_audiobridge_rtp_relay_packet *mixedpkt = (janus_audiobridge_rtp_relay_packet *)g_malloc(sizeof(janus_audiobridge_rtp_relay_packet));
			mixedpkt->data = (janus_rtp_header *)g_malloc(samples*2);
			/* Just copy */
			memcpy(mixedpkt->data, outBuffer, samples*2);
			mixedpkt->length = samples;	/* We set the number of samples here, not the data length */
			mixedpkt->timestamp = ts;
			mixedpkt->seq_number = seq;
			mixedpkt->ssrc = audiobridge->room_ssrc;
			mixedpkt->silence = FALSE;
			g_async_queue_push(p->outbuf, mixedpkt);
			if(pkt) {
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
			}
			janus_refcount_decrease(&p->ref);
			ps = ps->next;
		}
		g_list_free(participants_list);
		/* Forward the mixed packet as RTP to any RTP forwarder that may be listening */
		janus_mutex_lock(&audiobridge->rtp_mutex);
		if(g_hash_table_size(audiobridge->rtp_forwarders) > 0 && audiobridge->rtp_encoder) {
			/* If the room is empty, check if there's any RTP forwarder with an "always on" option */
			gboolean go_on = FALSE;
			if(count == 0) {
				GHashTableIter iter;
				gpointer value;
				g_hash_table_iter_init(&iter, audiobridge->rtp_forwarders);
				while(g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_audiobridge_rtp_forwarder *forwarder = (janus_audiobridge_rtp_forwarder *)value;
					if(forwarder->always_on) {
						go_on = TRUE;
						break;
					}
				}
			} else {
				go_on = TRUE;
			}
			if(go_on) {
				/* By default, let's send the mixed frame to everybody */
				for(i=0; i<samples; i++)
					outBuffer[i] = buffer[i];
				have_opus = FALSE;
				GHashTableIter iter;
				gpointer key, value;
				g_hash_table_iter_init(&iter, audiobridge->rtp_forwarders);
				opus_int32 length = 0;
				while(audiobridge->rtp_udp_sock > 0 && g_hash_table_iter_next(&iter, &key, &value)) {
					guint32 stream_id = GPOINTER_TO_UINT(key);
					janus_audiobridge_rtp_forwarder *forwarder = (janus_audiobridge_rtp_forwarder *)value;
					if(count == 0 && !forwarder->always_on)
						continue;
					for(i=0; i<samples; i++)
						outBuffer[i] = buffer[i];
					/* This is an Opus forwarder, check if we have a version for that already */
					if(!have_opus) {
						/* We don't, encode now */
						OpusEncoder *rtp_encoder = audiobridge->rtp_encoder;
						length = opus_encode(rtp_encoder, outBuffer,
							audiobridge->spatial_audio ? samples/2 : samples,
							rtpbuffer + 12, 1500-12);
						if(length < 0) {
							JANUS_LOG(LOG_ERR, "[Opus] Ops! got an error encoding the Opus frame: %d (%s)\n", length, opus_strerror(length));
							continue;
						}
						have_opus = TRUE;
					}
					rtph = (janus_rtp_header *)(rtpbuffer);
					rtph->version = 2;
					/* Update header */
					rtph->type = forwarder->payload_type;
					rtph->ssrc = htonl(forwarder->ssrc ? forwarder->ssrc : stream_id);
					forwarder->seq_number++;
					rtph->seq_number = htons(forwarder->seq_number);
					forwarder->timestamp += OPUS_SAMPLES;
					rtph->timestamp = htonl(forwarder->timestamp);
					/* Check if this packet needs to be encrypted */
					char *payload = (char *)rtph;
					int plen = length+12;
					if(forwarder->is_srtp) {
						memcpy(sbuf, payload, plen);
						int protected_ = plen;
						int res = srtp_protect(forwarder->srtp_ctx, sbuf, &protected_);
						if(res != srtp_err_status_ok) {
							janus_rtp_header *header = (janus_rtp_header *)sbuf;
							guint32 timestamp = ntohl(header->timestamp);
							guint16 seq = ntohs(header->seq_number);
							JANUS_LOG(LOG_ERR, "Error encrypting RTP packet for room %s... %s (len=%d-->%d, ts=%" SCNu32 ", seq=%" SCNu16 ")...\n",
								audiobridge->room_id_str, janus_srtp_error_str(res), plen, protected_, timestamp, seq);
						} else {
							payload = (char *)&sbuf;
							plen = protected_;
						}
					}
					/* No encryption, send the RTP packet as it is */
					struct sockaddr *address = (forwarder->serv_addr.sin_family == AF_INET ?
						(struct sockaddr *)&forwarder->serv_addr : (struct sockaddr *)&forwarder->serv_addr6);
					size_t addrlen = (forwarder->serv_addr.sin_family == AF_INET ? sizeof(forwarder->serv_addr) : sizeof(forwarder->serv_addr6));
					if(sendto(audiobridge->rtp_udp_sock, payload, plen, 0, address, addrlen) < 0) {
						JANUS_LOG(LOG_HUGE, "Error forwarding mixed RTP packet for room %s... %s (len=%d)...\n",
							audiobridge->room_id_str, g_strerror(errno), plen);
					}
				}
			}
		}
		janus_mutex_unlock(&audiobridge->rtp_mutex);
	}
	g_free(rtpbuffer);
	JANUS_LOG(LOG_VERB, "Leaving mixer thread for room %s (%s)...\n", audiobridge->room_id_str, audiobridge->room_name);

	janus_refcount_decrease(&audiobridge->ref);

	return NULL;
}

/* Thread to encode a mixed frame and send it to a specific participant */
static void *janus_audiobridge_participant_thread(void *data) {
	JANUS_LOG(LOG_VERB, "AudioBridge Participant thread starting...\n");
	janus_audiobridge_participant *participant = (janus_audiobridge_participant *)data;
	if(!participant) {
		JANUS_LOG(LOG_ERR, "Invalid participant!\n");
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Thread is for participant %s (%s)\n",
		participant->user_id_str, participant->display ? participant->display : "??");
	janus_audiobridge_session *session = participant->session;

	/* Output buffer */
	janus_audiobridge_rtp_relay_packet *outpkt = (janus_audiobridge_rtp_relay_packet *)g_malloc(sizeof(janus_audiobridge_rtp_relay_packet));
	outpkt->data = (janus_rtp_header *)g_malloc0(1500);
	outpkt->ssrc = 0;
	outpkt->timestamp = 0;
	outpkt->seq_number = 0;
	outpkt->length = 0;
	outpkt->silence = FALSE;
	uint8_t *payload = (uint8_t *)outpkt->data;

	janus_audiobridge_rtp_relay_packet *mixedpkt = NULL;

	/* Start working: check the outgoing queue for packets, then encode and send them */
	while(!g_atomic_int_get(&stopping) && g_atomic_int_get(&session->destroyed) == 0) {
		mixedpkt = (janus_audiobridge_rtp_relay_packet *)g_async_queue_timeout_pop(participant->outbuf, 100000);
		if(mixedpkt != NULL && g_atomic_int_get(&session->destroyed) == 0 && g_atomic_int_get(&session->started)) {
			if(g_atomic_int_get(&participant->active) && participant->encoder &&
					g_atomic_int_compare_and_exchange(&participant->encoding, 0, 1)) {
				/* Encode raw frame to Opus */
				opus_int16 *outBuffer = (opus_int16 *)mixedpkt->data;
				outpkt->length = opus_encode(participant->encoder, outBuffer,
					participant->stereo ? mixedpkt->length/2 : mixedpkt->length, payload+12, 1500-12);
				g_atomic_int_set(&participant->encoding, 0);
				if(outpkt->length < 0) {
					JANUS_LOG(LOG_ERR, "[Opus] Ops! got an error encoding the Opus frame: %d (%s)\n", outpkt->length, opus_strerror(outpkt->length));
				} else {
					outpkt->length += 12;	/* Take the RTP header into consideration */
					/* Update RTP header */
					outpkt->data->version = 2;
					outpkt->data->markerbit = 0;	/* FIXME Should be 1 for the first packet */
					outpkt->data->seq_number = htons(mixedpkt->seq_number);
					outpkt->data->timestamp = htonl(mixedpkt->timestamp);
					outpkt->data->ssrc = htonl(mixedpkt->ssrc);	/* The Janus core will fix this anyway */
					/* Backup the actual timestamp and sequence number set by the audiobridge, in case a room is changed */
					outpkt->ssrc = mixedpkt->ssrc;
					outpkt->timestamp = mixedpkt->timestamp;
					outpkt->seq_number = mixedpkt->seq_number;
					janus_audiobridge_relay_rtp_packet(participant->session, outpkt);
				}
			}
			g_free(mixedpkt->data);
			g_free(mixedpkt);
		}
	}
	/* We're done, get rid of the resources */
	g_free(outpkt->data);
	g_free(outpkt);
	JANUS_LOG(LOG_VERB, "AudioBridge Participant thread leaving...\n");

	janus_refcount_decrease(&participant->ref);
	janus_refcount_decrease(&session->ref);
	g_thread_unref(g_thread_self());
	return NULL;
}

static void janus_audiobridge_relay_rtp_packet(gpointer data, gpointer user_data) {
	janus_audiobridge_rtp_relay_packet *packet = (janus_audiobridge_rtp_relay_packet *)user_data;
	if(!packet || !packet->data || packet->length < 1) {
		JANUS_LOG(LOG_ERR, "Invalid packet...\n");
		return;
	}
	janus_audiobridge_session *session = (janus_audiobridge_session *)data;
	if(!session || !session->handle) {
		/* JANUS_LOG(LOG_ERR, "Invalid session...\n"); */
		return;
	}
	if(!g_atomic_int_get(&session->started)) {
		/* JANUS_LOG(LOG_ERR, "Streaming not started yet for this session...\n"); */
		return;
	}
	janus_audiobridge_participant *participant = session->participant;
	/* Set the payload type */
	packet->data->type = participant->opus_pt;
	/* Fix sequence number and timestamp (room switching may be involved) */
	janus_rtp_header_update(packet->data, &participant->context, FALSE, 0);
	if(gateway != NULL) {
		janus_plugin_rtp rtp = { .mindex = -1, .video = FALSE, .buffer = (char *)packet->data, .length = (uint16_t)packet->length };
		janus_plugin_rtp_extensions_reset(&rtp.extensions);
		/* FIXME Should we add our own audio level extension? */
		gateway->relay_rtp(session->handle, &rtp);
	}
	/* Restore the timestamp and sequence number to what the mixer set them to */
	packet->data->timestamp = htonl(packet->timestamp);
	packet->data->seq_number = htons(packet->seq_number);
}
