/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "ptt_audioroom_plugin.h"

#include <cassert>
#include <memory>
#include <thread>

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
#include "janus/sdp-utils.h"
#include "janus/utils.h"
#include "janus/ip-utils.h"
}

#include "constants.h"
#include "plugin_session.h"
#include "ptt_room.h"
#include "room_participant.h"
#include "rtp_relay_packet.h"
#include "rtp_forwarder.h"
#include "room_message.h"
#include "event_handlers.h"
#include "record.h"
#include "thread_type.h"
#include "janus_mutex_lock_guard.h"
using namespace ptt_audioroom;

/* Plugin methods */
extern "C" janus_plugin *create(void);
static int plugin_init(janus_callbacks *callback, const char *config_path);
static void plugin_destroy(void);
static int plugin_get_api_compatibility(void);
static int plugin_get_version(void);
static const char *plugin_get_version_string(void);
static const char *plugin_get_description(void);
static const char *plugin_get_name(void);
static const char *plugin_get_author(void);
static const char *plugin_get_package(void);
static void create_session(janus_plugin_session *handle, int *error);

// following function bound to thread_type::INCOMING_RTP
static void setup_media(janus_plugin_session *handle);
static void incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet);
static void hangup_media(janus_plugin_session *handle);
static void destroy_session(janus_plugin_session *handle, int *error);

namespace ptt_audioroom {
/* Plugin setup */
janus_plugin ptt_audioroom_plugin =
	janus_plugin{
		.init = plugin_init,
		.destroy = plugin_destroy,

		.get_api_compatibility = plugin_get_api_compatibility,
		.get_version = plugin_get_version,
		.get_version_string = plugin_get_version_string,
		.get_description = plugin_get_description,
		.get_name = plugin_get_name,
		.get_author = plugin_get_author,
		.get_package = plugin_get_package,

		.create_session = create_session,
		.handle_message = handle_message,
		.handle_admin_message = handle_admin_message,
		.setup_media = setup_media,
		.incoming_rtp = incoming_rtp,
		.hangup_media = hangup_media,
		.destroy_session = destroy_session,
		.query_session = query_session,
	};
}

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", PTT_AUDIOROOM_NAME);
	return &ptt_audioroom_plugin;
}

namespace ptt_audioroom {
/* Static configuration instance */
janus_config *config = NULL;
const char *config_folder = NULL;
janus_mutex config_mutex = JANUS_MUTEX_INITIALIZER;
}

/* Useful stuff */
namespace ptt_audioroom {
gint initialized = 0, stopping = 0;
gboolean notify_events = TRUE;
gboolean ipv6_disabled = FALSE;
janus_callbacks *gateway = NULL;
}
static GThread *handler_thread;
static void relay_rtp_packet(room_participant *participant, plugin_session* session, rtp_relay_packet *packet);
static void hangup_media_internal(janus_plugin_session *handle);

namespace ptt_audioroom {
GAsyncQueue *messages = NULL;
}

namespace ptt_audioroom {
GHashTable *rooms;
janus_mutex rooms_mutex = JANUS_MUTEX_INITIALIZER;
char *admin_key = NULL;
gboolean lock_rtpfwd = FALSE;
}


static int create_static_rtp_forwarder(janus_config_category *cat, ptt_room *audiobridge) {
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

	if(create_udp_socket_if_needed(audiobridge)) {
		janus_mutex_unlock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);
		return -1;
	}

	rtp_forwarder_add_helper(audiobridge,
		host, port, ssrc_value, ptype, srtp_suite, srtp_crypto,
		always_on, forwarder_id);

	janus_mutex_unlock(&audiobridge->mutex);
	janus_mutex_unlock(&rooms_mutex);

	return 0;
}

/* Plugin implementation */
int plugin_init(janus_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, PTT_AUDIOROOM_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", PTT_AUDIOROOM_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, PTT_AUDIOROOM_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	config_folder = config_path;
	if(config != NULL)
		janus_config_print(config);

	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)plugin_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) room_message_free);
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
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", PTT_AUDIOROOM_NAME);
		}
	}

	/* Iterate on all rooms */
	rooms = g_hash_table_new_full(g_str_hash, g_str_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)ptt_room_destroy);
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
			janus_config_item *audiolevel_ext = janus_config_get(config, cat, janus_config_type_item, "audiolevel_ext");
			janus_config_item *audiolevel_event = janus_config_get(config, cat, janus_config_type_item, "audiolevel_event");
			janus_config_item *audio_active_packets = janus_config_get(config, cat, janus_config_type_item, "audio_active_packets");
			janus_config_item *audio_level_average = janus_config_get(config, cat, janus_config_type_item, "audio_level_average");
			janus_config_item *default_prebuffering = janus_config_get(config, cat, janus_config_type_item, "default_prebuffering");
			janus_config_item *secret = janus_config_get(config, cat, janus_config_type_item, "secret");
			janus_config_item *pin = janus_config_get(config, cat, janus_config_type_item, "pin");
			janus_config_item *mjrs = janus_config_get(config, cat, janus_config_type_item, "mjrs");
			janus_config_item *mjrsdir = janus_config_get(config, cat, janus_config_type_item, "mjrs_dir");
			/* Create the AudioBridge room */
			ptt_room *audiobridge = new ptt_room {};
			janus_refcount_init(&audiobridge->ref, ptt_room_free);
			const char *room_num = cat->name;
			if(strstr(room_num, "room-") == room_num)
				room_num += 5;
			/* Let's make sure the room doesn't exist already */
			janus_mutex_lock(&rooms_mutex);
			if(g_hash_table_lookup(rooms, (gpointer)room_num) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Can't add the AudioBridge room, room %s already exists...\n", room_num);
				ptt_room_destroy(audiobridge);
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
				(GDestroyNotify)g_free, (GDestroyNotify)participant_unref);
			audiobridge->check_tokens = FALSE;	/* Static rooms can't have an "allowed" list yet, no hooks to the configuration file */
			audiobridge->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
			g_atomic_int_set(&audiobridge->destroyed, 0);
			janus_mutex_init(&audiobridge->mutex);
			audiobridge->rtp_forwarders = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)rtp_forwarder_destroy);
			audiobridge->rtp_udp_sock = -1;
			janus_mutex_init(&audiobridge->rtp_mutex);
			JANUS_LOG(LOG_VERB, "Created AudioBridge room: %s (%s, %s, secret: %s, pin: %s)\n",
				audiobridge->room_id_str, audiobridge->room_name,
				audiobridge->is_private ? "private" : "public",
				audiobridge->room_secret ? audiobridge->room_secret : "no secret",
				audiobridge->room_pin ? audiobridge->room_pin : "no pin");

			if(create_static_rtp_forwarder(cat, audiobridge)) {
				JANUS_LOG(LOG_ERR, "Error creating static RTP forwarder (room %s)\n", audiobridge->room_id_str);
			}

			/* We need a thread for the send */
			GError *error = NULL;
			char tname[16];
			g_snprintf(tname, sizeof(tname), "sender %s", audiobridge->room_id_str);
			janus_refcount_increase(&audiobridge->ref);
			audiobridge->thread = g_thread_try_new(tname, &participants_sender_thread, audiobridge, &error);
			if(error != NULL) {
				/* FIXME We should clear some resources... */
				janus_refcount_decrease(&audiobridge->ref);
				JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the sender thread...\n",
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
		ptt_room *ar = (ptt_room *)value;
		JANUS_LOG(LOG_VERB, "  ::: [%s][%s]\n", ar->room_id_str, ar->room_name);
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
	handler_thread = g_thread_try_new("audiobridge handler", message_handler_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the AudioBridge handler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		janus_config_destroy(config);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", PTT_AUDIOROOM_NAME);
	return 0;
}

void plugin_destroy(void) {
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
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", PTT_AUDIOROOM_NAME);
}

int plugin_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int plugin_get_version(void) {
	return PTT_AUDIOROOM_VERSION;
}

const char *plugin_get_version_string(void) {
	return PTT_AUDIOROOM_VERSION_STRING;
}

const char *plugin_get_description(void) {
	return PTT_AUDIOROOM_DESCRIPTION;
}

const char *plugin_get_name(void) {
	return PTT_AUDIOROOM_NAME;
}

const char *plugin_get_author(void) {
	return PTT_AUDIOROOM_AUTHOR;
}

const char *plugin_get_package(void) {
	return PTT_AUDIOROOM_PACKAGE;
}

void create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	plugin_session *session = (plugin_session *)g_malloc0(sizeof(plugin_session));
	session->handle = handle;
	g_atomic_int_set(&session->started, 0);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	handle->plugin_handle = session;
	janus_refcount_init(&session->ref, plugin_session_free);

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void destroy_session(janus_plugin_session *handle, int *error) {
	assert_thread_type_is(thread_type::INCOMING_RTP);

	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	plugin_session *session = lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No AudioBridge session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing AudioBridge session...\n");
	hangup_media_internal(handle);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

static void notify_participants(room_participant *participant, json_t *msg, gboolean notify_source_participant) {
	/* participant->room->participants_mutex has to be locked. */
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, participant->room->participants);
	while(!participant->room->destroyed && g_hash_table_iter_next(&iter, NULL, &value)) {
		room_participant *p = (room_participant *)value;
		if(p && p->session && (p != participant || notify_source_participant)) {
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, msg, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
	}
}

void setup_media(janus_plugin_session *handle) {
	assign_thread_type(thread_type::INCOMING_RTP);

	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", PTT_AUDIOROOM_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	plugin_session *session = lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	room_participant *participant = (room_participant *)session->participant;
	if(!participant) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}

	assert(participant->incoming_rtp_thread_id == std::thread::id() || participant->incoming_rtp_thread_id == std::this_thread::get_id());
	participant->incoming_rtp_thread_id = std::this_thread::get_id();

	g_atomic_int_set(&session->hangingup, 0);
	/* FIXME Only send this peer the audio mix when we get this event */
	g_atomic_int_set(&session->started, 1);
	janus_mutex_unlock(&sessions_mutex);
	/* Notify all other participants that there's a new boy in town */
	janus_mutex_lock(&rooms_mutex);
	ptt_room *audiobridge = participant->room;
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
	json_array_append_new(list, pl);
	json_t *pub = json_object();
	json_object_set_new(pub, "audiobridge", json_string("event"));
	json_object_set_new(pub, "room", json_string(participant->room->room_id_str));
	json_object_set_new(pub, "participants", list);
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, audiobridge->participants);
	while(g_hash_table_iter_next(&iter, NULL, &value)) {
		room_participant *p = (room_participant *)value;
		if(p == participant) {
			continue;	/* Skip the new participant itself */
		}
		JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
		int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, pub, NULL);
		JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	}
	json_decref(pub);
	g_atomic_int_set(&participant->active, 1);
	janus_mutex_unlock(&audiobridge->mutex);
	janus_mutex_unlock(&rooms_mutex);
}

void incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {
	assert_thread_type_is(thread_type::INCOMING_RTP);

	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	plugin_session *session = (plugin_session *)handle->plugin_handle;
	if(!session || g_atomic_int_get(&session->destroyed) || !session->participant)
		return;
	room_participant *participant = (room_participant *)session->participant;
	if(!g_atomic_int_get(&participant->active) || participant->muted || !participant->room)
		return;

	assert(participant->incoming_rtp_thread_id == std::this_thread::get_id());

	char *buf = packet->buffer;
	uint16_t len = packet->length;
	/* Save the frame if we're recording this leg */
	audio_recorder_save_frame(participant->arc, buf, len);
	if(g_atomic_int_get(&participant->active)) {
		participant->reset = FALSE;

		/* Decode frame (Opus -> slinear) */
		janus_rtp_header *rtp = (janus_rtp_header *)buf;
		rtp_relay_packet *pkt = (rtp_relay_packet *)g_malloc(sizeof(rtp_relay_packet));
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
							notify_participants(participant, event, TRUE);
							json_decref(event);
							janus_mutex_unlock(&participant->room->mutex);
							/* Also notify event handlers */
							if(notify_events && gateway->events_is_enabled()) {
								json_t *info = json_object();
								json_object_set_new(info, "audiobridge", json_string(participant->talking ? "talking" : "stopped-talking"));
								json_object_set_new(info, "room", json_string(participant->room ? participant->room->room_id_str : NULL));
								json_object_set_new(info, "id", json_string(participant->user_id_str));
								gateway->notify_event(&ptt_audioroom_plugin, session->handle, info);
							}
						}
					}
				}
			}
		}
		int plen = 0;
		const unsigned char *payload = (const unsigned char *)janus_rtp_payload(buf, len, &plen);
		if(!payload) {
			JANUS_LOG(LOG_ERR, "Ops! got an error accessing the RTP payload\n");
			g_free(pkt->data);
			g_free(pkt);
			return;
		}
		/* Check sequence number received, verify if it's relevant to the expected one */
		if(pkt->seq_number == participant->expected_seq) {
#if GLIB_CHECK_VERSION(2, 68, 0)
			pkt->data = (janus_rtp_header*) g_memdup2(packet->buffer, packet->length);
#else
			pkt->data = (janus_rtp_header*) g_memdup(packet->buffer, packet->length);
#endif
			pkt->length = packet->length;
			/* Update last_timestamp */
			participant->last_timestamp = pkt->timestamp;
			/* Increment according to previous seq_number */
			participant->expected_seq = pkt->seq_number + 1;
		} else if(pkt->seq_number > participant->expected_seq) {
			/* Sequence(s) losts */
			uint16_t gap = pkt->seq_number - participant->expected_seq;
			JANUS_LOG(LOG_HUGE, "%" SCNu16 " sequence(s) lost, sequence = %" SCNu16 ", expected seq = %" SCNu16 "\n",
				gap, pkt->seq_number, participant->expected_seq);

#if GLIB_CHECK_VERSION(2, 68, 0)
			pkt->data = (janus_rtp_header*) g_memdup2(packet->buffer, packet->length);
#else
			pkt->data = (janus_rtp_header*) g_memdup(packet->buffer, packet->length);
#endif
			pkt->length = packet->length;
			/* Increment according to previous seq_number */
			participant->expected_seq = pkt->seq_number + 1;
		} else {
			/* In late sequence or sequence wrapped */
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

		/* Enqueue frame */
		janus_mutex_lock(&participant->qmutex);
		gint64 now = janus_get_monotonic_time();
		participant->inbuf_timestamp = now;
		/* Insert packets sorting by sequence number */
		participant->inbuf = g_list_insert_sorted(participant->inbuf, pkt, &rtp_sort);
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
					rtp_relay_packet *pkt = (rtp_relay_packet *)first->data;
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

void hangup_media(janus_plugin_session *handle) {
	assert_thread_type_is(thread_type::INCOMING_RTP);

	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", PTT_AUDIOROOM_PACKAGE, handle);
	janus_mutex_lock(&sessions_mutex);
	hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void hangup_media_internal(janus_plugin_session *handle) {
	assert_thread_type_is(thread_type::INCOMING_RTP);

	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	plugin_session *session = lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	g_atomic_int_set(&session->started, 0);
	if(session->participant == NULL)
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;

	assert(session->participant->incoming_rtp_thread_id == std::thread::id() || session->participant->incoming_rtp_thread_id == std::this_thread::get_id());
	session->participant->incoming_rtp_thread_id = std::thread::id();

	/* Get rid of participant */
	room_participant *participant = (room_participant *)session->participant;
	janus_mutex_lock(&rooms_mutex);
	ptt_room *audiobridge = participant->room;
	gboolean removed = FALSE;
	if(audiobridge != NULL) {
		janus_mutex_lock(&audiobridge->mutex);

		participant->room = NULL;
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
			room_participant *p = (room_participant *)value;
			if(p == participant) {
				continue;	/* Skip the leaving participant itself */
			}
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
		json_decref(event);

		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("left"));
			json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
			json_object_set(info, "participant", participantInfo);

			gateway->notify_event(&ptt_audioroom_plugin, NULL, info);
		}
		json_decref(participantInfo);
	}
	/* Get rid of the recorders, if available */
	janus_mutex_lock(&participant->rec_mutex);
	recorder_close(participant);
	janus_mutex_unlock(&participant->rec_mutex);
	/* Free the participant resources */
	janus_mutex_lock(&participant->qmutex);
	g_atomic_int_set(&participant->active, 0);
	participant->muted = TRUE;
	g_free(participant->display);
	participant->display = NULL;
	participant->prebuffering = TRUE;
	participant->reset = FALSE;
	participant->audio_active_packets = 0;
	participant->audio_dBov_sum = 0;
	participant->talking = FALSE;
	/* Get rid of queued packets */
	clear_inbuf(participant, false);
	participant->last_drop = 0;
	janus_mutex_unlock(&participant->qmutex);
	if(audiobridge != NULL) {
		janus_mutex_unlock(&audiobridge->mutex);
		if(removed) {
			janus_refcount_decrease(&audiobridge->ref);
		}
	}
	janus_mutex_unlock(&rooms_mutex);
	g_atomic_int_set(&session->hangingup, 0);
}

namespace ptt_audioroom {

void *participants_sender_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Audio bridge thread starting...\n");
	ptt_room *audiobridge = (ptt_room *)data;
	if(!audiobridge) {
		JANUS_LOG(LOG_ERR, "Invalid room!\n");
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Thread is for room %s (%s)...\n",
		audiobridge->room_id_str, audiobridge->room_name);

	/* Base RTP packets, in case there are forwarders involved */
	const gsize max_rtp_size = 1500;
	unsigned char *rtpbuffer = (unsigned char *)g_malloc0(max_rtp_size);

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
			room_participant *p = (room_participant *)ps->data;
			janus_refcount_increase(&p->ref);
			ps = ps->next;
		}

		room_participant* unmutedParticipant = audiobridge->unmutedParticipant;
		janus_mutex_unlock_nodebug(&audiobridge->mutex);

		if(unmutedParticipant) {
			room_participant *p = unmutedParticipant;
			janus_mutex_lock_guard inbuf_lock_guard(&p->qmutex);
			if(g_atomic_int_get(&p->destroyed) || !p->session || !g_atomic_int_get(&p->session->started) || !g_atomic_int_get(&p->active) || p->prebuffering || !p->inbuf) {
				continue;
			}

			GList *peek = g_list_first(p->inbuf);
			rtp_relay_packet *pkt = (rtp_relay_packet *)(peek ? peek->data : NULL);
			p->inbuf = g_list_delete_link(p->inbuf, peek);

			if(pkt && !pkt->silence) {
				/* Send packet to each participant (except self) */
				ps = participants_list;
				while(ps) {
					room_participant *p = (room_participant *)ps->data;
					if(g_atomic_int_get(&p->destroyed) || !p->session || !g_atomic_int_get(&p->session->started) || p == unmutedParticipant) {
						ps = ps->next;
						continue;
					}

					pkt->length = pkt->length;
					pkt->timestamp = ts;
					pkt->seq_number = seq;
					pkt->ssrc = audiobridge->room_ssrc;
					pkt->silence = FALSE;
					pkt->data->version = 2;
					pkt->data->markerbit = 0;	/* FIXME Should be 1 for the first packet */
					/* Backup the actual timestamp and sequence number set by the audiobridge, in case a room is changed */
					relay_rtp_packet(p, p->session, pkt);

					ps = ps->next;
				}
			}

			/* Forward the packet as RTP to any RTP forwarder that may be listening */
			janus_mutex_lock_guard forwarders_lock_guard(&audiobridge->rtp_mutex);
			if(g_hash_table_size(audiobridge->rtp_forwarders) > 0) {
				/* If the room is empty, check if there's any RTP forwarder with an "always on" option */
				gboolean go_on = FALSE;
				if(count == 0) {
					GHashTableIter iter;
					gpointer value;
					g_hash_table_iter_init(&iter, audiobridge->rtp_forwarders);
					while(g_hash_table_iter_next(&iter, NULL, &value)) {
						rtp_forwarder *forwarder = (rtp_forwarder *)value;
						if(forwarder->always_on) {
							go_on = TRUE;
							break;
						}
					}
				} else {
					go_on = TRUE;
				}
				if(go_on) {
					memcpy(rtpbuffer, pkt->data, std::min<gsize>(pkt->length, max_rtp_size));

					GHashTableIter iter;
					gpointer key, value;
					g_hash_table_iter_init(&iter, audiobridge->rtp_forwarders);
					opus_int32 length = 0;
					while(audiobridge->rtp_udp_sock > 0 && g_hash_table_iter_next(&iter, &key, &value)) {
						guint32 stream_id = GPOINTER_TO_UINT(key);
						rtp_forwarder *forwarder = (rtp_forwarder *)value;
						if(count == 0 && !forwarder->always_on)
							continue;

						janus_rtp_header *rtph = (janus_rtp_header *)(rtpbuffer);
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

			if(pkt) {
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
			}
		}

		ps = participants_list;
		while(ps) {
			room_participant *p = (room_participant *)ps->data;
			janus_refcount_decrease(&p->ref);
			ps = ps->next;
		}
		g_list_free(participants_list);

	}
	g_free(rtpbuffer);
	JANUS_LOG(LOG_VERB, "Leaving sender thread for room %s (%s)...\n", audiobridge->room_id_str, audiobridge->room_name);

	janus_refcount_decrease(&audiobridge->ref);

	return NULL;
}

}

static void relay_rtp_packet(
	room_participant *participant,
	plugin_session* session,
	rtp_relay_packet *packet)
{
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
	/* Restore the timestamp and sequence number to what the sender set them to */
	packet->data->timestamp = htonl(packet->timestamp);
	packet->data->seq_number = htons(packet->seq_number);
}
