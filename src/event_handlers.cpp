#include "event_handlers.h"

#include <netdb.h>

extern "C" {
#include "janus/apierror.h"
#include "janus/sdp-utils.h"
#include "janus/utils.h"
#include "janus/ip-utils.h"
}

#include "constants.h"
#include "ptt_audioroom_plugin.h"
#include "plugin_session.h"
#include "ptt_room.h"
#include "room_participant.h"
#include "rtp_forwarder.h"
#include "rtp_relay_packet.h"
#include "room_message.h"


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
	{"mjrs", JANUS_JSON_BOOL, 0},
	{"mjrs_dir", JSON_STRING, 0},
	{"permanent", JANUS_JSON_BOOL, 0},
	{"audiolevel_ext", JANUS_JSON_BOOL, 0},
	{"audiolevel_event", JANUS_JSON_BOOL, 0},
	{"audio_active_packets", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_level_average", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"default_prebuffering", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
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
	{"audio_level_average", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_active_packets", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"secret", JSON_STRING, 0}
};
static struct janus_json_parameter mjrs_parameters[] = {
	{"mjrs", JANUS_JSON_BOOL, JANUS_JSON_PARAM_REQUIRED},
	{"mjrs_dir", JSON_STRING, 0}
};
static struct janus_json_parameter configure_parameters[] = {
	{"prebuffer", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"display", JSON_STRING, 0},
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

namespace ptt_audioroom
{

json_t* query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	plugin_session *session = lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* Show the participant/room info, if any */
	json_t *info = json_object();
	room_participant *participant = (room_participant *)session->participant;
	json_object_set_new(info, "state", json_string(participant && participant->room ? "inroom" : "idle"));
	if(participant) {
		janus_mutex_lock(&rooms_mutex);
		ptt_room *room = participant->room;
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
		if(participant->last_drop > 0)
			json_object_set_new(info, "last-drop", json_integer(participant->last_drop));
		if(participant->extmap_id > 0) {
			json_object_set_new(info, "audio-level-dBov", json_integer(participant->dBov_level));
			json_object_set_new(info, "talking", participant->talking ? json_true() : json_false());
		}
		json_object_set_new(info, "fec", participant->fec ? json_true() : json_false());
	}
	json_object_set_new(info, "started", g_atomic_int_get(&session->started) ? json_true() : json_false());
	json_object_set_new(info, "hangingup", g_atomic_int_get(&session->hangingup) ? json_true() : json_false());
	json_object_set_new(info, "destroyed", g_atomic_int_get(&session->destroyed) ? json_true() : json_false());
	janus_refcount_decrease(&session->ref);
	return info;
}

static int check_room_access(json_t *root, gboolean check_modify, ptt_room **audiobridge, char *error_cause, int error_cause_size) {
	/* rooms_mutex has to be locked */
	int error_code = 0;
	json_t *room = json_object_get(root, "room");
	char room_id_num[30], *room_id_str = NULL;
	room_id_str = (char *)json_string_value(room);
	*audiobridge = (ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
	if(*audiobridge == NULL) {
		JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
		error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
		if(error_cause)
			g_snprintf(error_cause, error_cause_size, "No such room (%s)", room_id_str);
		return error_code;
	}
	if(g_atomic_int_get(&((*audiobridge)->destroyed))) {
		JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
		error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
		if(error_cause)
			g_snprintf(error_cause, error_cause_size, "No such room (%s)", room_id_str);
		return error_code;
	}
	if(check_modify) {
		char error_cause2[100];
		JANUS_CHECK_SECRET((*audiobridge)->room_secret, root, "secret", error_code, error_cause2,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			g_strlcpy(error_cause, error_cause2, error_cause_size);
			return error_code;
		}
	}
	return 0;
}

/* Helper method to process synchronous requests */
static json_t* process_synchronous_request(plugin_session *session, json_t *message) {
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstropt_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto prepare_response;
		}
		json_t *desc = json_object_get(root, "description");
		json_t *secret = json_object_get(root, "secret");
		json_t *pin = json_object_get(root, "pin");
		json_t *is_private = json_object_get(root, "is_private");
		json_t *allowed = json_object_get(root, "allowed");
		json_t *audiolevel_ext = json_object_get(root, "audiolevel_ext");
		json_t *audiolevel_event = json_object_get(root, "audiolevel_event");
		json_t *audio_active_packets = json_object_get(root, "audio_active_packets");
		json_t *audio_level_average = json_object_get(root, "audio_level_average");
		json_t *default_prebuffering = json_object_get(root, "default_prebuffering");
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
				error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
				goto prepare_response;
			}
		}
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't create permanent room\n");
			error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
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
				error_code = PTT_AUDIOROOM_ERROR_ROOM_EXISTS;
				JANUS_LOG(LOG_ERR, "Room %s already exists!\n", room_id_str);
				g_snprintf(error_cause, 512, "Room %s already exists", room_id_str);
				goto prepare_response;
			}
		}
		/* Create the AudioBridge room */
		ptt_room *audiobridge = new ptt_room {};
		janus_refcount_init(&audiobridge->ref, ptt_room_free);
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
		audiobridge->room_ssrc = janus_random_uint32();
		if(mjrs && json_is_true(mjrs))
			audiobridge->mjrs = TRUE;
		if(mjrsdir)
			audiobridge->mjrs_dir = g_strdup(json_string_value(mjrsdir));
		audiobridge->destroy = 0;
		audiobridge->participants = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			(GDestroyNotify)g_free, (GDestroyNotify)participant_unref);
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
		audiobridge->rtp_forwarders = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)rtp_forwarder_destroy);
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
		g_snprintf(tname, sizeof(tname), "sender %s", audiobridge->room_id_str);
		janus_refcount_increase(&audiobridge->ref);
		audiobridge->thread = g_thread_try_new(tname, &room_sender_thread, audiobridge, &error);
		if(error != NULL) {
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the sender thread...\n",
				error->code, error->message ? error->message : "??");
			error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "Got error %d (%s) trying to launch the sender thread",
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
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, PTT_AUDIOROOM_PACKAGE) < 0)
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
			gateway->notify_event(&ptt_audioroom_plugin, session ? session->handle : NULL, info);
		}
		if(room_id_allocated)
			g_free(room_id_str);
		janus_mutex_unlock(&rooms_mutex);
		goto prepare_response;
	} else if(!strcasecmp(request_text, "edit")) {
		JANUS_LOG(LOG_VERB, "Attempt to edit an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, edit_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
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
			error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't edit room permanently");
			goto prepare_response;
		}
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, PTT_AUDIOROOM_PACKAGE) < 0)
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
			gateway->notify_event(&ptt_audioroom_plugin, session ? session->handle : NULL, info);
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't destroy room permanently\n");
			error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't destroy room permanently");
			goto prepare_response;
		}
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
			if(janus_config_save(config, config_folder, PTT_AUDIOROOM_PACKAGE) < 0)
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
			room_participant *p = (room_participant *)value;
			if(p && p->session) {
				if(p->room) {
					p->room = NULL;
					janus_refcount_decrease(&audiobridge->ref);
				}
				int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, destroyed, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				/* Get rid of queued packets */
				janus_mutex_lock(&p->qmutex);
				g_atomic_int_set(&p->active, 0);
				clear_inbuf(p, false);
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
			gateway->notify_event(&ptt_audioroom_plugin, session ? session->handle : NULL, info);
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *mjrs = json_object_get(root, "mjrs");
		json_t *mjrsdir = json_object_get(root, "mjrs_dir");
		gboolean mjrs_active = json_is_true(mjrs);
		JANUS_LOG(LOG_VERB, "Enable MJR recording: %d\n", (mjrs_active ? 1 : 0));
		/* Lookup room */
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge = NULL;
		error_code = check_room_access(root, TRUE, &audiobridge, error_cause, sizeof(error_cause));
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
					PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
			ptt_room *room = (ptt_room *)value;
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
			json_object_set_new(rl, "pin_required", room->room_pin ? json_true() : json_false());
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *action = json_object_get(root, "action");
		json_t *room = json_object_get(root, "room");
		json_t *allowed = json_object_get(root, "allowed");
		const char *action_text = json_string_value(action);
		if(strcasecmp(action_text, "enable") && strcasecmp(action_text, "disable") &&
				strcasecmp(action_text, "add") && strcasecmp(action_text, "remove")) {
			JANUS_LOG(LOG_ERR, "Unsupported action '%s' (allowed)\n", action_text);
			error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Unsupported action '%s' (allowed)", action_text);
			goto prepare_response;
		}
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
					error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, idstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		json_t *id = json_object_get(root, "id");
		gboolean muted = (!strcasecmp(request_text, "mute")) ? TRUE : FALSE;
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		janus_mutex_lock(&audiobridge->mutex);
		janus_mutex_unlock(&rooms_mutex);

		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}

		char *user_id_str = NULL;
		user_id_str = (char *)json_string_value(id);
		room_participant *participant =
			(room_participant *)g_hash_table_lookup(audiobridge->participants, (gpointer)user_id_str);
		if(participant == NULL) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			JANUS_LOG(LOG_ERR, "No such user %s in room %s\n", user_id_str, room_id_str);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_USER;
			g_snprintf(error_cause, 512, "No such user %s in room %s", user_id_str, room_id_str);
			goto prepare_response;
		}

		if(!muted && audiobridge->unmuted_participant && audiobridge->unmuted_participant != participant) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			JANUS_LOG(LOG_ERR, "Room \"%s\" already has unmuted user\n", room_id_str);
			error_code = PTT_AUDIOROOM_ERROR_ROOM_ALREADY_HAS_UNMUTED_USER;
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
	} else if(!strcasecmp(request_text, "kick")) {
		JANUS_LOG(LOG_VERB, "Attempt to kick a participant from an existing AudioBridge room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, secret_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, idstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		json_t *id = json_object_get(root, "id");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}
		char *user_id_str = NULL;
		user_id_str = (char *)json_string_value(id);
		room_participant *participant =
			(room_participant *)g_hash_table_lookup(audiobridge->participants, (gpointer)user_id_str);
		if(participant == NULL) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			JANUS_LOG(LOG_ERR, "No such user %s in room %s\n", user_id_str, room_id_str);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_USER;
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
			room_participant *p = (room_participant *)value;
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
		json_decref(event);
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("kicked"));
			json_object_set_new(info, "room", json_string(room_id_str));
			json_object_set_new(info, "id", json_string(user_id_str));
			gateway->notify_event(&ptt_audioroom_plugin, session ? session->handle : NULL, info);
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		janus_refcount_increase(&audiobridge->ref);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&audiobridge->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_refcount_decrease(&audiobridge->ref);
			goto prepare_response;
		}
		GHashTableIter kick_iter;
		gpointer kick_value;
		g_hash_table_iter_init(&kick_iter, audiobridge->participants);
		while(g_hash_table_iter_next(&kick_iter, NULL, &kick_value)) {
			room_participant *participant = (room_participant *)kick_value;
			JANUS_LOG(LOG_VERB, "Kicking participant %s (%s)\n",
					participant->user_id_str, participant->display ? participant->display : "??");
			char *user_id_str = NULL;
			user_id_str = participant->user_id_str;
			/* Notify all participants about the kick */
			json_t *event = json_object();
			json_object_set_new(event, "audiobridge", json_string("event"));
			json_object_set_new(event, "room", json_string(room_id_str));
			json_object_set_new(event, "kicked_all", json_string(user_id_str));
			JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", participant->user_id_str, participant->display ? participant->display : "??");
			int ret = gateway->push_event(participant->session->handle, &ptt_audioroom_plugin, NULL, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("kicked_all"));
				json_object_set_new(info, "room", json_string(room_id_str));
				json_object_set_new(info, "id", json_string(user_id_str));
				gateway->notify_event(&ptt_audioroom_plugin, session ? session->handle : NULL, info);
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
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
			room_participant *p = (room_participant *)value;
			json_t *pl = json_object();
			json_object_set_new(pl, "id", json_string(p->user_id_str));
			if(p->display)
				json_object_set_new(pl, "display", json_string(p->display));
			json_object_set_new(pl, "setup", g_atomic_int_get(&p->session->started) ? json_true() : json_false());
			json_object_set_new(pl, "muted", p->muted ? json_true() : json_false());
			if(p->extmap_id > 0)
				json_object_set_new(pl, "talking", p->talking ? json_true() : json_false());
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
		room_participant *participant = (room_participant *)(session ? session->participant : NULL);
		if(participant == NULL || participant->room == NULL) {
			JANUS_LOG(LOG_ERR, "Can't reset (not in a room)\n");
			error_code = PTT_AUDIOROOM_ERROR_NOT_JOINED;
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(lock_rtpfwd && admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
			error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
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
				error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
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
			error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Could not resolve address (%s)...", host);
			goto prepare_response;
		}
		host = resolved_host;
		if(ipv6_disabled && strstr(host, ":") != NULL) {
			JANUS_LOG(LOG_ERR, "Attempt to create an IPv6 forwarder, but IPv6 networking is not available\n");
			error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
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
				error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid SRTP suite (%d)", srtp_suite);
				goto prepare_response;
			}
			srtp_crypto = json_string_value(s_crypto);
		}
		/* Update room */
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s", room_id_str);
			goto prepare_response;
		}
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		if(audiobridge->destroyed) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}

		if(create_udp_socket_if_needed(audiobridge)) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "Could not open UDP socket for RTP forwarder");
			goto prepare_response;
		}

		guint32 stream_id = rtp_forwarder_add_helper(audiobridge,
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		if(lock_rtpfwd && admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto prepare_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
		ptt_room *audiobridge = (ptt_room *)g_hash_table_lookup(rooms,
			(gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		janus_mutex_lock(&audiobridge->mutex);
		if(audiobridge->destroyed) {
			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
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
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto prepare_response;
		json_t *room = json_object_get(root, "room");
		char room_id_num[30], *room_id_str = NULL;
		room_id_str = (char *)json_string_value(room);
		janus_mutex_lock(&rooms_mutex);
		ptt_room *audiobridge =
			(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
		if(audiobridge == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto prepare_response;
		}
		if(audiobridge->destroyed) {
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			janus_mutex_unlock(&rooms_mutex);
			goto prepare_response;
		}
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(audiobridge->room_secret, root, "secret", error_code, error_cause,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
			rtp_forwarder *rf = (rtp_forwarder *)value;
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
				error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
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

json_t* handle_admin_message(json_t* message) {
	/* Some requests (e.g., 'create' and 'destroy') can be handled via Admin API */
	int error_code = 0;
	char error_cause[512];
	json_t *response = NULL;

	JANUS_VALIDATE_JSON_OBJECT(message, request_parameters,
		error_code, error_cause, TRUE,
		PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto admin_response;
	json_t *request; request = json_object_get(message, "request");
	const char *request_text; request_text = json_string_value(request);
	if((response = process_synchronous_request(NULL, message)) != NULL) {
		/* We got a response, send it back */
		goto admin_response;
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = PTT_AUDIOROOM_ERROR_INVALID_REQUEST;
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

janus_plugin_result* handle_message(
	janus_plugin_session *handle,
	char *transaction,
	json_t *message,
	json_t *jsep)
{
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	janus_mutex_lock(&sessions_mutex);
	plugin_session *session = lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "No session associated with this handle...");
		goto plugin_response;
	}
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been marked as destroyed...\n");
		error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been marked as destroyed...");
		goto plugin_response;
	}

	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = PTT_AUDIOROOM_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto plugin_response;
	}
	if(!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = PTT_AUDIOROOM_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto plugin_response;
	}
	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
		error_code, error_cause, TRUE,
		PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	json_t *request; request = json_object_get(root, "request");
	/* Some requests ('create', 'destroy', 'exists', 'list') can be handled synchronously */
	const char *request_text; request_text = json_string_value(request);
	/* We have a separate method to process synchronous requests, as those may
	 * arrive from the Admin API as well, and so we handle them the same way */
	response = process_synchronous_request(session, root);
	if(response != NULL) {
		/* We got a response, send it back */
		goto plugin_response;
	} else if(!strcasecmp(request_text, "join") || !strcasecmp(request_text, "configure")
			|| !strcasecmp(request_text, "self-unmute") || !strcasecmp(request_text, "self-mute")
			|| !strcasecmp(request_text, "changeroom") || !strcasecmp(request_text, "leave")
			|| !strcasecmp(request_text, "hangup")) {
		/* These messages are handled asynchronously */
		room_message *msg = (room_message *)g_malloc(sizeof(room_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;

		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = PTT_AUDIOROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(error_code == 0 && !response) {
				error_code = PTT_AUDIOROOM_ERROR_UNKNOWN_ERROR;
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

/* Thread to handle incoming messages */
void* message_handler_thread(void* data) {
	JANUS_LOG(LOG_VERB, "Joining AudioBridge handler thread\n");
	room_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = (room_message *)g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			room_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		plugin_session *session = lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			room_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			room_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = NULL;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = PTT_AUDIOROOM_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		root = msg->message;
		/* Get the request first */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request; request = json_object_get(root, "request");
		const char *request_text; request_text = json_string_value(request);
		json_t *event; event = NULL;
		gboolean sdp_update; sdp_update = FALSE;
		if(json_object_get(msg->jsep, "update") != NULL)
			sdp_update = json_is_true(json_object_get(msg->jsep, "update"));
		gboolean got_offer, got_answer;
		got_offer = FALSE; got_answer = FALSE;
		const char *msg_sdp_type; msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp; msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		if(msg_sdp_type != NULL) {
			got_offer = !strcasecmp(msg_sdp_type, "offer");
			got_answer = !strcasecmp(msg_sdp_type, "answer");
			if(!got_offer && !got_answer) {
				JANUS_LOG(LOG_ERR, "Unsupported SDP type '%s'\n", msg_sdp_type);
				error_code = PTT_AUDIOROOM_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Unsupported SDP type '%s'\n", msg_sdp_type);
				goto error;
			}
		}
		if(!strcasecmp(request_text, "join")) {
			JANUS_LOG(LOG_VERB, "Configuring new participant\n");
			room_participant *participant = session->participant;
			if(participant != NULL && participant->room != NULL) {
				JANUS_LOG(LOG_ERR, "Already in a room (use changeroom to join another one)\n");
				error_code = PTT_AUDIOROOM_ERROR_ALREADY_JOINED;
				g_snprintf(error_cause, 512, "Already in a room (use changeroom to join another one)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			JANUS_VALIDATE_JSON_OBJECT(root, idstropt_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *room = json_object_get(root, "room");
			char room_id_num[30], *room_id_str = NULL;
			room_id_str = (char *)json_string_value(room);
			janus_mutex_lock(&rooms_mutex);
			ptt_room *audiobridge =
				(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
			if(audiobridge == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
				JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
				g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
				goto error;
			}
			janus_refcount_increase(&audiobridge->ref);
			janus_mutex_lock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
			/* A pin may be required for this action */
			JANUS_CHECK_SECRET(audiobridge->room_pin, root, "pin", error_code, error_cause,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
					error_code = PTT_AUDIOROOM_ERROR_UNAUTHORIZED;
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
					PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
			json_t *user_audio_level_average = json_object_get(root, "audio_level_average");
			json_t *user_audio_active_packets = json_object_get(root, "audio_active_packets");
			uint prebuffer_count = prebuffer ? json_integer_value(prebuffer) : audiobridge->default_prebuffering;
			if(prebuffer_count > MAX_PREBUFFERING) {
				prebuffer_count = audiobridge->default_prebuffering;
				JANUS_LOG(LOG_WARN, "Invalid prebuffering value provided (too high), using room default: %d\n",
					audiobridge->default_prebuffering);
			}
			char *user_id_str = NULL;
			gboolean user_id_allocated = FALSE;
			json_t *id = json_object_get(root, "id");
			if(id) {
				user_id_str = (char *)json_string_value(id);
				if(g_hash_table_lookup(audiobridge->participants, (gpointer)user_id_str)) {
					/* User ID already taken */
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					error_code = PTT_AUDIOROOM_ERROR_ID_EXISTS;
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
				participant = new room_participant {};
				janus_refcount_init(&participant->ref, participant_free);
				g_atomic_int_set(&participant->active, 0);
				participant->prebuffering = TRUE;
				participant->display = NULL;
				participant->inbuf = NULL;
				participant->last_drop = 0;
				participant->reset = FALSE;
				participant->fec = FALSE;
				participant->expected_seq = 0;
				participant->probation = 0;
				participant->last_timestamp = 0;
			}
			participant->session = session;
			participant->room = audiobridge;
			participant->user_id_str = g_strdup(user_id_str);
			g_free(participant->display);
			participant->admin = admin;
			participant->display = display_text ? g_strdup(display_text) : NULL;
			participant->muted = TRUE;	/* By default, everyone's muted when joining */
			participant->prebuffer_count = prebuffer_count;
			participant->user_audio_active_packets = json_integer_value(user_audio_active_packets);
			participant->user_audio_level_average = json_integer_value(user_audio_level_average);
			g_atomic_int_set(&participant->active, g_atomic_int_get(&session->started));
			if(!g_atomic_int_get(&session->started)) {
				/* Initialize the RTP context only if we're renegotiating */
				janus_rtp_switching_context_reset(&participant->context);
				participant->opus_pt = 0;
				participant->extmap_id = 0;
				participant->dBov_level = 0;
				participant->talking = FALSE;
			}
			participant->reset = FALSE;
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
			json_array_append_new(newuserlist, pl);
			json_object_set_new(newuser, "participants", newuserlist);
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				room_participant *p = (room_participant *)value;
				if(p == participant) {
					continue;
				}
				JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
				int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, newuser, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(newuser);
			/* Return a list of all available participants for the new participant now */
			json_t *list = json_array();
			g_hash_table_iter_init(&iter, audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				room_participant *p = (room_participant *)value;
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
				gateway->notify_event(&ptt_audioroom_plugin, session->handle, info);
			}
			if(user_id_allocated)
				g_free(user_id_str);
		} else if(!strcasecmp(request_text, "configure")) {
			/* Handle this participant */
			room_participant *participant = (room_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				JANUS_LOG(LOG_ERR, "Can't configure (not in a room)\n");
				error_code = PTT_AUDIOROOM_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't configure (not in a room)");
				goto error;
			}
			/* Configure settings for this participant */
			JANUS_VALIDATE_JSON_OBJECT(root, configure_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *prebuffer = json_object_get(root, "prebuffer");
			json_t *display = json_object_get(root, "display");
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
							rtp_relay_packet *pkt = (rtp_relay_packet *)first->data;
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
			if(display) {
				char *old_display = participant->display;
				char *new_display = g_strdup(json_string_value(display));
				participant->display = new_display;
				g_free(old_display);
				JANUS_LOG(LOG_VERB, "Setting display property: %s (room %s, user %s)\n",
					participant->display, participant->room->room_id_str, participant->user_id_str);

				/* Notify all other participants */
				janus_mutex_lock(&rooms_mutex);
				ptt_room *audiobridge = participant->room;
				if(audiobridge != NULL) {
					janus_mutex_lock(&audiobridge->mutex);
					json_t *list = json_array();
					json_t *pl = json_object();
					json_object_set_new(pl, "id", json_string(participant->user_id_str));
					if(participant->display)
						json_object_set_new(pl, "display", json_string(participant->display));
					json_object_set_new(pl, "setup", g_atomic_int_get(&participant->session->started) ? json_true() : json_false());
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
						JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n",
							p->user_id_str, p->display ? p->display : "??");
						int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, pub, NULL);
						JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
					}
					json_decref(pub);
					janus_mutex_unlock(&audiobridge->mutex);
				}
				janus_mutex_unlock(&rooms_mutex);
			}
			gboolean do_update = update ? json_is_true(update) : FALSE;
			if(do_update && !sdp_update) {
				JANUS_LOG(LOG_WARN, "Got a 'update' request, but no SDP update? Ignoring...\n");
			}
			/* Done */
			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("event"));
			json_object_set_new(event, "result", json_string("ok"));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				ptt_room *audiobridge = participant->room;
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("configured"));
				json_object_set_new(info, "room", json_string(audiobridge->room_id_str));
				json_object_set_new(info, "id", json_string(participant->user_id_str));
				json_object_set_new(info, "display", json_string(participant->display));
				json_object_set_new(info, "muted", participant->muted ? json_true() : json_false());
				gateway->notify_event(&ptt_audioroom_plugin, session->handle, info);
			}
		} else if(!strcasecmp(request_text, "self-unmute") || !strcasecmp(request_text, "self-mute")) {
			room_participant *participant = (room_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				JANUS_LOG(LOG_ERR, "Can't mute/unmute (not in a room)\n");
				error_code = PTT_AUDIOROOM_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't configure (not in a room)");
				goto error;
			}

			janus_mutex_lock(&rooms_mutex);
			ptt_room *audiobridge = participant->room;
			janus_mutex_lock(&audiobridge->mutex);

			const gboolean muting = !strcasecmp(request_text, "self-mute");
			if(!muting && audiobridge->unmuted_participant && audiobridge->unmuted_participant != participant) {
				// check if unmuted_participant was not active for too long time
				gboolean mute_forced = FALSE;
				struct room_participant* unmuted_participant = audiobridge->unmuted_participant;
				janus_mutex_lock(&unmuted_participant->qmutex);
				gint64 now = janus_get_monotonic_time();
				if(now - MAX(unmuted_participant->inbuf_timestamp, unmuted_participant->unmuted_timestamp) > PTT_NO_AUDIO_TIMEOUT*G_USEC_PER_SEC) {
					mute_forced = TRUE;
					JANUS_LOG(LOG_WARN, "Room \"%s\" already has unmuted but inactive user. Forcing mute...\n", participant->room->room_id_str);
					mute_participant(session, unmuted_participant, TRUE, FALSE, FALSE);

					// Notify participant about forced mute
					json_t *participantInfo = json_object();
					json_object_set_new(participantInfo, "id", json_string(unmuted_participant->user_id_str));
					if(unmuted_participant->display)
						json_object_set_new(participantInfo, "display", json_string(unmuted_participant->display));

					json_t *pub = json_object();
					json_object_set_new(pub, "audiobridge", json_string("forcibly-muted"));
					json_object_set_new(pub, "room", json_string(unmuted_participant->room->room_id_str));
					json_object_set_new(pub, "participant", participantInfo);

					JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n",
						unmuted_participant->user_id_str, unmuted_participant->display ? unmuted_participant->display : "??");
					int ret = gateway->push_event(unmuted_participant->session->handle, &ptt_audioroom_plugin, NULL, pub, NULL);
					JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
					json_decref(pub);
				}
				janus_mutex_unlock(&unmuted_participant->qmutex);

				if(!mute_forced) {
					JANUS_LOG(LOG_INFO, "Room \"%s\" already has unmuted user\n", participant->room->room_id_str);
					error_code = PTT_AUDIOROOM_ERROR_ROOM_ALREADY_HAS_UNMUTED_USER;
					g_snprintf(error_cause, 512, "Room \"%s\" already has unmuted user\n", participant->room->room_id_str);
					janus_mutex_unlock(&audiobridge->mutex);
					janus_mutex_unlock(&rooms_mutex);
					goto error;
				}
			}

			mute_participant(session, participant, muting, FALSE, TRUE);

			event = json_object();
			json_object_set_new(event, "audiobridge", json_string("event"));
			json_object_set_new(event, "result", json_string("ok"));
			if(audiobridge->mjrs && !muting) {
				json_object_set_new(event, "recording_id", json_string(participant->recording_id.c_str()));
			}

			janus_mutex_unlock(&audiobridge->mutex);
			janus_mutex_unlock(&rooms_mutex);
		} else if(!strcasecmp(request_text, "changeroom")) {
			/* The participant wants to leave the current room and join another one without reconnecting (e.g., a sidebar) */
			JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *room = json_object_get(root, "room");
			char room_id_num[30], *room_id_str = NULL;
			room_id_str = (char *)json_string_value(room);
			janus_mutex_lock(&rooms_mutex);
			room_participant *participant = (room_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Can't change room (not in a room in the first place)\n");
				error_code = PTT_AUDIOROOM_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't change room (not in a room in the first place)");
				goto error;
			}
			/* Is this the same room we're in? */
			if(participant->room && (participant->room->room_id_str && !strcmp(participant->room->room_id_str, room_id_str))) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Already in this room\n");
				error_code = PTT_AUDIOROOM_ERROR_ALREADY_JOINED;
				g_snprintf(error_cause, 512, "Already in this room");
				goto error;
			}
			ptt_room *audiobridge =
				(ptt_room *)g_hash_table_lookup(rooms, (gpointer)room_id_str);
			if(audiobridge == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				error_code = PTT_AUDIOROOM_ERROR_NO_SUCH_ROOM;
				JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
				g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
				goto error;
			}
			janus_refcount_increase(&audiobridge->ref);
			janus_mutex_lock(&audiobridge->mutex);
			/* A pin may be required for this action */
			JANUS_CHECK_SECRET(audiobridge->room_pin, root, "pin", error_code, error_cause,
				PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
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
					error_code = PTT_AUDIOROOM_ERROR_UNAUTHORIZED;
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
					PTT_AUDIOROOM_ERROR_MISSING_ELEMENT, PTT_AUDIOROOM_ERROR_INVALID_ELEMENT, PTT_AUDIOROOM_ERROR_UNAUTHORIZED);
				if(error_code != 0) {
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					goto error;
				}
				admin = TRUE;
			}
			json_t *display = json_object_get(root, "display");
			const char *display_text = display ? json_string_value(display) : NULL;
			char *user_id_str = NULL;
			gboolean user_id_allocated = FALSE;
			json_t *id = json_object_get(root, "id");
			if(id) {
				user_id_str = (char *)json_string_value(id);
				if(g_hash_table_lookup(audiobridge->participants, (gpointer)user_id_str) != NULL) {
					/* User ID already taken */
					janus_mutex_unlock(&audiobridge->mutex);
					janus_refcount_decrease(&audiobridge->ref);
					janus_mutex_unlock(&rooms_mutex);
					error_code = PTT_AUDIOROOM_ERROR_ID_EXISTS;
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
			ptt_room *old_audiobridge = participant->room;
			/* Leave the old room first... */
			janus_refcount_increase(&participant->ref);
			janus_mutex_lock(&old_audiobridge->mutex);
			if(old_audiobridge->unmuted_participant == participant) {
				old_audiobridge->unmuted_participant = nullptr;
			}
			g_hash_table_remove(old_audiobridge->participants, (gpointer)participant->user_id_str);

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
				room_participant *p = (room_participant *)value;
				if(p == participant) {
					continue;	/* Skip the new participant itself */
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
				json_object_set_new(info, "room", json_string(old_audiobridge->room_id_str));
				json_object_set(info, "participant", participantInfo);

				gateway->notify_event(&ptt_audioroom_plugin, session->handle, info);
			}
			json_decref(participantInfo);
			janus_mutex_unlock(&old_audiobridge->mutex);

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
			json_array_append_new(newuserlist, pl);
			json_object_set_new(newuser, "participants", newuserlist);
			g_hash_table_iter_init(&iter, audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				room_participant *p = (room_participant *)value;
				if(p == participant) {
					continue;
				}
				JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
				int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, newuser, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(newuser);
			/* Return a list of all available participants for the new participant now */
			json_t *list = json_array();
			g_hash_table_iter_init(&iter, audiobridge->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				room_participant *p = (room_participant *)value;
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
				gateway->notify_event(&ptt_audioroom_plugin, session->handle, info);
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
			room_participant *participant = (room_participant *)session->participant;
			if(participant == NULL || participant->room == NULL) {
				JANUS_LOG(LOG_ERR, "Can't leave (not in a room)\n");
				error_code = PTT_AUDIOROOM_ERROR_NOT_JOINED;
				g_snprintf(error_cause, 512, "Can't leave (not in a room)");
				goto error;
			}
			/* Tell everybody */
			janus_mutex_lock(&rooms_mutex);
			ptt_room *audiobridge = participant->room;
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
					room_participant *p = (room_participant *)value;
					if(p == participant) {
						continue;	/* Skip the new participant itself */
					}
					JANUS_LOG(LOG_VERB, "Notifying participant %s (%s)\n", p->user_id_str, p->display ? p->display : "??");
					int ret = gateway->push_event(p->session->handle, &ptt_audioroom_plugin, NULL, event, NULL);
					JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				}
				json_decref(event);
				json_decref(participantInfo);

				/* Actually leave the room... */
				if(audiobridge->unmuted_participant == participant) {
					audiobridge->unmuted_participant = nullptr;
				}
				removed = g_hash_table_remove(audiobridge->participants, (gpointer)participant->user_id_str);
				participant->room = NULL;
			}

			/* Get rid of queued packets */
			janus_mutex_lock(&participant->qmutex);
			g_atomic_int_set(&participant->active, 0);
			participant->prebuffering = TRUE;
			clear_inbuf(participant, false);
			janus_mutex_unlock(&participant->qmutex);

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

				gateway->notify_event(&ptt_audioroom_plugin, session->handle, info);
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
			error_code = PTT_AUDIOROOM_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
			goto error;
		}

		/* Prepare JSON event */
		JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
		/* Any SDP to handle? */
		if(!msg_sdp) {
			int ret = gateway->push_event(msg->handle, &ptt_audioroom_plugin, msg->transaction, event, NULL);
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
				error_code = PTT_AUDIOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Media encryption unsupported by this plugin");
				goto error;
			}
			/* We answer by default, unless the user asked the plugin for an offer */
			if(msg_sdp && got_answer) {
				json_decref(event);
				JANUS_LOG(LOG_ERR, "Received an answer when we didn't send an offer\n");
				error_code = PTT_AUDIOROOM_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Received an answer when we didn't send an offer");
				goto error;
			}
			const char *type = "answer";
			char error_str[512];
			janus_sdp *sdp = NULL;
			if(msg_sdp != NULL) {
				sdp = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
				if(sdp == NULL) {
					json_decref(event);
					JANUS_LOG(LOG_ERR, "Error parsing %s: %s\n", msg_sdp, error_str);
					error_code = PTT_AUDIOROOM_ERROR_INVALID_SDP;
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
			room_participant *participant = (room_participant *)session->participant;
			if(sdp != NULL) {
				participant->opus_pt = janus_sdp_get_codec_pt(sdp, -1, "opus");
				if(participant->opus_pt > 0 && strstr(msg_sdp, "useinbandfec=1")){
					/* Opus codec, inband FEC setted */
					participant->fec = TRUE;
					participant->probation = MIN_SEQUENTIAL;
				}
				JANUS_LOG(LOG_VERB, "Opus payload type is %d, FEC %s\n", participant->opus_pt, participant->fec ? "enabled" : "disabled");
			}
			/* Check if the audio level extension was offered */
			int extmap_id = -1;
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
				int res = gateway->push_event(msg->handle, &ptt_audioroom_plugin, msg->transaction, event, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %" SCNu64 " us)\n", res, janus_get_monotonic_time()-start);
				json_decref(event);
				janus_sdp_destroy(sdp);
				if(msg)
					room_message_free(msg);
				msg = NULL;
				continue;
			}
			if(participant == NULL || participant->room == NULL) {
				JANUS_LOG(LOG_ERR, "Can't handle SDP (not in a room)\n");
				error_code = PTT_AUDIOROOM_ERROR_NOT_JOINED;
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
			g_snprintf(fmtp, sizeof(fmtp), "%d; useinbandfec=%d\r\n",
				participant->opus_pt, participant->fec ? 1 : 0);
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
			}
			/* Was the audio level extension negotiated? */
			participant->extmap_id = 0;
			participant->dBov_level = 0;
			if(extmap_id > -1 && participant->room && participant->room->audiolevel_ext) {
				/* Add an extmap attribute too */
				participant->extmap_id = extmap_id;
			}
			/* Prepare the response */
			char *new_sdp = janus_sdp_write(answer ? answer : offer);
			janus_sdp_destroy(sdp);
			janus_sdp_destroy(answer ? answer : offer);
			json_t *jsep = json_pack("{ssss}", "type", type, "sdp", new_sdp);
			/* How long will the Janus core take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &ptt_audioroom_plugin, msg->transaction, event, jsep);
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
			room_message_free(msg);
		msg = NULL;

		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "audiobridge", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &ptt_audioroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			room_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving AudioBridge handler thread\n");
	return NULL;
}

}
