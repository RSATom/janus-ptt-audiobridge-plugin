#pragma once

#include <glib.h>

extern "C" {
#include "plugin.h"
#include "janus/config.h"
#include "janus/mutex.h"
}

#include "plugin_session.h"
#include "ptt_room.h"


namespace ptt_audioroom
{

extern janus_plugin ptt_audioroom_plugin;

extern janus_callbacks* gateway;

/* Static configuration instance */
extern janus_config* config;
extern const char *config_folder;
extern janus_mutex config_mutex;

extern gint initialized, stopping;
extern gboolean notify_events;
extern gboolean ipv6_disabled;

extern GAsyncQueue *messages;

extern GHashTable* rooms;
extern janus_mutex rooms_mutex;
extern char* admin_key;
extern gboolean lock_rtpfwd;

void* participants_sender_thread(void* data);

}
