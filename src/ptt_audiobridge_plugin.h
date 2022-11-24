/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#pragma once

#include <glib.h>

extern "C" {
#include "plugin.h"
#include "janus/config.h"
#include "janus/mutex.h"
}

#include "plugin_session.h"
#include "ptt_room.h"


namespace ptt_audiobridge
{

extern janus_plugin ptt_audiobridge_plugin;

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
extern gboolean lock_playfile;
extern gboolean lock_rtpfwd;

}
