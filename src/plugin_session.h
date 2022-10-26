/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#pragma once

#include <glib.h>

extern "C" {
#include "janus/refcount.h"
#include "plugin.h"
}


namespace ptt_audiobridge
{
extern GHashTable* sessions;
extern janus_mutex sessions_mutex;

struct room_participant;

struct plugin_session {
	janus_plugin_session *handle;
	gint64 sdp_sessid;
	gint64 sdp_version;
	// once assinged will be alive (and never changed) while plugin_session is alive
	room_participant* participant;
	volatile gint started;
	gint hangingup;
	gint destroyed;
	janus_refcount ref;
};

void plugin_session_destroy(plugin_session *session);
void plugin_session_free(const janus_refcount *session_ref);

plugin_session* lookup_session(janus_plugin_session *handle);

}
