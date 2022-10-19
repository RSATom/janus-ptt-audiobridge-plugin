#pragma once

#include <glib.h>

extern "C" {
#include "plugin.h"
}

#include <jansson.h>


namespace ptt_audioroom
{

json_t* janus_audiobridge_query_session(janus_plugin_session *handle);

janus_plugin_result* janus_audiobridge_handle_message(
	janus_plugin_session* handle,
	char* transaction,
	json_t* message,
	json_t* jsep);

json_t* janus_audiobridge_handle_admin_message(json_t* message);

void* janus_audiobridge_handler(void* data);

}
