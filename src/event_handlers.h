#pragma once

#include <glib.h>

extern "C" {
#include "plugin.h"
}

#include <jansson.h>


namespace ptt_audioroom
{

json_t* query_session(janus_plugin_session *handle);

janus_plugin_result* handle_message(
	janus_plugin_session* handle,
	char* transaction,
	json_t* message,
	json_t* jsep);

json_t* handle_admin_message(json_t* message);

void* message_handler_thread(void* data);

}
