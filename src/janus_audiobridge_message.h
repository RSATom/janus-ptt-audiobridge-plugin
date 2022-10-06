#pragma once

#include <glib.h>
#include <jansson.h>

extern "C" {
#include "plugin.h"
}


namespace ptt_audioroom
{

/* Asynchronous API message to handle */
struct janus_audiobridge_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
};

extern janus_audiobridge_message exit_message;

void janus_audiobridge_message_free(janus_audiobridge_message *msg);

}
