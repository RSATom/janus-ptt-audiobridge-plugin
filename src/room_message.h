/*! \file
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#pragma once

#include <glib.h>
#include <jansson.h>

extern "C" {
#include "plugin.h"
}


namespace ptt_audiobridge
{

/* Asynchronous API message to handle */
struct room_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
};

extern room_message exit_message;

void room_message_free(room_message *msg);

}
