#include "room_message.h"

#include "plugin_session.h"


namespace ptt_audioroom
{

room_message exit_message;

void room_message_free(room_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		plugin_session *session = (plugin_session *)msg->handle->plugin_handle;
		janus_refcount_decrease(&session->ref);
	}
	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message)
		json_decref(msg->message);
	msg->message = NULL;
	if(msg->jsep)
		json_decref(msg->jsep);
	msg->jsep = NULL;

	g_free(msg);
}

}
