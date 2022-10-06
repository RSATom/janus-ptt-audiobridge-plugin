#include "janus_audiobridge_message.h"

#include "janus_audiobridge_session.h"


namespace ptt_audioroom
{

janus_audiobridge_message exit_message;

void janus_audiobridge_message_free(janus_audiobridge_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_audiobridge_session *session = (janus_audiobridge_session *)msg->handle->plugin_handle;
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
