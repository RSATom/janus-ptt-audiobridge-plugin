#include "janus_audiobridge_session.h"

#include "janus_audiobridge_participant.h"


namespace ptt_audioroom
{

GHashTable *sessions;
janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

void janus_audiobridge_session_destroy(janus_audiobridge_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

void janus_audiobridge_session_free(const janus_refcount *session_ref) {
	janus_audiobridge_session *session = janus_refcount_containerof(session_ref, janus_audiobridge_session, ref);
	/* Destroy the participant instance, if any */
	if(session->participant)
		janus_audiobridge_participant_destroy(session->participant);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session);
}

janus_audiobridge_session *janus_audiobridge_lookup_session(janus_plugin_session *handle) {
	janus_audiobridge_session *session = NULL;
	if(g_hash_table_contains(sessions, handle)) {
		session = (janus_audiobridge_session *)handle->plugin_handle;
	}
	return session;
}

}
