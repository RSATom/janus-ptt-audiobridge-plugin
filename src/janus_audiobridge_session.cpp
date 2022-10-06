#include "janus_audiobridge_session.h"

#include "janus_audiobridge_participant.h"


namespace ptt_audioroom
{

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

}
