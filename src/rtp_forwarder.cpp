#include "rtp_forwarder.h"


namespace ptt_audioroom
{

void rtp_forwarder_destroy(rtp_forwarder *rf) {
	if(rf && g_atomic_int_compare_and_exchange(&rf->destroyed, 0, 1)) {
		janus_refcount_decrease(&rf->ref);
	}
}

void rtp_forwarder_free(const janus_refcount *f_ref) {
	rtp_forwarder *rf = janus_refcount_containerof(f_ref, rtp_forwarder, ref);
	if(rf->is_srtp) {
		srtp_dealloc(rf->srtp_ctx);
		g_free(rf->srtp_policy.key);
	}
	g_free(rf);
}

}
