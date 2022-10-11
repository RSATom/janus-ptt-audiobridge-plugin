#pragma once

extern "C" {
#include "janus/mutex.h"
}


struct janus_mutex_lock_guard {
	janus_mutex_lock_guard(janus_mutex* mutex) :
		_mutex(mutex)
	{
		janus_mutex_lock(_mutex);
	}

	~janus_mutex_lock_guard() {
		janus_mutex_unlock(_mutex);
	}

private:
	janus_mutex *const _mutex;
};
