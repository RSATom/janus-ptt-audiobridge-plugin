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
		unlock();
	}

	void unlock() {
		if(_mutex) {
			janus_mutex_unlock(_mutex);
			_mutex = nullptr;
		}
	}

private:
	janus_mutex* _mutex;
};
