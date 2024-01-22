/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright MIT License
 */

#pragma once

#include <memory>
#include <functional>

#include <glib.h>


class event_source {
	event_source(event_source&) = delete;

	event_source& operator = (event_source&) = delete;

public:
	event_source(GMainContext* context);
	~event_source();

	void post_event();

	typedef std::function<void ()> event_target_type;
	void subscribe(const event_target_type& event_target);

private:
	struct event_source_private;
	std::unique_ptr<event_source_private> _p;
};
