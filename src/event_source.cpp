/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "event_source.h"

#include <sys/eventfd.h>
#include <unistd.h>

extern "C" {
#include "janus/debug.h"
}

namespace {

struct EventSource
{
	GSource base;

	int notify_fd;
	gpointer notify_fd_tag;
};

gboolean prepare(GSource* source, gint* timeout)
{
	*timeout = -1;

	return FALSE;
}

gboolean check(GSource* source)
{
	EventSource* event_source = reinterpret_cast<EventSource*>(source);

	eventfd_t value;
	if(0 == eventfd_read(event_source->notify_fd, &value)) {
		return value != 0;
	}

	return FALSE;
}

gboolean dispatch(
	GSource* /*source*/,
	GSourceFunc sourceCallback,
	gpointer userData)
{
	sourceCallback(userData);

	return G_SOURCE_CONTINUE;
}

void finalize(GSource* source)
{
	EventSource* event_source = reinterpret_cast<EventSource*>(source);

	g_source_remove_unix_fd(source, event_source->notify_fd_tag);
	event_source->notify_fd_tag = nullptr;

	close(event_source->notify_fd);
	event_source->notify_fd = -1;
}

void event_source_post_event(GSource* source)
{
	EventSource* event_source = reinterpret_cast<EventSource*>(source);

	eventfd_write(event_source->notify_fd, 1);
}

EventSource* event_source_add(GMainContext* context)
{
	static GSourceFuncs funcs = {
		.prepare = prepare,
		.check = check,
		.dispatch = dispatch,
		.finalize = finalize,
	};

	GSource* source = g_source_new(&funcs, sizeof(EventSource));

	EventSource* event_source = reinterpret_cast<EventSource*>(source);
	event_source->notify_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	event_source->notify_fd_tag = g_source_add_unix_fd(source, event_source->notify_fd, G_IO_IN);

	g_source_attach(source, context);

	return event_source;
}

}


struct event_source::event_source_private
{
	EventSource* event_source;
	event_target_type event_target;

	void on_event();
};

void event_source::event_source_private::on_event()
{
	if(event_target) event_target();
}

event_source::event_source(GMainContext* context) :
	_p(std::make_unique<event_source_private>())
{
	_p->event_source = event_source_add(context);
	auto callback =
		[] (gpointer user_data) -> gboolean {
			event_source_private* p = static_cast<event_source_private*>(user_data);
			p->on_event();
			return G_SOURCE_CONTINUE;
		};
	g_source_set_callback(
		reinterpret_cast<GSource*>(_p->event_source),
		callback,
		_p.get(),
		nullptr);
}

event_source::~event_source()
{
	if(_p->event_source) {
		g_source_unref(reinterpret_cast<GSource*>(_p->event_source));
		_p->event_source = nullptr;
	}
}

void event_source::post_event()
{
	if(!_p->event_source) return;

	event_source_post_event(reinterpret_cast<GSource*>(_p->event_source));
}

void event_source::subscribe(const event_target_type& event_target)
{
	_p->event_target = event_target;
}
