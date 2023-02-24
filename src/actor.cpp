/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#include "actor.h"

#include <thread>

#include "glib_ptr.h"

#include "event_source.h"


namespace {

struct action {
	actor::action_type action;
};

void on_event(GAsyncQueue* queue)
{
	while(gpointer item = g_async_queue_try_pop(queue)) {
		std::unique_ptr<action>(static_cast<action*>(item))->action();
	}
}

void actor_main(
	GMainContext* main_context,
	GMainLoop* main_loop,
	GAsyncQueue* queue,
	event_source* notifier)
{
	g_main_context_push_thread_default(main_context);

	notifier->subscribe(std::bind(&on_event, queue));

	g_main_loop_run(main_loop);
}

}

struct actor::actor_private {
	actor_private();

	void post_quit();

	g_main_context_ptr main_context_ptr;
	g_main_loop_ptr main_loop_ptr;
	g_async_queue_ptr queue_ptr;
	event_source notifier;
	std::thread actor_thread;
};

actor::actor_private::actor_private() :
	main_context_ptr(g_main_context_new()),
	main_loop_ptr(g_main_loop_new(main_context_ptr.get(), FALSE)),
	queue_ptr(g_async_queue_new()),
	notifier(main_context_ptr.get()),
	actor_thread(
		actor_main,
		main_context_ptr.get(),
		main_loop_ptr.get(),
		queue_ptr.get(),
		&notifier)
{
}

void actor::actor_private::post_quit()
{
	GMainLoop* loop = main_loop_ptr.get();

	g_async_queue_push(
		queue_ptr.get(),
		new action {
			[loop] () {
				g_main_loop_quit(loop);
			}
		});
}

actor::actor() :
	_p(std::make_unique<actor_private>())
{
}

actor::~actor()
{
	_p->post_quit();
	_p->actor_thread.join();
}

void actor::post_action(const action_type& action)
{
	g_async_queue_push(
		_p->queue_ptr.get(),
		new ::action { action });
	_p->notifier.post_event();
}
