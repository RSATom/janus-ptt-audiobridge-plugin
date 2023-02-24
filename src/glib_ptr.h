/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright MIT License
 */

#pragma once

#include <memory>

#include <glib.h>


struct glib_free {
	void operator() (gchar* str)
		{ g_free(str); }
};

typedef std::unique_ptr<gchar, glib_free> gchar_ptr;


struct glib_unref {
	void operator() (GMainContext* context)
		{ g_main_context_unref(context); }

	void operator() (GMainLoop* loop)
		{ g_main_loop_unref(loop); }

	void operator() (GAsyncQueue* queue)
		{ g_async_queue_unref(queue); }
};

typedef
	std::unique_ptr<
		GMainContext,
		glib_unref> g_main_context_ptr;

typedef
	std::unique_ptr<
		GMainLoop,
		glib_unref> g_main_loop_ptr;

typedef
	std::unique_ptr<
		GAsyncQueue,
		glib_unref> g_async_queue_ptr;
