#pragma once

#include <memory>

#include <glib.h>


struct glib_free {
	void operator() (gchar* str)
		{ g_free(str); }
};

typedef std::unique_ptr<gchar, glib_free> gchar_ptr;
