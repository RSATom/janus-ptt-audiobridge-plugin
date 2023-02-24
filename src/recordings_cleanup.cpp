#include "recordings_cleanup.h"

#include <map>
#include <algorithm>

#include <gio/gio.h>

#include "actor.h"
#include "ptt_audiobridge_plugin.h"


enum {
	MINIMUM_SCAN_INTERVAL = 5
};

namespace {

actor* recordings_cleanup_actor = nullptr;

unsigned recordings_ttl = 0;
GSource* timeout_source = nullptr;
std::map<std::string, unsigned> recordings_dirs;

void cleanup(const char* path);

void cleanup(GFile* dir)
{
	g_return_if_fail(dir != nullptr);

	GDateTime* now = g_date_time_new_now_local();
	g_autoptr(GDateTime) drop_time = g_date_time_add_seconds(now, -(double)recordings_ttl);
	g_date_time_unref(now);

	g_autoptr(GFileEnumerator) enumerator =
		g_file_enumerate_children(
			dir,
			G_FILE_ATTRIBUTE_STANDARD_NAME "," G_FILE_ATTRIBUTE_TIME_MODIFIED,
			G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
			NULL,
			NULL);
	if(enumerator) {
		GFileInfo* child_info;
		GFile* child;
		for(
			gboolean iterated = g_file_enumerator_iterate(enumerator, &child_info, &child, NULL, NULL);
			iterated && child_info && child;
			iterated = g_file_enumerator_iterate(enumerator, &child_info, &child, NULL, NULL))
		{
			switch(g_file_info_get_file_type(child_info)) {
				case G_FILE_TYPE_DIRECTORY: {
					cleanup(child);
					break;
				}
				case G_FILE_TYPE_REGULAR: {
					const char* name = g_file_info_get_name(child_info);
					if(g_str_has_suffix(name, ".mjr")) {
						if(g_autoptr(GDateTime) file_time = g_file_info_get_modification_date_time(child_info)) {
							if(g_date_time_compare(file_time, drop_time) < 0) {
								g_autofree char* path = g_file_get_path(child);
								if(path)
									JANUS_LOG(LOG_VERB, "Removing too old recording \"%s\"\n", path);
								g_file_delete(child, NULL, NULL);
							}
						}
					}
					break;
				}
			}
		}
	}
}

void cleanup(const std::string& path)
{
	GFile* dir = g_file_new_for_path(path.c_str());

	cleanup(dir);

	g_object_unref(dir);
}

void cleanup()
{
	for(const auto& pair: recordings_dirs) {
		cleanup(pair.first);
	}
}

}

namespace ptt_audiobridge {

void init_recordings_cleanup(unsigned recordings_ttl)
{
	if(recordings_ttl == 0) return;

	::recordings_ttl = recordings_ttl;
	recordings_cleanup_actor = new actor();
}

void destroy_recordings_cleanup()
{
	delete recordings_cleanup_actor;
	recordings_cleanup_actor = nullptr;
}

void add_recordings_dir(const std::string& recordings_dir)
{
	if(!recordings_cleanup_actor) return;

	recordings_cleanup_actor->post_action([recordings_dir] () {
		if(recordings_dirs.empty() && timeout_source == nullptr) {
			const unsigned interval = std::max<unsigned>(recordings_ttl >> 1, MINIMUM_SCAN_INTERVAL);
			JANUS_LOG(LOG_INFO, "Starting too old recordings check with %u seconds interval...\n", interval);
			timeout_source = g_timeout_source_new_seconds(interval);

			auto callback =
				[] (gpointer /*user_data*/) -> gboolean {
					cleanup();
					return G_SOURCE_CONTINUE;
				};
			g_source_set_callback(timeout_source, callback, nullptr, nullptr);
			g_source_attach(timeout_source, g_main_context_get_thread_default());
		}

		if(++recordings_dirs[recordings_dir] == 1) {
			JANUS_LOG(LOG_INFO, "Starting monitoring too old recordings in \"%s\"...\n", recordings_dir.c_str());
		}
	});
}

void remove_recordings_dir(const std::string& recordings_dir)
{
	if(!recordings_cleanup_actor) return;

	recordings_cleanup_actor->post_action([recordings_dir] () {
		auto it = recordings_dirs.find(recordings_dir);
		if(it != recordings_dirs.end() && --(it->second) == 0) {
			recordings_dirs.erase(it);
			cleanup(recordings_dir);

			JANUS_LOG(LOG_INFO, "Stopped monitoring too old recordings in \"%s\"\n", recordings_dir.c_str());

			if(recordings_dirs.empty()) {
				g_source_unref(timeout_source);
				timeout_source = nullptr;
				JANUS_LOG(LOG_INFO, "Stopped too old recordings check\n");
			}
		}
	});
}

}
