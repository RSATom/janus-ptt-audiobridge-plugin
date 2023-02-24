/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#pragma once

#include <string>


namespace ptt_audiobridge {

void init_recordings_cleanup(unsigned recordings_ttl);
void destroy_recordings_cleanup();

void add_recordings_dir(const std::string&);
void remove_recordings_dir(const std::string&);

}
