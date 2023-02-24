/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright GNU General Public License v3
 */

#pragma once

#include <memory>
#include <functional>


class actor {
	actor(actor&) = delete;

	actor& operator = (actor&) = delete;

public:
	actor();
	~actor();

	typedef std::function<void ()> action_type;
	void post_action(const action_type&);

private:
	struct actor_private;
	std::unique_ptr<actor_private> _p;
};
