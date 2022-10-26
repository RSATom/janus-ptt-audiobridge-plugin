/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright MIT License
 */

#include "thread_type.h"

#include <cassert>


static thread_local thread_type current_thread_type = thread_type::UNKNOWN;

void assign_thread_type(thread_type type)
{
	assert(current_thread_type == thread_type::UNKNOWN || current_thread_type == type);
	current_thread_type = type;
}

void assert_thread_type_is(thread_type type)
{
	assert(current_thread_type = type);
}
