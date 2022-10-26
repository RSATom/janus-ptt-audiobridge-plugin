/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright MIT License
 */

#pragma once


enum class thread_type {
	UNKNOWN,
	INCOMING_RTP
};

void assign_thread_type(thread_type);
void assert_thread_type_is(thread_type);
