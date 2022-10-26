/*! \file
 * \author Sergey Radionov <rsatom@gmail.com>
 * \copyright MIT License
 */

#pragma once

#include <memory>


struct c_free {
	void operator() (char* str)
		{ free(str); }
};

typedef std::unique_ptr<char, c_free> char_ptr;
