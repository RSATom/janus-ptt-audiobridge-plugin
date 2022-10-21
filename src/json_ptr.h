#pragma once

#include <memory>

#include <jansson.h>


struct json_unref {
	void operator() (json_t* json) { json_decref(json); }
};

typedef std::unique_ptr<json_t, json_unref> json_ptr;
