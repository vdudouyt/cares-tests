#pragma once
#include <ares.h>

typedef struct {
   void *handle;
} ares_impl_t;

extern ares_impl_t impl;

void load_cares_impl(const char *path);
void unload_cares_impl();
