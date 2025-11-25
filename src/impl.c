#include <dlfcn.h>
#include <assert.h>
#include "impl.h"

ares_impl_t impl;

void load_cares_impl(const char *path) {
   impl.handle = dlopen(path, RTLD_LAZY);
   assert(impl.handle);
}

void unload_cares_impl() {
   dlclose(impl.handle);
}
